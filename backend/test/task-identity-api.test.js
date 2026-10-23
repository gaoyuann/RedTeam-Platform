import test from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import express from 'express';
import Database from 'better-sqlite3';
import { runMigrations } from '../src/db/migrate.js';
import pipelines from '../src/routes/pipelines.js';
import reports from '../src/routes/reports.js';
import { authenticate } from '../src/middleware/auth.js';
import { generateAccessToken } from '../src/middleware/jwtUtils.js';
import errorHandler from '../src/middleware/errorHandler.js';
import { taskResultsSnapshot,createTaskReport,readTaskReport,taskReportHtml } from '../src/services/taskResults.js';
import identity from '../src/db/migrations/037_task_identity.js';
import { exportTaskReport } from '../src/services/taskReportExport.js';
import { PDFDocument, PDFRawStream, decodePDFRawStream } from 'pdf-lib';
import JSZip from 'jszip';
async function fixture(){
 const db=new Database(':memory:');db.pragma('foreign_keys=ON');await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
 for(const name of ['owner','other','admin'])db.prepare("INSERT OR IGNORE INTO users(username,password,role) VALUES (?,'fixture',?)").run(name,name==='admin'?'admin':'user');
 const app=express();app.use(express.json());app.use('/api/pipelines',authenticate,pipelines(db));app.use('/api/reports',authenticate,reports(db));app.use(errorHandler);
 const server=await new Promise(resolve=>{const s=app.listen(0,'127.0.0.1',()=>resolve(s));});
 const request=async(method,path,body,owner='owner')=>{
 const r=await fetch(`http://127.0.0.1:${server.address().port}/api${path}`,{method,headers:{'content-type':'application/json',authorization:'Bearer '+generateAccessToken({username:owner,role:owner==='admin'?'admin':'user'})},body:body===undefined?undefined:JSON.stringify(body)});
 return {http:r.status,...await r.json()};};
 return {db,request,close:async()=>{await new Promise(resolve=>server.close(resolve));db.close();}};
}
const body={target:'http://192.0.2.10/app/',request_id:'fixture-creation-1',config:{task_name:'same name',test_type:'web',authorization_confirmed:true,authorization_scope:'http://192.0.2.10/app/'}};
test('real API persists one task for retries, searches all states and enforces ownership',async()=>{
 const f=await fixture();try{
 const a=await f.request('POST','/pipelines',body);assert.equal(a.http,201);assert.match(a.data.task_no,/^TASK-\d{8}-\d{6,}$/);
 const again=await f.request('POST','/pipelines',body);assert.equal(again.http,200);assert.equal(again.data.pipeline_id,a.data.pipeline_id);
 assert.equal((await f.request('POST','/pipelines',{...body,target:'http://192.0.2.11/'})).http,409);
 const encoded=encodeURIComponent('  '+a.data.task_no.toLowerCase()+'  ');
 assert.equal((await f.request('GET','/pipelines/lookup?task_no='+encoded)).data.pipeline_id,a.data.pipeline_id);
 assert.equal((await f.request('GET','/pipelines?status=failed&search='+encoded)).data[0].task_no,a.data.task_no);
 assert.equal((await f.request('GET','/pipelines?search=TASK-')).data.length,1);
 assert.equal((await f.request('GET','/pipelines?search='+a.data.pipeline_id)).data[0].task_no,a.data.task_no);
 assert.equal((await f.request('GET','/pipelines/lookup?task_no='+encoded,undefined,'other')).http,404);
 assert.equal((await f.request('GET','/pipelines?search='+encoded,undefined,'other')).data.length,0);
 assert.equal((await f.request('GET','/pipelines/lookup?task_no=TASK-20000101-999999',undefined,'other')).http,404);
 assert.equal((await f.request('GET','/pipelines/lookup?task_no='+encoded,undefined,'admin')).data.task_no,a.data.task_no);
 assert.equal((await f.request('GET','/pipelines/'+a.data.pipeline_id)).data.task_no,a.data.task_no);
 const renamed=await f.request('PUT','/pipelines/'+a.data.pipeline_id,{config:{...body.config,task_name:'renamed'}});
 assert.equal(renamed.data.task_no,a.data.task_no);
 assert.equal((await f.request('GET','/pipelines/analysis-index?search='+encoded)).data.total,1);
 assert.equal((await f.request('GET','/pipelines/'+a.data.pipeline_id+'/execution')).data.task_no,a.data.task_no);
 assert.equal(f.db.prepare('SELECT count(*) n FROM pipelines').get().n,1);
 assert.equal(f.db.prepare('SELECT count(*) n FROM pipeline_steps').get().n,0);
 const duplicate=await f.request('POST','/pipelines',{...body,request_id:'fixture-creation-2'});assert.notEqual(duplicate.data.task_no,a.data.task_no);
 f.db.prepare("UPDATE pipelines SET status='completed' WHERE pipeline_id=?").run(a.data.pipeline_id);
 const retry=await f.request('POST','/pipelines/'+a.data.pipeline_id+'/retry-scan',{request_id:'fixture-retry-1'});
 assert.equal(retry.http,201);assert.notEqual(retry.data.task_no,a.data.task_no);
 const retryAgain=await f.request('POST','/pipelines/'+a.data.pipeline_id+'/retry-scan',{request_id:'fixture-retry-1'});
 assert.equal(retryAgain.http,200);assert.equal(retryAgain.data.task_no,retry.data.task_no);
 assert.equal((await f.request('POST','/pipelines',{...body,request_id:'bad'})).http,400);
 }finally{await f.close();}
});
test('new reports freeze task numbers; backfilled history retains its frozen content',async()=>{
 const f=await fixture();try{
 const a=(await f.request('POST','/pipelines',body)).data;f.db.prepare("UPDATE pipelines SET status='completed' WHERE pipeline_id=?").run(a.pipeline_id);
 let p=f.db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(a.pipeline_id);
 let snapshot=taskResultsSnapshot(f.db,p);let saved=createTaskReport(f.db,p,{sub:'owner',role:'user'},{source_fingerprint:snapshot.source_fingerprint,run_id:null});
 let document=readTaskReport(f.db,p,saved.report.report_id);assert.equal(document.report.content.provenance.task_no,a.task_no);assert.ok(taskReportHtml(document).includes(a.task_no));
 for(const format of ['json','html','docx','pdf']){
  const file=await exportTaskReport(document,format);let text=file.buffer.toString();
  if(format==='docx')text=await (await JSZip.loadAsync(file.buffer)).file('word/document.xml').async('string');
  if(format==='pdf'){
   const pdf=await PDFDocument.load(file.buffer);
   const streams=[...pdf.context.enumerateIndirectObjects()].map(([,value])=>value)
    .filter(value=>value instanceof PDFRawStream).map(value=>Buffer.from(decodePDFRawStream(value).decode()).toString('latin1'));
   const unicode=new Map();
   for(const stream of streams.filter(value=>value.includes('begincmap')))
    for(const block of stream.matchAll(/beginbfchar([\s\S]*?)endbfchar/g))
     for(const [,code,mapped] of block[1].matchAll(/<([\da-f]+)>\s*<([\da-f]+)>/gi))
      unicode.set(code.toUpperCase(),String.fromCharCode(...mapped.match(/.{4}/g).map(v=>parseInt(v,16))));
   assert.ok(unicode.size>0);
   text=streams.filter(value=>!value.includes('begincmap')).flatMap(stream=>[...stream.matchAll(/<([\da-f]+)>\s*Tj/gi)]
    .map(([,encoded])=>encoded.match(/.{4}/g).map(code=>unicode.get(code.toUpperCase())||'').join(''))).join('');
  }
  assert.ok(text.includes(a.task_no),format+' retains the frozen task ID');
 }
 assert.equal((await f.request('GET','/reports/index?search='+a.task_no)).data.records[0].task_no,a.task_no);
 f.db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,config) VALUES ('old-report','http://192.0.2.12/','completed','owner','{}')").run();
 p=f.db.prepare("SELECT * FROM pipelines WHERE pipeline_id='old-report'").get();snapshot=taskResultsSnapshot(f.db,p);
 saved=createTaskReport(f.db,p,{sub:'owner',role:'user'},{source_fingerprint:snapshot.source_fingerprint,run_id:null});
 const frozen=f.db.prepare('SELECT content FROM test_reports WHERE report_id=?').get(saved.report.report_id).content;
 identity(f.db);p=f.db.prepare("SELECT * FROM pipelines WHERE pipeline_id='old-report'").get();document=readTaskReport(f.db,p,saved.report.report_id);
 assert.equal(document.task_no,p.task_no);assert.equal(document.report.task_no_source,'current_task_metadata');
 assert.equal(f.db.prepare('SELECT content FROM test_reports WHERE report_id=?').get(saved.report.report_id).content,frozen);
 assert.ok(!taskReportHtml(document).includes(p.task_no));
 }finally{await f.close();}
});

test('ID search rejects disabled accounts and outdated administrator roles like direct lookup',async()=>{
 const f=await fixture();try{
  const a=(await f.request('POST','/pipelines',body)).data;
  f.db.prepare("UPDATE users SET is_active=0 WHERE username='owner'").run();
  assert.equal((await f.request('GET','/pipelines/lookup?task_no='+a.task_no)).http,401);
  assert.equal((await f.request('GET','/pipelines?search='+a.task_no)).http,401);
  assert.equal((await f.request('GET','/pipelines/'+a.pipeline_id)).http,401);
  for(const suffix of ['/execution','/logs','/steps'])
   assert.equal((await f.request('GET','/pipelines/'+a.pipeline_id+suffix)).http,401);
  assert.equal((await f.request('POST','/pipelines',{...body,request_id:'disabled-new-task'})).http,401);
  assert.equal((await f.request('POST','/pipelines/'+a.pipeline_id+'/retry-scan',{request_id:'disabled-retry-task'})).http,401);
  f.db.prepare("UPDATE users SET role='user' WHERE username='admin'").run();
  assert.equal((await f.request('GET','/pipelines?search='+a.task_no,undefined,'admin')).http,401);
  assert.equal((await f.request('GET','/pipelines/'+a.pipeline_id,undefined,'admin')).http,401);
 }finally{await f.close();}
});

test('server search retains translated type names and special characters',async()=>{
 const f=await fixture();try{
  const task=(await f.request('POST','/pipelines',{...body,config:{...body.config,test_type:'comprehensive',task_name:'C++ 100% & #'}})).data;
  assert.equal((await f.request('GET','/pipelines?search='+encodeURIComponent('综合测试'))).data[0]?.pipeline_id,task.pipeline_id);
  assert.equal((await f.request('GET','/pipelines?search=comprehensive')).data[0]?.pipeline_id,task.pipeline_id);
  const found=await f.request('GET','/pipelines?search='+encodeURIComponent('C++ 100% & #'));
  assert.equal(found.data[0]?.pipeline_id,task.pipeline_id);
  assert.equal(found.meta.search_applied,true);
  assert.equal(found.meta.task_identity_version,1);
 }finally{await f.close();}
});
