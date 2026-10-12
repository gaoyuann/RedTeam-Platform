import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import Database from 'better-sqlite3';
import scanRoutes from '../src/routes/scans.js';
import playbookRoutes from '../src/routes/playbooks.js';
import runRoutes from '../src/routes/runs.js';
import reportRoutes from '../src/routes/reports.js';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { runMigrations } from '../src/db/migrate.js';
async function fixture(t) {
  const db=new Database(':memory:');
  await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
  for (const username of ['alice', 'bob']) {
    db.prepare("INSERT INTO users (username, password, role) VALUES (?, 'fixture', 'user')").run(username);
  }
  const app=express();
  app.use(express.json(),(req,res,next)=>{req.user={sub:req.headers['x-user']||'alice',role:'user'};next();});
  app.use('/scans',scanRoutes(db));app.use('/runs',runRoutes(db));app.use('/playbooks',playbookRoutes(db));app.use('/reports',reportRoutes(db));
  const server=app.listen(0,'127.0.0.1');
  await new Promise(r=>server.once('listening',r));
  t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));db.close();});
  const base='http://127.0.0.1:'+server.address().port;
  async function request(path,body,user='alice',method) {
    const response=await fetch(base+path,{method:method||(body?'POST':'GET'),headers:{'content-type':'application/json','x-user':user},...(body?{body:JSON.stringify(body)}:{})});
    return {status:response.status,body:await response.json()};
  }
  return {db,request};
}
test('source API creates runtime targets, isolates source tasks and preserves completed evidence',async t=>{
  const {db,request}=await fixture(t);
  const created=await request('/scans',{target:'tcp://192.168.1.113:8091',scan_type:'source_scan',created_by:'bob'});
  assert.equal(created.status,201);
  const task=created.body.data;
  assert.equal(task.created_by,'alice');assert.equal(task.target_class,'tcp_service');
  assert.equal((await request('/scans/'+task.scan_task_id,null,'bob')).status,403);
  assert.equal((await request('/scans',null,'bob')).body.data.length,0);
  for(const suffix of ['/execute','/abort','/generate-playbook']) assert.equal((await request('/scans/'+task.scan_task_id+suffix,{},'bob')).status,403);
  assert.equal((await request('/scans/'+task.scan_task_id,null,'bob','DELETE')).status,403);
  db.prepare("UPDATE scan_tasks SET status='COMPLETED'").run();
  assert.equal((await request('/scans/'+task.scan_task_id+'/execute',{})).status,409);
  assert.equal((await request('/scans',{target:'exploit-demo',scan_type:'source_scan'})).status,400);
  assert.equal((await request('/scans',{target:'http://192.168.1.113:8090',scan_type:'source_scan',parameters:{connection_id:'nonexistent-project'}})).status,400);
});
test('run creation cannot retarget or use someone else source verification',async t=>{
  const {db,request}=await fixture(t),target='tcp://192.168.1.113:8091';
  db.prepare("INSERT INTO scan_tasks(scan_task_id,scan_type,target,created_by) VALUES ('s','source_scan',?,'alice')").run(target);
  db.prepare("INSERT INTO playbooks(playbook_id,name,metadata) VALUES ('p','fixture',?)").run(JSON.stringify({source_verification:{scan_task_id:'s',target,finding_ids:[1]}}));
  assert.equal((await request('/runs',{playbook_id:'p',target:'tcp://192.168.1.113:8092'})).status,400);
  assert.equal((await request('/runs',{playbook_id:'p',target},'bob')).status,403);
  const created=await request('/runs',{playbook_id:'p',target,user_sub:'bob',user_role:'admin'});
  assert.equal(created.status,201);
  assert.equal(created.body.data.scan_task_id,'s');
  assert.equal(created.body.data.user_sub,'alice');
  assert.equal(created.body.data.user_role,'user');
});

test('source directory browsing and task input support arbitrary same-origin paths',async t=>{
  const {request}=await fixture(t);
  const hits=[];
  const server=http.createServer((req,res)=>{
    hits.push(req.url);
    res.setHeader('content-type','text/html');
    res.end('<a href="src/">src/</a><a href="main.c">main.c</a><a href="../outside.c">outside</a><a href="https://example.com/foreign.c">foreign</a>');
  });
  server.listen(0,'127.0.0.1'); await new Promise(r=>server.once('listening',r));
  t.after(async()=>{server.closeAllConnections();await new Promise(r=>server.close(r));});
  const target=`http://127.0.0.1:${server.address().port}/app/`;
  const browse=await request('/scans/source-directory',{target,source_url:'/project/code/'});
  assert.equal(browse.status,200);
  assert.deepEqual(browse.body.data.entries.map(e=>e.name),['src/','main.c']);
  assert.equal(browse.body.data.parent,`http://127.0.0.1:${server.address().port}/project/`);
  const created=await request('/scans',{target,scan_type:'source_scan',parameters:{source_url:'/project/code',connection_id:'unused'}});
  assert.equal(created.status,201);
  const parameters=JSON.parse(created.body.data.parameters);
  assert.equal(parameters.source_url,`http://127.0.0.1:${server.address().port}/project/code/`);
  assert.equal(parameters.connection_id,null);
  assert.equal(created.body.data.target,target);
  for(const source_url of ['http://example.com/code/','http://user:pass@127.0.0.1/code/','file:///etc/','relative-directory']) {
    assert.equal((await request('/scans/source-directory',{target,source_url})).status,400);
    assert.equal((await request('/scans',{target,scan_type:'source_scan',parameters:{source_url}})).status,400);
  }
  assert.deepEqual(hits,['/project/code/']);
});

test('source code context and execution evidence are not exposed through other users playbooks or runs',async t=>{
  const {db,request}=await fixture(t),target='http://192.168.1.113:8090/';
  db.prepare("INSERT INTO scan_tasks(scan_task_id,scan_type,target,created_by) VALUES ('s','source_scan',?,'alice')").run(target);
  db.prepare("INSERT INTO playbooks(playbook_id,name,metadata) VALUES ('p','fixture',?)").run(JSON.stringify({source_verification:{scan_task_id:'s',target,context:[{code:'private source'}]}}));
  db.prepare("INSERT INTO execution_runs(run_id,playbook_id,user_sub) VALUES ('r','p','alice')").run();
  assert.equal((await request('/playbooks/p',null,'bob')).status,403);
  assert.equal((await request('/runs/r',null,'bob')).status,403);
  assert.equal((await request('/runs/r/abort',{},'bob')).status,403);
});

test('program report list, reads, writes and exports retain scan ownership',async t=>{
  const {db,request}=await fixture(t);
  db.prepare("INSERT INTO playbooks(playbook_id,name,metadata) VALUES ('p','fixture',?)").run(JSON.stringify({source_verification:{scan_task_id:'s'}}));
  db.exec("INSERT INTO scan_tasks(scan_task_id,scan_type,target,created_by) VALUES ('s','source_scan','http://fixture.invalid/','alice'); INSERT INTO execution_runs(run_id,playbook_id,scan_task_id,user_sub) VALUES ('r','p','s','alice'); INSERT INTO test_reports(report_id,title,run_id,scan_task_id,content,created_at,generated_by) VALUES ('report','fixture','r','s','private response','2026-10-12','alice');");
  assert.equal((await request('/reports',null,'bob')).body.data.length,0);
  assert.equal((await request('/reports/report',null,'alice')).status,200);
  for(const suffix of ['', '/export?format=html']) assert.equal((await request('/reports/report'+suffix,null,'bob')).status,403);
  for(const method of ['DELETE','PUT','PATCH']) assert.equal((await request('/reports/report',{},'bob',method)).status,403);
  assert.equal((await request('/reports/report/export-template',{},'bob')).status,403);
  for(const path of ['/reports/generate','/reports/generate-and-export','/reports'])
    assert.equal((await request(path,{run_id:'r',title:'private',report_id:'x'},'bob')).status,403);
  // A deleted playbook must not turn its surviving execution and reports public.
  db.exec("UPDATE execution_runs SET playbook_id=NULL WHERE run_id='r'; DELETE FROM playbooks WHERE playbook_id='p'");
  assert.equal((await request('/runs/r',null,'bob')).status,403);
  assert.equal((await request('/reports/report',null,'bob')).status,403);
});
