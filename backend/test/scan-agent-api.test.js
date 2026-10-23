import {getPostRequests} from '../src/services/scanPostRequests.js';
import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';
import {runMigrations} from '../src/db/migrate.js';
let waiting,modelCalls=0;
await mock.module('../src/services/llmClient.js',{namedExports:{callLlm:async(_messages,options)=>{
 modelCalls++;waiting=true;return new Promise(resolve=>options.signal.addEventListener('abort',()=>resolve({ok:false}),{once:true}));
},callLlmReact:async()=>''}});
const {default:routes}=await import('../src/routes/pipelines.js');
const {scanSessionAuth}=await import('../src/services/scanSessionAuth.js');
const {cancelPipeline}=await import('../src/services/pipelineEngine.js');
test('new comprehensive API task actually enters model dispatch and cancellation converges without tools',async t=>{
 const db=getDb(':memory:');t.after(closeDb);await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
 db.prepare("INSERT INTO users(username,password,role) VALUES ('owner','unused','user')").run();
 const app=express();app.use(express.json());app.use((req,res,next)=>{req.user={sub:'owner',role:'user'};next();});app.use('/api/pipelines',routes(db));
 const server=http.createServer(app);await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>new Promise(r=>server.close(r)));
 const base=`http://127.0.0.1:${server.address().port}/api/pipelines`;
 const post=async(path,body)=>{const r=await fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});return {code:r.status,data:(await r.json()).data};};
 const created=await post('',{target:'http://fixture.test/',config:{test_type:'comprehensive'}});assert.equal(created.code,201);
 assert.deepEqual(created.data.config.scan_orchestrator,{version:1,mode:'react'});assert.equal(created.data.config.require_approval,true);
 const id=created.data.pipeline_id;
 for(const url of [undefined,null,'', '/lookup','http://fixture.test/lookup#x']){
  const invalid={encoding:'json',fields:{id:'1'},parameters:['id'],read_only_confirmed:true,...(url===undefined?{}:{url})};
  assert.equal((await post('/'+id+'/start',{post_requests:[invalid]})).code,400);
  assert.equal(db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(id).status,'created');
  assert.equal(db.prepare('SELECT count(*) n FROM scan_tasks').get().n,0);assert.equal(getPostRequests(id,'owner').length,0);
 }

  assert.equal((await post('/'+id+'/start',{authentication:{type:'cookie',value:'bad\r\nvalue'}})).code,400);
  assert.equal(db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(id).status,'created');
 assert.equal((await post('/'+id+'/start',{authentication:{type:'bearer',value:'api-private-session'},post_requests:[{url:'http://fixture.test/lookup',encoding:'json',fields:{id:'private-body-value'},parameters:['id'],read_only_confirmed:true}]})).code,202);
 for(let n=0;n<50&&!waiting;n++)await new Promise(r=>setTimeout(r,10));
 assert.equal(modelCalls,1);assert.equal(waiting,true);
 assert.equal(scanSessionAuth(id,'owner').value,'api-private-session');assert.equal(getPostRequests(id,'owner').length,1);assert.doesNotMatch(db.prepare('SELECT config FROM pipelines WHERE pipeline_id=?').get(id).config,/private-body-value/);
 assert.doesNotMatch(db.prepare('SELECT config FROM pipelines WHERE pipeline_id=?').get(id).config,/api-private-session/);
 assert.equal(cancelPipeline(id).ok,true);assert.equal(scanSessionAuth(id,'owner'),null);assert.equal(getPostRequests(id,'owner').length,0);
 for(let n=0;n<100&&db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(id).status==='running';n++)await new Promise(r=>setTimeout(r,10));
 assert.equal(db.prepare('SELECT status FROM pipelines WHERE pipeline_id=?').get(id).status,'cancelled');
 assert.equal(db.prepare('SELECT count(*) n FROM scan_tool_runs').get().n,0);
 assert.ok(db.prepare("SELECT 1 FROM scan_results WHERE result_type='scan_agent_summary'").get());
 const retry=await post('/'+id+'/retry-scan',{request_id:'general-retry-001'});assert.equal(retry.code,201);assert.notEqual(retry.data.pipeline_id,id);
 assert.equal(retry.data.config.scan_orchestrator.mode,'react');
 assert.equal((await post('/'+id+'/retry-scan',{request_id:'general-retry-001'})).data.pipeline_id,retry.data.pipeline_id);
 const editable=await post('',{target:'http://mode.test/',config:{test_type:'web'}});assert.equal(editable.code,201);
 const modeId=editable.data.pipeline_id;
 const put=async config=>{const res=await fetch(base+'/'+modeId,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({config})});return res.status;};
 assert.equal(await put({test_type:'source',source_path:'/src/demo',input_kind:'source',task_scope:{includes:['http://mode.test/','/src/demo'],excludes:[]}}),200);
 let modeConfig=JSON.parse(db.prepare('SELECT config FROM pipelines WHERE pipeline_id=?').get(modeId).config);
 assert.equal(modeConfig.scan_mode,'source_assisted');assert.equal(modeConfig.scan_orchestrator,undefined);
 assert.equal(await put({test_type:'web',task_scope:{includes:['http://mode.test/'],excludes:[]}}),200);
 modeConfig=JSON.parse(db.prepare('SELECT config FROM pipelines WHERE pipeline_id=?').get(modeId).config);
 assert.equal(modeConfig.scan_orchestrator.mode,'react');assert.equal(modeConfig.scan_mode,undefined);
 // Corrupt legacy combination must fail at start even if it bypassed update normalization.
 db.prepare('UPDATE pipelines SET config=? WHERE pipeline_id=?').run(JSON.stringify({...modeConfig,scan_mode:'source_assisted'}),modeId);
 const priorCalls=modelCalls;
 assert.equal((await post('/'+modeId+'/start',{})).code,400);assert.equal(modelCalls,priorCalls);
 db.prepare("UPDATE pipelines SET status='failed',config=? WHERE pipeline_id=?").run(JSON.stringify(modeConfig),modeId);
 assert.equal(await put({test_type:'source',source_path:'/src/demo',input_kind:'source',task_scope:{includes:['http://mode.test/','/src/demo'],excludes:[]}}),409);

});
