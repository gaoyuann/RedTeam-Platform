import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';
import {runMigrations} from '../src/db/migrate.js';
import {takeWebCredentials} from '../src/services/webScanConfig.js';
let resolveRun,started=0,received;
await mock.module('../src/services/pipelineEngine.js',{namedExports:{runPipeline:async id=>{
  started++;received=takeWebCredentials(id,'web-owner');await new Promise(resolve=>{resolveRun=resolve;});
}}});
const {default:routes}=await import('../src/routes/pipelines.js');
const {default:scanRoutes}=await import('../src/routes/scans.js');
test('API forwards ephemeral start credentials once, freezes config, and isolates owners',async t=>{
  const db=getDb(':memory:');t.after(()=>closeDb());
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role) VALUES ('web-owner','unused','user')").run();
  db.prepare("INSERT INTO users(username,password,role) VALUES ('other','unused','user')").run();
  const app=express();app.use(express.json());app.use((req,res,next)=>{req.user={sub:req.headers['x-user']||'web-owner',role:'user'};next();});
  app.use('/api/pipelines',routes(db));app.use('/api/scan-tasks',scanRoutes(db));
  const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  const base=`http://127.0.0.1:${server.address().port}/api/pipelines`;
  const post=async(path,body,user)=>{const r=await fetch(base+path,{method:'POST',headers:{'content-type':'application/json',...(user?{'x-user':user}:{})},body:JSON.stringify(body)});return {code:r.status,data:await r.json()};};
  const config={scan_parameters:{web:{version:1,mode:'react_sqli',auth_mode:'dvwa_ephemeral'}}};
  const bad=await post('',{target:'http://dvwa.test/',config:{scan_parameters:{web:{...config.scan_parameters.web,password:'do-not-store'}}}});
  assert.equal(bad.code,400);
  const created=await post('',{target:'http://dvwa.test/',config});assert.equal(created.code,201);
  const id=created.data.data.pipeline_id;
  assert.equal((await post('/'+id+'/start',{authentication:{username:'sentinel-user',password:'sentinel-password'}},'other')).code,403);
  const start=await post('/'+id+'/start',{authentication:{username:'sentinel-user',password:'sentinel-password'}});
  assert.equal(start.code,202);assert.equal(started,1);assert.equal(received.password,'sentinel-password');
  assert.equal((await post('/'+id+'/start',{authentication:{username:'sentinel-user',password:'sentinel-password'}})).code,400);
  assert.equal(started,1);
  const changed=await fetch(base+'/'+id,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({config:{}})});
  assert.equal(changed.status,409);
  assert.doesNotMatch(JSON.stringify(db.prepare('SELECT config FROM pipelines').all()),/sentinel|do-not-store/);
  assert.doesNotMatch(JSON.stringify(start.data),/sentinel/);
  const parallel=await post('',{target:'http://dvwa.test/other/',config});
  assert.equal(parallel.code,201);
  assert.equal((await post('/'+parallel.data.data.pipeline_id+'/start',{authentication:{username:'sentinel-user',password:'sentinel-password'}})).code,409);
  assert.equal(started,1);
  resolveRun();
  db.prepare("UPDATE pipelines SET status='failed' WHERE pipeline_id=?").run(id);
  const retry=await post('/'+id+'/retry-web-scan',{request_id:'retry-fixture-001'});
  const duplicate=await post('/'+id+'/retry-web-scan',{request_id:'retry-fixture-001'});
  assert.equal(retry.code,201);assert.notEqual(retry.data.data.pipeline_id,id);
  assert.equal(retry.data.data.pipeline_id,duplicate.data.data.pipeline_id);
  assert.equal(retry.data.data.config.retry_of_pipeline_id,id);
  assert.equal(retry.data.data.status,'created');
  assert.equal(started,1); // A retry task is not automatically started with expired credentials.
  assert.equal(duplicate.code,200);
  const childId=retry.data.data.pipeline_id;
  const update=await fetch(base+'/'+childId,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({config:{...config,task_name:'renamed'}})});
  assert.equal(update.status,200);
  const preserved=JSON.parse(db.prepare('SELECT config FROM pipelines WHERE pipeline_id=?').get(childId).config);
  assert.equal(preserved.retry_of_pipeline_id,id);assert.equal(preserved.retry_request_id,'retry-fixture-001');
  db.prepare('INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id) VALUES (?,?,?,?,?,?)').run('unknown-scan','http://dvwa.test/different/','web_scan','FAILED','web-owner',id);
  db.prepare('INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,scan_type,state,started_at,outcome) VALUES (?,?,?,?,?,?,?)').run('unknown-run','unknown-scan','sqlmap','web_scan','failed',new Date().toISOString(),'{"stopped":false}');
  assert.equal((await post('/'+childId+'/start',{authentication:{username:'sentinel-user',password:'sentinel-password'}})).code,409);
  assert.equal((await post('/'+id+'/retry-web-scan',{request_id:'different-fixture'})).code,409);
  assert.equal((await fetch(base+'/'+id,{method:'DELETE'})).status,409);
  assert.equal((await fetch(base.replace('/api/pipelines','/api/scan-tasks')+'/unknown-scan',{method:'DELETE'})).status,409);
  assert.equal((await post('/'+id+'/retry-web-scan',{request_id:'retry-fixture-001'})).data.data.pipeline_id,childId);
  db.prepare("UPDATE scan_tool_runs SET outcome='{\"stopped\":true}' WHERE tool_run_id='unknown-run'").run();
  db.exec('ALTER TABLE task_entries RENAME COLUMN metadata TO old_metadata');
  assert.equal((await post('/'+childId+'/start',{authentication:{username:'sentinel-user',password:'sentinel-password'}})).code,409);
  assert.equal(started,1);
  for(const table of ['audit_log','task_activity_log','pipelines','scan_tasks']){
    if(db.prepare("SELECT 1 FROM sqlite_master WHERE name=? AND type='table'").get(table))
      assert.doesNotMatch(JSON.stringify(db.prepare('SELECT * FROM '+table).all()),/sentinel|do-not-store/);
  }

});
