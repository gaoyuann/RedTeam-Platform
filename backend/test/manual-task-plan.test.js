import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import Database from 'better-sqlite3';
import {fileURLToPath} from 'node:url';
import {runMigrations} from '../src/db/migrate.js';
import routes from '../src/routes/taskPlans.js';
import {taskPlanSelectionState,createTaskPlan,transitionTaskPlan} from '../src/services/taskPlan.js';

async function fixture(t) {
 const db=new Database(':memory:');t.after(()=>db.close());db.pragma('foreign_keys=ON');
 await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
 for(const [name,role] of [['alice','user'],['bob','user'],['admin','admin']])
  db.prepare("INSERT OR IGNORE INTO users(username,password,role) VALUES (?,'fixture',?)").run(name,role);
 const config={task_mode:'assessment',authorization_confirmed:true,authorization_scope:'http://fixture.invalid/',auto_execute:true};
 db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,config,error_message,result) VALUES ('manual','http://fixture.invalid/','failed','alice',?,'scan incomplete',?)").run(JSON.stringify(config),JSON.stringify({original:true}));
 db.prepare("INSERT INTO pipeline_steps(pipeline_id,step_order,step_type,status,error_message) VALUES ('manual',0,'scan','failed','model decision invalid')").run();
 db.prepare("INSERT INTO scan_tasks(scan_task_id,pipeline_id,target,scan_type,status,created_by) VALUES ('scan-manual','manual','http://fixture.invalid/','web_scan','COMPLETED','alice')").run();
 db.prepare("INSERT INTO scan_results(scan_task_id,result_type,severity,source_tool,result_data) VALUES ('scan-manual','web_vuln','medium','nikto','{}')").run();
 db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,state,started_at,completed_at,outcome) VALUES ('call','scan-manual','nikto','completed',datetime('now'),datetime('now'),?)").run(JSON.stringify({stopped:true}));
 return {db,config,pipeline:()=>db.prepare("SELECT * FROM pipelines WHERE pipeline_id='manual'").get(),actor:{sub:'alice',role:'user'},admin:{sub:'admin',role:'admin'}};
}

test('failed scan can explicitly select a preset, preserve failed evidence and follow normal approval exactly once',async t=>{
 const f=await fixture(t),{db,pipeline}=f,resumed=[];
 const source=db.prepare("SELECT * FROM playbooks WHERE playbook_id='recon_dir_enum'").get();
 const app=express();app.use(express.json(),(req,res,next)=>{const sub=req.headers['x-user']||'alice';req.user={sub,role:sub==='admin'?'admin':'user'};next();});
 app.use('/tasks/:id/plan',routes(db,async()=>async id=>{resumed.push(id);return {ok:true};}));
 app.use((error,req,res,next)=>res.status(error.status||500).json({status:'error',error:{message:error.message}}));
 const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(async()=>{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));});
 async function request(method,suffix='',body,user='alice') {
  const response=await fetch('http://127.0.0.1:'+server.address().port+'/tasks/manual/plan'+suffix,{method,
   headers:{'content-type':'application/json','x-user':user},...(body===undefined?{}:{body:JSON.stringify(body)})});
  return {...await response.json(),status:response.status};
 }
 const read=await request('GET');assert.equal(read.meta.plan_selection.can_create_from_existing,true);
 assert.equal(read.data,null);assert.equal(pipeline().status,'failed');assert.deepEqual(resumed,[]);
 const sources=await request('GET','/sources');assert.ok(sources.data.some(p=>p.playbook_id===source.playbook_id));
 const body={playbook_id:source.playbook_id,continue_after_scan_failure:true};
 assert.equal((await request('POST','',{playbook_id:source.playbook_id})).status,409);
 assert.equal((await request('POST','',{...body,playbook_id:'missing'})).status,404);
 assert.equal(pipeline().status,'failed');assert.equal(db.prepare('SELECT count(*) n FROM task_plans').get().n,0);
 assert.equal((await request('POST','',body,'bob')).status,403);
 const created=await request('POST','',body);assert.equal(created.status,200);
 assert.equal(created.data.state,'draft');assert.equal(created.meta.plan_selection.pipeline_status,'awaiting_approval');
 assert.equal(created.data.content.target,'http://fixture.invalid/');assert.equal(pipeline().error_message,'scan incomplete');
 const result=JSON.parse(pipeline().result);assert.equal(result.original,true);assert.equal(result.manual_scan_continuation.scan_error,'scan incomplete');
 assert.equal(db.prepare("SELECT status FROM pipeline_steps WHERE step_type='scan'").get().status,'failed');
 assert.equal(db.prepare('SELECT count(*) n FROM scan_results').get().n,1);assert.deepEqual(resumed,[]);
 assert.equal((await request('POST','',body)).status,409);
 const submitted=await request('POST','/submit',{revision:created.data.revision});assert.equal(submitted.status,200);
 assert.equal((await request('POST','/approve',{revision:submitted.data.revision})).status,403);
 assert.equal((await request('POST','/approve',{revision:submitted.data.revision},'admin')).status,202);assert.deepEqual(resumed,['manual']);
 assert.equal((await request('POST','/approve',{revision:submitted.data.revision},'admin')).status,409);assert.deepEqual(resumed,['manual']);
 assert.deepEqual(db.prepare('SELECT * FROM playbooks WHERE playbook_id=?').get(source.playbook_id),source);
 assert.equal((await request('GET','',undefined,'bob')).status,403);
});

for(const scenario of ['no-findings','info-only','running-scan','unknown-stop','running-tool','source','discovery','staged','cancelled'])
 test('manual continuation rejects '+scenario,async t=>{
  const f=await fixture(t),{db,pipeline,config}=f;
  if(scenario==='no-findings')db.prepare('DELETE FROM scan_results').run();
  if(scenario==='info-only')db.prepare("UPDATE scan_results SET severity='info'").run();
  if(scenario==='running-scan')db.prepare("UPDATE scan_tasks SET status='RUNNING'").run();
  if(scenario==='unknown-stop')db.prepare("UPDATE scan_tool_runs SET outcome='{}'").run();
  if(scenario==='running-tool')db.prepare("UPDATE scan_tool_runs SET state='running',completed_at=NULL").run();
  if(scenario==='source')config.scan_mode='source_assisted';
  if(scenario==='discovery')config.task_mode='discovery';
  if(scenario==='staged')config.workflow_mode='staged';
  if(scenario==='cancelled')db.prepare("UPDATE pipelines SET status='cancelled'").run();
  db.prepare('UPDATE pipelines SET config=?').run(JSON.stringify(config));
  assert.equal(taskPlanSelectionState(db,pipeline()).can_create_from_existing,false);
  assert.throws(()=>createTaskPlan(db,pipeline(),f.actor,'recon_dir_enum',{continueAfterScanFailure:true}),error=>error.status===409);
  assert.equal(db.prepare('SELECT count(*) n FROM task_plans').get().n,0);
  assert.equal(pipeline().status,scenario==='cancelled'?'cancelled':'failed');
 });

test('manual continuation rechecks stopped tools and authorization before submit and approve',async t=>{
 const f=await fixture(t),{db,pipeline}=f;
 const draft=createTaskPlan(db,pipeline(),f.actor,'recon_dir_enum',{continueAfterScanFailure:true});
 db.prepare("UPDATE scan_tool_runs SET outcome='{}'").run();
 assert.throws(()=>transitionTaskPlan(db,pipeline(),f.actor,'submit',{revision:draft.revision}),error=>error.status===409);
 db.prepare('UPDATE scan_tool_runs SET outcome=?').run(JSON.stringify({stopped:true}));
 const submitted=transitionTaskPlan(db,pipeline(),f.actor,'submit',{revision:draft.revision});
 db.prepare("UPDATE scan_tool_runs SET state='running'").run();
 assert.throws(()=>transitionTaskPlan(db,pipeline(),f.admin,'approve',{revision:submitted.revision}),error=>error.status===409);
 db.prepare("UPDATE scan_tool_runs SET state='completed'").run();
 db.prepare('UPDATE pipelines SET config=?').run(JSON.stringify({...f.config,authorization_confirmed:false}));
 assert.throws(()=>transitionTaskPlan(db,pipeline(),f.admin,'approve',{revision:submitted.revision}),error=>error.status===409);
 assert.equal(db.prepare('SELECT state FROM task_plans').get().state,'submitted');
});

test('historical scan-only config requires an explicit administrator confirmation to enable reviewed execution',async t=>{
 const f=await fixture(t),{db,pipeline}=f;
 const original={...f.config,auto_execute:false,require_approval:true};
 db.prepare('UPDATE pipelines SET config=?').run(JSON.stringify(original));
 const draft=createTaskPlan(db,pipeline(),f.actor,'recon_dir_enum',{continueAfterScanFailure:true});
 const submitted=transitionTaskPlan(db,pipeline(),f.actor,'submit',{revision:draft.revision});
 for(const body of [{revision:submitted.revision},{revision:submitted.revision,enable_execution:'true'}])
  assert.throws(()=>transitionTaskPlan(db,pipeline(),f.admin,'approve',body),error=>error.status===409);
 assert.throws(()=>transitionTaskPlan(db,pipeline(),f.actor,'approve',{revision:submitted.revision,enable_execution:true}),error=>error.status===403);
 assert.throws(()=>transitionTaskPlan(db,pipeline(),f.admin,'approve',{revision:submitted.revision-1,enable_execution:true}),error=>error.status===409);
 assert.deepEqual(JSON.parse(pipeline().config),original);
 const approved=transitionTaskPlan(db,pipeline(),f.admin,'approve',{revision:submitted.revision,enable_execution:true});
 assert.equal(approved.state,'approved');
 assert.deepEqual(JSON.parse(pipeline().config),{...original,auto_execute:true});
 assert.match(approved.history[0].note,/执行/);
 assert.throws(()=>transitionTaskPlan(db,pipeline(),f.admin,'approve',{revision:approved.revision,enable_execution:true}),error=>error.status===409);
 assert.equal(db.prepare("SELECT count(*) n FROM playbooks WHERE playbook_id LIKE 'task_plan_%'").get().n,1);
});
