import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';
import {runMigrations} from '../src/db/migrate.js';

let turns=0,analyses=0;
await mock.module('../src/services/llmClient.js',{namedExports:{callLlm:async messages=>{
 turns++;
 if(turns>2)return {ok:true,content:'{"action":"finish","reason":"保留部分结果继续"}'};
 const c=JSON.parse(messages[1].content).candidates.find(c=>c.scan_type===(turns===1?'app_discovery':'api_fuzz'));
 return {ok:true,content:JSON.stringify({action:'execute_check',check_id:c.check_id,evidence_id:c.source_record_id,reason:'实测入口'})};
},callLlmReact:async()=>''}});
await mock.module('../src/services/scanExecutor.js',{namedExports:{requestScanAbort:()=>{},executeScan:async id=>{
 const db=getDb(),scan=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(id);
 if(scan.scan_type==='app_discovery') {
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'http_probe',?)").run(id,JSON.stringify({url:scan.target,status_code:200,body:'<h1>Fixture</h1>'}));
  db.prepare("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id=?").run(id);
  return {ok:true,status:'COMPLETED'};
 }
 db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,scan_type,state,started_at,completed_at,outcome) VALUES (?,?,'arjun','api_fuzz','timed_out',datetime('now'),datetime('now'),?)")
  .run(id,id,JSON.stringify({tool_started:true,stopped:true,exit_code:137,timed_out:true}));
 db.prepare("UPDATE scan_tasks SET status='PARTIAL',error_message='arjun timeout' WHERE scan_task_id=?").run(id);
 return {ok:false,status:'PARTIAL'};
}}});
await mock.module('../src/services/scanAnalyzer.js',{namedExports:{analyzeScanResults:async ids=>{
 analyses++;assert.ok(ids.some(id=>getDb().prepare("SELECT 1 FROM scan_tasks WHERE scan_task_id=? AND status='PARTIAL'").get(id)));
 return {ok:true,data:{tech_stack:[],attack_surface:[],risk_assessment:[],recommended_strategy:[]}};
}}});
await mock.module('../src/services/playbookGenerator.js',{namedExports:{generatePlaybook:async()=>({ok:true,playbook_id:'recon_dir_enum',name:'Fixture preset'})}});
const {runPipeline}=await import('../src/services/pipelineEngine.js');

test('partial scan reaches analysis and review without rewriting incomplete checks or executing a plan',async t=>{
 const db=getDb(':memory:');t.after(closeDb);
 await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
 db.prepare("INSERT INTO users(username,password,role) VALUES ('partial-owner','fixture','user')").run();
 const config={task_mode:'assessment',scan_orchestrator:{version:1,mode:'react'},require_approval:true,
  task_scope:{includes:['http://fixture.invalid/'],excludes:[],discovery_budget:0}};
 db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,config) VALUES ('partial-review','http://fixture.invalid/','created','partial-owner',?)").run(JSON.stringify(config));
 const result=await runPipeline('partial-review');
 assert.equal(result.status,'awaiting_approval');assert.equal(analyses,1);
 const step=db.prepare("SELECT * FROM pipeline_steps WHERE pipeline_id='partial-review' AND step_type='scan'").get();
 assert.equal(step.status,'completed');assert.equal(JSON.parse(step.output_data).completeness,'incomplete');
 assert.match(JSON.parse(step.output_data).warning,/部分完成/);
 assert.equal(db.prepare("SELECT status FROM scan_tasks WHERE pipeline_id='partial-review' AND scan_type='react_scan'").get().status,'PARTIAL');
 assert.equal(db.prepare("SELECT status,error_message FROM scan_tasks WHERE pipeline_id='partial-review' AND scan_type='api_fuzz'").get().error_message,'arjun timeout');
 assert.equal(db.prepare("SELECT state FROM scan_tool_runs WHERE tool_id='arjun'").get().state,'timed_out');
 assert.ok(db.prepare("SELECT 1 FROM pipeline_logs WHERE pipeline_id='partial-review' AND level='warn' AND message LIKE '%部分完成%'").get());
 assert.equal(db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
});
