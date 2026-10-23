import test,{mock} from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';
import {runMigrations} from '../src/db/migrate.js';
import {putWebCredentials} from '../src/services/webScanConfig.js';
let turn=0,calls=0,toolMissing=false,analysisCalls=0;
await mock.module('../src/services/llmClient.js',{namedExports:{callLlm:async messages=>{
  const input=JSON.parse(messages[1].content);turn++;
  const entry=input.entries.find(e=>turn===1?e.kind==='link':e.kind==='form');
  return {ok:true,content:JSON.stringify(turn>3?{action:'finish',reason:'已完成检测'}:{action:turn<=2?'inspect_entry':'check_sqli',entry_id:entry.id,evidence_id:entry.source_evidence_id,...(turn===3?{parameter:'id'}:{}),reason:'实际页面证据'})};
},callLlmReact:async()=>''}});
await mock.module('../src/tools/toolRunner.js',{namedExports:{runTool:async tool=>{
  assert.equal(tool,'sqlmap');calls++;if(toolMissing)return {success:false,toolStarted:false,exitCode:-1,processStopped:true,stdout:''};return {toolStarted:true,success:true,exitCode:0,processStopped:true,stdout:'Parameter: id (GET)\n    Type: boolean-based blind\n    Title: test\n[*] ending @ 10:00'};
}}});
await mock.module('../src/services/scanAnalyzer.js',{namedExports:{analyzeScanResults:async()=>{analysisCalls++;throw new Error('fixture stops before subsequent analysis');}}});
const {runPipeline,cleanupOrphanedPipelines}=await import('../src/services/pipelineEngine.js');
const {scanPage}=await import('../src/services/scanResultQuery.js');
test('parent creates authenticated child, records real structured detections and exposes process independently of candidate filter',async t=>{
  const db=getDb(':memory:');t.after(()=>closeDb());await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role) VALUES ('web-integration','fixture','user')").run();
  const config={require_approval:true,auto_execute:false,scan_parameters:{web:{version:1,mode:'react_sqli',auth_mode:'dvwa_ephemeral'}},task_scope:{includes:['http://dvwa.test/'],excludes:[]}};
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,config) VALUES ('web-integration','http://dvwa.test/','created','web-integration',?)").run(JSON.stringify(config));
  putWebCredentials('web-integration','web-integration',{username:'owner-secret',password:'pw-secret'});
  const oldFetch=globalThis.fetch;t.after(()=>{globalThis.fetch=oldFetch;});let logged=false;
  globalThis.fetch=async(url,opts={})=>{
    if(opts.method==='POST')logged=true;
    return new Response(!logged?'<title>DVWA</title><form method="POST"><input type="password" name="password"><input name="user_token" value="token-secret"></form>':
      String(url).includes('sqli')?'<a href="logout.php">logout</a><form><input name="id"><input type="submit" name="Submit" value="Submit"></form>':'<a href="logout.php">logout</a><a href="sqli/">SQL</a>',{headers:{'set-cookie':'PHPSESSID=session-secret; Path=/, security=high; Path=/'}});
  };
  const execution=await runPipeline('web-integration');assert.equal(calls,1,JSON.stringify({execution,scans:db.prepare('SELECT status,error_message FROM scan_tasks').all(),summary:db.prepare("SELECT result_data FROM scan_results WHERE result_type='web_scan_summary'").all()}));
  const parent=db.prepare("SELECT * FROM pipelines WHERE pipeline_id='web-integration'").get();
  const child=db.prepare('SELECT * FROM scan_tasks WHERE pipeline_id=?').get(parent.pipeline_id);
  assert.equal(JSON.parse(child.parameters).web.mode,'react_sqli');
  const page=scanPage(db,parent,{category:'vulnerability'});
  assert.equal(page.scan_records.length,1);assert.ok(page.web_scan_process.length>=3);
  assert.equal(page.scan_records[0].result_type,'sql_injection');
  assert.doesNotMatch(JSON.stringify(page),/owner-secret|pw-secret|token-secret|session-secret/);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM finding_verification_attempts').get().n,0);
  const priorAnalysis=analysisCalls;turn=0;toolMissing=true;
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,config) VALUES ('missing-tool','http://dvwa.test/','created','web-integration',?)").run(JSON.stringify(config));
  putWebCredentials('missing-tool','web-integration',{username:'owner-secret',password:'pw-secret'});
  await runPipeline('missing-tool');
  assert.equal(db.prepare("SELECT status FROM pipelines WHERE pipeline_id='missing-tool'").get().status,'failed');
  assert.equal(analysisCalls,priorAnalysis,'unstarted tool must not enter analysis');
  const missingSummary=JSON.parse(db.prepare("SELECT r.result_data FROM scan_results r JOIN scan_tasks s USING(scan_task_id) WHERE s.pipeline_id='missing-tool' AND r.result_type='web_scan_summary'").get().result_data);
  assert.equal(missingSummary.checks,1);assert.equal(missingSummary.checks_started,0);
  db.prepare("UPDATE scan_tasks SET status='RUNNING' WHERE scan_task_id=?").run(child.scan_task_id);
  db.prepare("UPDATE scan_tool_runs SET state='running',completed_at=NULL WHERE scan_task_id=?").run(child.scan_task_id);
  cleanupOrphanedPipelines();
  const run=db.prepare('SELECT * FROM scan_tool_runs WHERE scan_task_id=?').get(child.scan_task_id);
  assert.equal(JSON.parse(run.outcome).stopped,false);
  assert.equal(db.prepare('SELECT status FROM scan_tasks WHERE scan_task_id=?').get(child.scan_task_id).status,'FAILED');
});
