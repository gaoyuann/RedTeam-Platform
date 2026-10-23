import test from 'node:test';import assert from 'node:assert/strict';import Database from 'better-sqlite3';
import {assessCapability} from '../src/services/scanCapabilityContract.js';
import {createScanBudget} from '../src/services/scanBudget.js';
function fixture(t){const db=new Database(':memory:');t.after(()=>db.close());db.exec('CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT);CREATE TABLE scan_tool_runs(tool_run_id TEXT,scan_task_id TEXT,tool_id TEXT,state TEXT,outcome TEXT)');return {db,record:(type,data)=>db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,?,?)').run('s',type,JSON.stringify(data)),tool:(name,overrides={},state='completed')=>db.prepare('INSERT INTO scan_tool_runs VALUES (?,?,?,?,?)').run(name,'s',name,state,JSON.stringify({tool_started:true,stopped:true,exit_code:0,parser_coverage_known:true,...overrides}))};}
test('HTTP observations do not imply a vulnerability detection took place',t=>{const f=fixture(t);f.record('http_probe',{status_code:200});const a=assessCapability(f.db,'s','app_discovery');assert.equal(a.observation_success,true);assert.equal(a.detection_executed,null);assert.equal(a.detection_complete,null);assert.equal(a.operation_complete,true);});
test('API discovery requires both adapters and is never labelled vulnerability detection',t=>{const f=fixture(t);f.tool('arjun');assert.equal(assessCapability(f.db,'s','api_fuzz').operation_complete,false);f.tool('ffuf');const a=assessCapability(f.db,'s','api_fuzz');assert.equal(a.operation_complete,true);assert.equal(a.detection_executed,null);});
test('external detection distinguishes not started, unknown, timeout and complete',async t=>{
 for(const [outcome,executed,complete] of [[{tool_started:false},false,false],[{tool_started:null},null,false],[{timed_out:true},true,false],[{incomplete:true},true,false],[{},true,true]])await t.test(JSON.stringify(outcome),t=>{
  const f=fixture(t);f.tool('nikto',outcome);const a=assessCapability(f.db,'s','web_scan');assert.equal(a.detection_executed,executed);assert.equal(a.detection_complete,complete);assert.equal(a.coverage_incomplete,!complete);
 });
});
test('one complete SQL report cannot conceal another incomplete parameter check',t=>{const f=fixture(t);f.record('web_observation',{status_code:200});f.record('web_scan_summary',{checks_started:2,complete:false});f.record('scan_evidence',{complete:true,status:'not_detected'});f.record('scan_evidence',{complete:false,status:'inconclusive'});const a=assessCapability(f.db,'s','web_parameter_scan');assert.equal(a.observation_success,true);assert.equal(a.detection_executed,true);assert.equal(a.detection_complete,false);});
test('budget is atomic across consumers, exposes usage and never refunds failed attempts',()=>{
 let time=0;const b=createScanBudget({decisions:2,pages:1,tools:1,sql_checks:1,duration_ms:100,tool_ms:60},()=>time);
 b.consume('decisions');b.consume('decisions');assert.throws(()=>b.consume('decisions'),/预算耗尽/);assert.equal(b.snapshot().used.decisions,2);
 b.consume('tools');assert.throws(()=>b.consume('tools'));assert.equal(b.snapshot().used.tools,1);
 time=80;assert.equal(b.timeout('tool_ms'),20);time=100;assert.throws(()=>b.consume('pages'),/duration_ms/);
 assert.throws(()=>createScanBudget({tools:-1}));
});

test('unknown stop dominates a seemingly complete report and old missing startup data stays unknown',t=>{
 const f=fixture(t);f.tool('nikto',{tool_started:null});assert.equal(assessCapability(f.db,'s','web_scan').detection_executed,null);
 f.db.prepare('DELETE FROM scan_tool_runs').run();f.tool('nikto',{stopped:false});const a=assessCapability(f.db,'s','web_scan');assert.equal(a.detection_executed,true);assert.equal(a.detection_complete,false);assert.ok(a.gaps.includes('stop_unconfirmed'));
});
test('deadline exhaustion is recorded even when the parent timer aborts before the next consume',()=>{
 let time=0;const b=createScanBudget({duration_ms:5},()=>time);time=5;assert.equal(b.snapshot().exhausted,'duration_ms');
});

test('multi-dimensional reservation rejects atomically and reports shared remaining amounts',async()=>{
 const {remainingScanBudget}=await import('../src/services/scanBudget.js');
 const b=createScanBudget({tools:0,sql_checks:2,decisions:4});
 assert.throws(()=>b.consumeMany(['sql_checks','tools']),/tools/);
 assert.equal(b.snapshot().used.sql_checks,0);assert.equal(b.snapshot().used.tools,0);
 b.consume('decisions');b.consume('decisions');
 assert.deepEqual(remainingScanBudget(b,{decisions:10,sql_checks:1,tools:4}),{decisions:2,sql_checks:1,tools:0});
 const c=createScanBudget({pages:0,tools:1});assert.throws(()=>c.consumeMany(['tools','pages']));assert.equal(c.snapshot().used.tools,0);
});
test('SQL report must match all completed runs and cannot override failure or missing evidence',async t=>{
 for(const mode of ['valid','timeout','missing-run','wrong-id','duplicate','unknown-parser'])await t.test(mode,t=>{
  const f=fixture(t);f.record('web_scan_summary',{checks_started:1,complete:true});
  f.record('scan_evidence',{tool_run_id:mode==='wrong-id'?'foreign':'sqlmap',complete:true,status:'not_detected'});
  if(mode==='duplicate')f.record('scan_evidence',{tool_run_id:'sqlmap',complete:true,status:'not_detected'});
  if(mode!=='missing-run')f.tool('sqlmap',mode==='timeout'?{timed_out:true,exit_code:137}:mode==='unknown-parser'?{parser_coverage_known:false}:{});
  assert.equal(assessCapability(f.db,'s','web_parameter_scan').detection_complete,mode==='valid');
 });
});
test('unknown parsing cannot claim a complete Nikto detection',t=>{const f=fixture(t);f.tool('nikto',{parser_coverage_known:false});assert.equal(assessCapability(f.db,'s','web_scan').detection_complete,false);});
