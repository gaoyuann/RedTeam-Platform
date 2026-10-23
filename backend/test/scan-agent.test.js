import test from 'node:test';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
import Database from 'better-sqlite3';
import {runMigrations} from '../src/db/migrate.js';
import {runScanAgent} from '../src/services/scanAgent.js';
import {defaultScanAgent,isScanAgent} from '../src/services/scanAgentConfig.js';
import {normalizeTaskScope} from '../src/services/taskScope.js';
async function fixture(t,target='http://fixture.test/'){
 const db=new Database(':memory:');t.after(()=>db.close());await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
 db.prepare("INSERT INTO users(username,password,role) VALUES ('owner','unused','user')").run();
 const config=defaultScanAgent({task_scope:{includes:[target],excludes:[],discovery_budget:0}},target);config.task_scope=normalizeTaskScope(config,target);
 const p={pipeline_id:'general-test',target,created_by:'owner',config:JSON.stringify(config)};
 db.prepare("INSERT INTO pipelines(pipeline_id,target,created_by,status,config) VALUES (?,?,?,'running',?)").run(p.pipeline_id,target,p.created_by,p.config);
 return {db,p};
}
const choose=messages=>{const x=JSON.parse(messages[1].content);const c=x.candidates.at(-1);return {ok:true,content:JSON.stringify({action:'execute_check',check_id:c.check_id,evidence_id:c.source_record_id,reason:'观察支持该检查'})};};
test('new runtime configs default to ReAct; CScan and legacy SQL remain explicit',()=>{
 assert.ok(isScanAgent(defaultScanAgent({test_type:'comprehensive'},'172.17.0.2')));
 assert.ok(isScanAgent(defaultScanAgent({test_type:'program',scan_mode:'program_dynamic',input_kind:'runtime'},'tcp://fixture.test:80')));
 assert.ok(!isScanAgent(defaultScanAgent({test_type:'source',source_path:'/src/demo'},'/src/demo')));
 assert.ok(!isScanAgent({}));
});
test('actual next-action choice changes scan order; observations feed later decisions and scope remains fixed',async t=>{
 const {db,p}=await fixture(t);const dispatched=[];let turns=0;
 const r=await runScanAgent(db,p,{llm:async m=>{turns++;if(turns>1)assert.ok(JSON.parse(m[1].content).history.length);return choose(m);},execute:async id=>{
  const s=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(id);dispatched.push(s.scan_type);assert.equal(s.target,p.target);
  if(s.scan_type==='app_discovery')db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'http_probe',?)").run(id,JSON.stringify({url:p.target,status_code:200,body:'<h1>Fixture</h1>'}));
  if(s.scan_type==='web_parameter_scan') {
   db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'web_scan_summary',?)").run(id,'{"checks_started":1,"complete":true}');
   db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'scan_evidence',?)").run(id,JSON.stringify({complete:true,status:'not_detected',tool_run_id:id+'sql'}));
  db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,scan_type,state,started_at,outcome) VALUES (?,?,'sqlmap','web_parameter_scan','completed',?,?)").run(id+'sql',id,new Date().toISOString(),'{"tool_started":true,"stopped":true,"exit_code":0,"parser_coverage_known":true}');
  } else if(s.scan_type!=='app_discovery') for(const tool of s.scan_type==='api_fuzz'?['arjun','ffuf']:['nikto'])db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,scan_type,state,started_at,outcome) VALUES (?,?,?,?,'completed',?,?)").run(id+tool,id,tool,s.scan_type,new Date().toISOString(),'{"tool_started":true,"stopped":true,"exit_code":0,"parser_coverage_known":true}');
  db.prepare("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id=?").run(id);return {ok:true,status:'COMPLETED'};
 }});
 assert.equal(r.ok,true);assert.equal(dispatched[0],'app_discovery');assert.ok(dispatched.includes('web_parameter_scan'));assert.ok(dispatched.includes('web_scan'));assert.ok(turns>=3);
 assert.ok(db.prepare("SELECT 1 FROM scan_results WHERE result_type='scan_agent_step'").get());
 const summary=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='scan_agent_summary'").get().result_data);
 assert.equal(summary.complete,false); // Missing authentication is explicitly retained.
});
test('model failure and invented actions never dispatch; cancellation aborts model wait',async t=>{
 for(const kind of ['failure','invented','cancel'])await t.test(kind,async t=>{
  const {db,p}=await fixture(t);const ctrl=new AbortController();let executed=0;
  const r=await runScanAgent(db,p,{signal:ctrl.signal,execute:async()=>{executed++;},llm:async(_m,o)=>{
   if(kind==='cancel'){const promise=new Promise(resolve=>o.signal.addEventListener('abort',()=>resolve({ok:false}),{once:true}));ctrl.abort();return promise;}
   return kind==='failure'?{ok:false}:{ok:true,content:JSON.stringify({action:'execute_check',check_id:'invented',evidence_id:null,reason:'bad'})};
  }});
  assert.equal(executed,0);assert.equal(r.ok,false);assert.equal(r.cancelled,kind==='cancel');
 });
});
test('unknown tool stop prevents all further dispatch even if adapter reports completion',async t=>{
 const {db,p}=await fixture(t);let calls=0;
 const r=await runScanAgent(db,p,{llm:choose,execute:async id=>{
  calls++;db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,scan_type,state,started_at,outcome) VALUES ('lost',?,'probe','app_discovery','failed',?,?)").run(id,new Date().toISOString(),'{"stopped":false}');return {ok:true,status:'COMPLETED'};
 }});
 assert.equal(calls,1);assert.equal(r.ok,false);assert.match(r.error,/停止未确认/);
});

test('non-HTTP service remains a concrete unsupported check instead of being scanned as Web',async t=>{
 const {db,p}=await fixture(t,'192.0.2.7');let calls=0;
 const r=await runScanAgent(db,p,{llm:choose,execute:async id=>{
  calls++;assert.equal(db.prepare('SELECT scan_type FROM scan_tasks WHERE scan_task_id=?').get(id).scan_type,'port_scan');
  db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,scan_type,state,started_at,outcome) VALUES (?,?,'nmap','port_scan','completed',?,?)").run(id,id,new Date().toISOString(),'{"tool_started":true,"stopped":true,"exit_code":0,"parser_coverage_known":true}');
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'open_port',?)").run(id,JSON.stringify({host:p.target,port:22,protocol:'tcp',state:'open',service:'ssh'}));return {ok:true,status:'COMPLETED'};
 }});
 assert.equal(calls,1);assert.equal(r.ok,true);
 assert.ok(db.prepare("SELECT 1 FROM task_checks WHERE state='unsupported' AND check_type='service_security'").get());
});

test('parser-incomplete tool output cannot be promoted to a complete check',async t=>{
 const {db,p}=await fixture(t);let turn=0;
 await runScanAgent(db,p,{llm:async m=>++turn===1?choose(m):{ok:true,content:JSON.stringify({action:'finish',reason:'结果不完整'})},execute:async id=>{
  db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,scan_type,state,started_at,outcome) VALUES ('partial',?,'probe','app_discovery','completed',?,?)").run(id,new Date().toISOString(),'{"stopped":true,"incomplete":true}');return {ok:true,status:'COMPLETED'};
 }});
 assert.equal(db.prepare("SELECT state FROM task_checks WHERE check_type='app_discovery'").get().state,'partial');
 assert.equal(JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='scan_agent_summary'").get().result_data).complete,false);
});

test('authenticated task exposes only session-capable checks and marks other tools unavailable',async t=>{
 const {putScanSessionAuth,clearScanSessionAuth}=await import('../src/services/scanSessionAuth.js');
 const {db,p}=await fixture(t);putScanSessionAuth(p.pipeline_id,p.created_by,p.target,{type:'cookie',value:'session=private-session-value'});t.after(()=>clearScanSessionAuth(p.pipeline_id));
 let count=0;
 await runScanAgent(db,p,{llm:async m=>{assert.doesNotMatch(JSON.stringify(m),/private-session-value/);const input=JSON.parse(m[1].content);assert.ok(input.candidates.every(c=>c.scan_type==='web_parameter_scan'));return choose(m);},execute:async id=>{
  count++;assert.equal(db.prepare('SELECT scan_type FROM scan_tasks WHERE scan_task_id=?').get(id).scan_type,'web_parameter_scan');return {ok:true,status:'COMPLETED'};
 }});
 assert.equal(count,1);
 assert.equal(db.prepare("SELECT count(*) n FROM task_checks WHERE state='missing_condition' AND reason='该能力尚未适配临时会话，未回退匿名执行'").get().n,2);
 assert.doesNotMatch(JSON.stringify(db.prepare('SELECT * FROM scan_results').all()),/private-session-value/);
});

test('PARTIAL parameter scan with only successful page reads cannot authorize analysis',async t=>{
 const {putScanSessionAuth,clearScanSessionAuth}=await import('../src/services/scanSessionAuth.js');
 const {db,p}=await fixture(t);putScanSessionAuth(p.pipeline_id,p.created_by,p.target,{type:'bearer',value:'fixture'});t.after(()=>clearScanSessionAuth(p.pipeline_id));
 const r=await runScanAgent(db,p,{llm:choose,execute:async id=>{
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'web_scan_summary','{\"checks_started\":0}')").run(id);
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'http_probe','{\"status_code\":200}')").run(id);
  return {ok:true,status:'PARTIAL'};
 }});
 assert.equal(r.ok,false);assert.match(r.error,/执行证据/);
});
test('built-in HTTP observation without tool process remains usable',async t=>{
 const {db,p}=await fixture(t);let turn=0;
 const r=await runScanAgent(db,p,{llm:async m=>++turn===1?choose(m):{ok:true,content:'{"action":"finish","reason":"观察完成"}'},execute:async id=>{
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'http_probe',?)").run(id,JSON.stringify({url:p.target,status_code:200}));return {ok:true,status:'COMPLETED'};
 }});
 assert.equal(r.ok,true);assert.equal(db.prepare('SELECT count(*) n FROM scan_tool_runs').get().n,0);
});

test('one shared budget covers nested work and exhaustion prevents subsequent checks',async t=>{
 const {db,p}=await fixture(t);let calls=0;
 const r=await runScanAgent(db,p,{limits:{decisions:4,checks:4,pages:2,tools:1,sql_checks:1,duration_ms:10000,model_ms:1000},llm:choose,execute:async(id,_signal,budget)=>{
  calls++;budget.consume('pages');budget.consume('pages');
  assert.throws(()=>budget.consume('pages'),/预算耗尽/);
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'http_probe',?)").run(id,JSON.stringify({url:p.target,status_code:200}));return {ok:true,status:'COMPLETED'};
 }});
 assert.equal(calls,1);assert.equal(r.ok,false);assert.match(r.error,/pages/);
 const s=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='scan_agent_summary'").get().result_data);
 assert.equal(s.budget.used.pages,2);assert.equal(s.budget.used.decisions,1);assert.equal(s.budget.exhausted,'pages');assert.equal(s.complete,false);
});

test('parent model sees decisions consumed by children instead of the local turn count',async t=>{
 const {db,p}=await fixture(t);let turn=0;
 await runScanAgent(db,p,{limits:{decisions:4},llm:async messages=>{
  turn++;const input=JSON.parse(messages[1].content);
  if(turn===1)return choose(messages);
  assert.equal(input.budget.decisions,0);return {ok:true,content:'{"action":"finish","reason":"预算边界"}'};
 },execute:async(id,_signal,budget)=>{
  budget.consume('decisions');budget.consume('decisions');
  db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES (?,'http_probe',?)").run(id,JSON.stringify({url:p.target,status_code:200}));return {ok:true,status:'COMPLETED'};
 }});
 assert.equal(turn,2);
});
