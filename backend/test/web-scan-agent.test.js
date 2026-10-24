import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import {validateWebScanConfig,putWebCredentials,takeWebCredentials,clearWebCredentials} from '../src/services/webScanConfig.js';
import {discoverWebEntries} from '../src/services/webScanEntries.js';
import {createWebScanSession} from '../src/services/webScanSession.js';
import {sqlDetectionArgs,sqlDetectionResult} from '../src/services/webSqlDetector.js';
import {scanWebAgent} from '../src/services/webScanAgent.js';
import {findingIdentity} from '../src/services/findingInstances.js';
import {resultCategory} from '../src/services/scanResultCatalog.js';
import migrate from '../src/db/migrations/036_web_scan_entries.js';

const target='http://dvwa.test/';
const login=`<title>DVWA</title><form method="POST"><input name="username"><input type="password" name="password"><input name="user_token" value="private-token"><input name="Login" value="Login"></form>`;
const home='<a href="logout.php">Logout</a><a href="vulnerabilities/sqli/">SQL</a>';
const form='<a href="logout.php">Logout</a><form method="GET"><input name="id"><input type="submit" name="Submit" value="Submit"></form>';
const positive='Parameter: id (GET)\n    Type: boolean-based blind\n    Title: boolean test\n    Type: UNION query\n    Title: union test\n[*] ending @ 10:00';
function fixtureRequest(calls, {reject=false}={}) {
  let logged=false;
  return async(url,options={})=>{
    calls.push({url,method:options.method||'GET'});
    assert.ok(!url.includes('security.php'));
    if(options.method==='POST'){
      assert.match(options.body,/user_token=private-token/);logged=!reject;
      return new Response(logged?home:login,{headers:{'set-cookie':'PHPSESSID=private-session; Path=/, security=high; Path=/'}});
    }
    if(!logged)return new Response(login);
    return new Response(url.includes('sqli')?form:home);
  };
}
function database(t) {
  const db=new Database(':memory:');t.after(()=>db.close());
  db.exec(`CREATE TABLE scan_tasks(scan_task_id TEXT PRIMARY KEY,pipeline_id TEXT);
    CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT,tool_run_id TEXT,record_index INTEGER);
    CREATE TABLE scan_tool_runs(tool_run_id TEXT PRIMARY KEY,scan_task_id TEXT,tool_id TEXT,scan_type TEXT,state TEXT,started_at TEXT,completed_at TEXT,outcome TEXT,diagnostics TEXT,evidence TEXT);
    CREATE TABLE task_entries(entry_id TEXT PRIMARY KEY,pipeline_id TEXT,kind TEXT,value TEXT,state TEXT,source_record_id INTEGER);
    CREATE TABLE task_checks(check_id TEXT PRIMARY KEY,pipeline_id TEXT,entry_id TEXT,check_type TEXT,scan_type TEXT,target TEXT,state TEXT,reason TEXT,scan_task_id TEXT,created_at TEXT,updated_at TEXT);`);
  migrate(db);migrate(db);return db;
}
const parent={pipeline_id:'pipe-fixture',created_by:'owner',target,config:JSON.stringify({task_scope:{includes:[target],excludes:[]}})};
const task={scan_task_id:'scan-fixture',created_by:'owner',target};
const credentials=()=>({username:'private-user',password:'private-password'});
const response=d=>({ok:true,content:JSON.stringify(d)});

test('config accepts only versioned policy and never persists credentials',()=>{
  const config={scan_parameters:{web:{version:1,mode:'react_sqli',auth_mode:'dvwa_ephemeral'}}};
  validateWebScanConfig(config,target);assert.equal(config.auto_execute,false);assert.equal(config.require_approval,true);
  assert.throws(()=>validateWebScanConfig({scan_parameters:{web:{...config.scan_parameters.web,password:'secret'}}},target));
  putWebCredentials('p','u',credentials());assert.throws(()=>putWebCredentials('p','u',credentials()));
  assert.throws(()=>takeWebCredentials('p','other'));assert.deepEqual(takeWebCredentials('p','u'),credentials());
  assert.throws(()=>takeWebCredentials('p','u'));clearWebCredentials('p');
});
test('GET forms use explicit id control, preserve parameter identity and block unsafe entries',()=>{
  const entries=discoverWebEntries(form+'<form method="POST"><input name="id" value="2"></form><a href="/setup.php">reset</a><a href="http://other.test/">other</a>',target,u=>u.startsWith(target));
  assert.equal(entries.length,2);assert.equal(entries[0].requestUrl,target+'?id=1&Submit=Submit');
  assert.deepEqual(entries[0].parameters,['id']);assert.equal(entries[0].reason,null);assert.ok(entries[1].reason);
  assert.ok(discoverWebEntries('<form><input name="user_token" value="secret"></form>',target,()=>true)[0].reason);
  assert.ok(discoverWebEntries('<form><input name="name"></form>',target,()=>true)[0].reason);
});
test('session logs in without changing security or using a fixed SQL endpoint; rejects bad credentials',async()=>{
  const calls=[];const session=createWebScanSession({target,credentials:credentials(),allowUrl:u=>u.startsWith(target),request:fixtureRequest(calls)});
  await session.login();assert.equal(calls.length,2);assert.equal(session.cookieFor(target),'PHPSESSID=private-session; security=high');
  assert.equal(session.scrub('private-session private-password'),'[已隐藏] [已隐藏]');session.close();
  const bad=createWebScanSession({target,credentials:credentials(),allowUrl:()=>true,request:fixtureRequest([],{reject:true})});
  await assert.rejects(bad.login(),/登录未成功/);bad.close();
});
test('sqlmap policy is narrow and only complete matching reports become positive',()=>{
  const args=sqlDetectionArgs(target+'?id=1','id','private-session');
  assert.ok(args.includes('--technique=BEU'));assert.ok(args.includes('--ignore-redirects'));assert.ok(args.includes('--risk=1'));
  const result={success:true,exitCode:0,stdout:positive,processStopped:true};
  assert.equal(sqlDetectionResult(result,'id').status,'tool_positive');
  for(const change of [{timedOut:true},{aborted:true},{outputLimitExceeded:true},{processStopped:false},{stdout:positive.replace('[*] ending @','incomplete')},{stdout:'resuming cached\n'+positive}])
    assert.equal(sqlDetectionResult({...result,...change},'id').status,'inconclusive');
  assert.equal(sqlDetectionResult(result,'other').status,'inconclusive');
  assert.equal(sqlDetectionResult({...result,stdout:'all tested parameters do not appear to be injectable\n[*] ending @ 12'},'id').status,'not_detected');
  assert.equal(sqlDetectionResult({...result,stdout:''},'id').status,'inconclusive');
});
test('real observe/decide/feedback loop stores one candidate with evidence and no secrets',async t=>{
  const db=database(t),calls=[];let toolCalls=0,turns=0;
  const llm=async messages=>{
    const text=JSON.stringify(messages);assert.doesNotMatch(text,/private-user|private-password|private-session|private-token/);
    const input=JSON.parse(messages[1].content);turns++;
    const e=input.entries.find(e=>turns===1?e.kind==='link':e.kind==='form');
    if(turns>3)return response({action:'finish',reason:'已有证据'});
    return response({action:turns<=2?'inspect_entry':'check_sqli',entry_id:e.id,evidence_id:e.source_evidence_id,...(turns===3?{parameter:'id'}:{}),reason:'根据真实入口选择'});
  };
  const result=await scanWebAgent(task,{db,parent,credentials:credentials(),request:fixtureRequest(calls),llm,
    runner:async(tool,args,opts)=>{toolCalls++;assert.equal(tool,'sqlmap');assert.ok(opts.privateOutputDir);assert.ok(args.includes('id'));return {success:true,exitCode:0,stdout:positive,processStopped:true};}});
  assert.equal(toolCalls,1);assert.equal(turns,4);assert.ok(result.count>0);
  const rows=db.prepare('SELECT * FROM scan_results').all();assert.doesNotMatch(JSON.stringify(rows),/private-user|private-password|private-session|private-token/);
  const findings=rows.filter(r=>r.result_type==='sql_injection');assert.equal(findings.length,1);
  const data=JSON.parse(findings[0].result_data);assert.equal(data.techniques.length,2);assert.equal(data.detection_status,'tool_positive');assert.equal(findingIdentity(findings[0]).parameter,'id');
  assert.equal(resultCategory(rows.find(r=>r.result_type==='web_agent_step')),'information');
  assert.ok(db.prepare('SELECT evidence FROM scan_tool_runs').get().evidence.includes('tool_positive'));
});
test('model disconnect and invalid decisions preserve incomplete coverage without tools',async t=>{
  for(const llm of [async()=>({ok:false}),async()=>response({action:'check_sqli',entry_id:'invented',reason:'bad'})]) {
    const db=database(t);let calls=0;
    await scanWebAgent(task,{db,parent,credentials:credentials(),request:fixtureRequest([]),llm,runner:()=>{calls++;assert.fail();}});
    assert.equal(calls,0);const summary=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='web_scan_summary'").get().result_data);
    assert.equal(summary.complete,false);assert.equal(summary.checks,0);
  }
});
test('pre-cancelled scans never authenticate or invoke models',async t=>{
  const db=database(t),controller=new AbortController();controller.abort();
  await scanWebAgent(task,{db,parent,signal:controller.signal,credentials:credentials(),request:()=>assert.fail(),llm:()=>assert.fail()});
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='sql_injection'").get().n,0);
});

test('session refreshes once, rejects a second expiry and checks redirect scope',async()=>{
  let logins=0,reads=0;
  const session=createWebScanSession({target,credentials:credentials(),allowUrl:u=>u.startsWith(target),request:async(url,opts)=>{
    if(opts.method==='POST'){logins++;return new Response(home,{headers:{'set-cookie':'security=high; Path=/'}});}
    if(url===target)return new Response(login);
    reads++;return new Response(reads===2?form:login);
  }});
  await session.login();await session.read(target+'sqli/');assert.equal(logins,2);
  await assert.rejects(session.read(target+'sqli/'),/再次失效/);session.close();
  const redirect=createWebScanSession({target,credentials:credentials(),allowUrl:()=>true,request:async()=>new Response('',{status:302,headers:{location:'http://outside.test/'}})});
  await assert.rejects(redirect.login(),/超出/);redirect.close();
});
test('cancellation reaches an active detector and retains stopped evidence without positive findings',async t=>{
  const db=database(t),controller=new AbortController();let turns=0;
  const result=await scanWebAgent(task,{db,parent,credentials:credentials(),signal:controller.signal,request:fixtureRequest([]),llm:async messages=>{
    const input=JSON.parse(messages[1].content),entry=input.entries.find(e=>turns===0?e.kind==='link':e.kind==='form');
    turns++;return response({action:turns<=2?'inspect_entry':'check_sqli',entry_id:entry.id,evidence_id:entry.source_evidence_id,...(turns===3?{parameter:'id'}:{}),reason:'test'});
  },runner:async(tool,args,options)=>{
    const wait=new Promise(resolve=>options.signal.addEventListener('abort',()=>resolve({success:false,exitCode:-1,stdout:'',aborted:true,processStopped:true}),{once:true}));
    controller.abort();return wait;
  }});
  assert.ok(result.outcomes.some(o=>!o.success));
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='sql_injection'").get().n,0);
  const run=db.prepare('SELECT outcome FROM scan_tool_runs').get();assert.equal(JSON.parse(run.outcome).stopped,true);assert.equal(JSON.parse(run.outcome).aborted,true);
});

test('cancellation before detector settlement retains evidence but never publishes late candidates or completed steps',async t=>{
  const db=database(t),controller=new AbortController();let turns=0;
  await scanWebAgent(task,{db,parent,credentials:credentials(),signal:controller.signal,request:fixtureRequest([]),llm:async messages=>{
    const input=JSON.parse(messages[1].content),entry=input.entries.find(e=>turns===0?e.kind==='link':e.kind==='form');
    turns++;return response({action:turns<=2?'inspect_entry':'check_sqli',entry_id:entry.id,evidence_id:entry.source_evidence_id,...(turns===3?{parameter:'id'}:{}),reason:'test'});
  },runner:async()=>{
    // A completed report can already be buffered while cancellation arrives.
    controller.abort();
    return {success:true,exitCode:0,stdout:positive,processStopped:true};
  }});
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='sql_injection'").get().n,0);
  const evidence=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='scan_evidence'").get().result_data);
  assert.equal(evidence.status,'inconclusive');assert.equal(evidence.complete,false);
  const run=db.prepare('SELECT state,outcome FROM scan_tool_runs').get();
  assert.equal(run.state,'cancelled');assert.equal(JSON.parse(run.outcome).stopped,true);
  const steps=db.prepare("SELECT result_data FROM scan_results WHERE result_type='web_agent_step'").all().map(r=>JSON.parse(r.result_data));
  assert.equal(steps.some(s=>s.action==='check_sqli' && s.state==='completed'),false);
  assert.equal(JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='web_scan_summary'").get().result_data).reason,'用户取消');
});

test('sqlmap ERROR-labelled exact negative conclusion is accepted without masking other errors',()=>{
 const line="[05:43:40] [ERROR] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options, skipping to the next target";
 const r={success:true,exitCode:0,processStopped:true,stdout:line+'\n[*] ending @ 05:43:40'};
 assert.equal(sqlDetectionResult(r,'id').status,'not_detected');
 for(const extra of ['\n[ERROR] unable to connect','\n[CRITICAL] authentication failed'])assert.equal(sqlDetectionResult({...r,stdout:r.stdout+extra},'id').status,'inconclusive');
 for(const change of [{aborted:true},{timedOut:true},{processStopped:false},{exitCode:1}])assert.equal(sqlDetectionResult({...r,...change},'id').status,'inconclusive');
});

test('dispatch attempts distinguish never-started, started timeout and unknown adapters in persisted evidence',async t=>{
 for(const state of [false,true,null])await t.test(String(state),async t=>{
  const db=database(t);let turn=0;
  await scanWebAgent(task,{db,parent,credentials:credentials(),request:fixtureRequest([]),llm:async messages=>{
   turn++;if(turn>3)return response({action:'finish',reason:'failure recorded'});
   const e=JSON.parse(messages[1].content).entries.find(e=>turn===1?e.kind==='link':e.kind==='form');
   return response({action:turn<=2?'inspect_entry':'check_sqli',entry_id:e.id,evidence_id:e.source_evidence_id,...(turn===3?{parameter:'id'}:{}),reason:'observed entry'});
  },runner:async()=>({success:false,exitCode:-1,processStopped:true,...(state===null?{}:{toolStarted:state}),timedOut:state===true,stdout:''})});
  const summary=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='web_scan_summary'").get().result_data);
  assert.equal(summary.checks,1);assert.equal(summary.checks_started,state===null?null:state?1:0);
  assert.equal(summary.checks_not_started,state===false?1:0);assert.equal(summary.checks_start_unknown,state===null?1:0);assert.equal(summary.complete,false);
  const evidence=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='scan_evidence'").get().result_data);
  assert.equal(evidence.tool_started,state);assert.equal(evidence.status,'inconclusive');
  assert.equal(JSON.parse(db.prepare('SELECT outcome FROM scan_tool_runs').get().outcome).tool_started,state);
  assert.equal(db.prepare("SELECT count(*) n FROM scan_results WHERE result_type='sql_injection'").get().n,0);
  if(state===false){assert.equal(summary.summary,'未开展 SQL 检测');assert.ok(db.prepare("SELECT 1 FROM task_checks WHERE state='not_checked' AND reason='工具未启动，SQL 检测未执行'").get());}
 });
});

test('general parameter capability inspects an ordinary anonymous form without DVWA login or cookies',async t=>{
 const db=database(t);let turns=0,calls=0;
 await scanWebAgent(task,{db,parent,anonymous:true,request:async(url,opts)=>{
  assert.equal(opts.method,'GET');assert.equal(opts.headers,undefined);
  return new Response('<form method="GET"><input name="id" value="1"><input type="submit" name="Submit" value="Submit"></form>');
 },llm:async messages=>{
  turns++;if(turns>2)return response({action:'finish',reason:'检查已结束'});
  const e=JSON.parse(messages[1].content).entries.find(e=>e.kind==='form');
  return response({action:turns===1?'inspect_entry':'check_sqli',entry_id:e.id,evidence_id:e.source_evidence_id,...(turns===2?{parameter:'id'}:{}),reason:'匿名表单证据'});
 },runner:async(_tool,args)=>{calls++;assert.equal(args.includes('--cookie'),false);return {success:true,toolStarted:true,processStopped:true,exitCode:0,stdout:'all tested parameters do not appear to be injectable\n[*] ending @ 12:00'};}});
 assert.equal(calls,1);
 const summary=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='web_scan_summary'").get().result_data);
 assert.equal(summary.checks_started,1);
 assert.equal(db.prepare("SELECT count(*) n FROM scan_results WHERE result_type='sql_injection'").get().n,0);
 assert.equal(JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='scan_evidence'").get().result_data).status,'not_detected');
});

test('temporary bearer session reaches page and SQL adapter without being persisted or sent to model',async t=>{
 const db=database(t);let turns=0,calls=0;
 const authentication={type:'bearer',value:'test-private-bearer',origin:'http://dvwa.test',path:'/'};
 await scanWebAgent(task,{db,parent,anonymous:true,authentication,request:async(url,opts)=>{
  assert.equal(opts.headers.Authorization,'Bearer test-private-bearer');
  return new Response('<form method="GET"><input name="id" value="1"><input type="submit" name="Submit" value="Submit"></form>');
 },llm:async messages=>{
  assert.doesNotMatch(JSON.stringify(messages),/test-private-bearer/);turns++;
  if(turns>2)return response({action:'finish',reason:'检测结束'});
  const e=JSON.parse(messages[1].content).entries.find(e=>e.kind==='form');
  return response({action:turns===1?'inspect_entry':'check_sqli',entry_id:e.id,evidence_id:e.source_evidence_id,...(turns===2?{parameter:'id'}:{}),reason:'已观察表单'});
 },runner:async(_tool,args)=>{
  calls++;assert.equal(args[args.indexOf('--headers')+1],'Authorization: Bearer test-private-bearer');
  return {success:true,toolStarted:true,processStopped:true,exitCode:0,stdout:'all tested parameters do not appear to be injectable\n[*] ending @ 12:00'};
 }});
 assert.equal(calls,1);assert.doesNotMatch(JSON.stringify(db.prepare('SELECT * FROM scan_results').all()),/test-private-bearer/);
});

test('nested Web decisions and page reads consume the parent budget without a SQL dispatch after exhaustion',async t=>{
 const {createScanBudget}=await import('../src/services/scanBudget.js');
 const db=database(t),budget=createScanBudget({decisions:1,pages:10,sql_checks:1,tools:1});let decisions=0,tools=0;
 await scanWebAgent(task,{db,parent,anonymous:true,budget,request:async()=>new Response('<form><input name="id" value="1"></form>'),llm:async messages=>{
  decisions++;const e=JSON.parse(messages[1].content).entries.find(e=>e.kind==='form');return response({action:'inspect_entry',entry_id:e.id,evidence_id:e.source_evidence_id,reason:'观察'});
 },runner:async()=>{tools++;throw Error('must not dispatch');}});
 assert.equal(decisions,1);assert.equal(tools,0);assert.equal(budget.snapshot().used.decisions,1);assert.equal(budget.snapshot().used.pages,2);assert.equal(budget.snapshot().exhausted,'decisions');
 const summary=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='web_scan_summary'").get().result_data);
 assert.equal(summary.complete,false);assert.match(summary.reason,/预算耗尽/);
});

test('deadline before SQL dispatch never creates an unknown-stop lock',async t=>{
 const {ScanBudgetExceeded}=await import('../src/services/scanBudget.js');
 const db=database(t);let turn=0,runners=0;
 await scanWebAgent(task,{db,parent,anonymous:true,budget:{consume(){},consumeMany(){},snapshot(){return {remaining:{decisions:12,pages:20,sql_checks:5,tools:5}};},timeout(key){if(key==='tool_ms')throw new ScanBudgetExceeded('duration_ms');return 1000;}},request:async()=>new Response('<form><input name="id" value="1"></form>'),llm:async messages=>{
  turn++;const e=JSON.parse(messages[1].content).entries[0];return response({action:turn===1?'inspect_entry':'check_sqli',entry_id:e.id,evidence_id:e.source_evidence_id,...(turn===1?{}:{parameter:'id'}),reason:'fixture'});
 },runner:async()=>{runners++;throw Error('must not start');}});
 assert.equal(runners,0);assert.equal(db.prepare('SELECT count(*) n FROM scan_tool_runs').get().n,0);
 const s=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='web_scan_summary'").get().result_data);assert.equal(s.checks,0);assert.match(s.reason,/预算耗尽.*duration_ms/);
});

test('explicit JSON POST is selected by the model, sent to the runner and stored without its body',async t=>{
 const {putPostRequests,clearPostRequests}=await import('../src/services/scanPostRequests.js');
 const db=database(t);let turns=0,toolCalls=0,posts=0;
 putPostRequests(parent.pipeline_id,task.created_by,target,[{url:target+'lookup',encoding:'json',fields:{id:'private-control-value'},parameters:['id'],read_only_confirmed:true}],()=>true);t.after(()=>clearPostRequests(parent.pipeline_id));
 await scanWebAgent(task,{db,parent,anonymous:true,request:async(url,options)=>{if(options.method==='POST'){posts++;assert.equal(options.body,'{"id":"private-control-value"}');}return new Response('<h1>lookup</h1>');},llm:async messages=>{
  assert.doesNotMatch(JSON.stringify(messages),/private-control-value/);turns++;if(turns>2)return response({action:'finish',reason:'检测结束'});
  const e=JSON.parse(messages[1].content).entries.find(e=>e.method==='POST');return response({action:turns===1?'inspect_entry':'check_sqli',entry_id:e.id,evidence_id:e.source_evidence_id,...(turns===2?{parameter:'id'}:{}),reason:'用户明确声明查询模板'});
 },runner:async(tool,args)=>{toolCalls++;assert.ok(args.includes('--method=POST'));return {success:true,toolStarted:true,processStopped:true,exitCode:0,stdout:'Parameter: JSON id ((custom) POST)\n Type: boolean-based blind\n Title: test\n[*] ending @ 12:00'};}});
 assert.equal(toolCalls,1);assert.equal(posts,2);const rows=db.prepare('SELECT * FROM scan_results').all();assert.doesNotMatch(JSON.stringify(rows),/private-control-value/);
 const finding=JSON.parse(rows.find(r=>r.result_type==='sql_injection').result_data);assert.equal(finding.method,'POST');assert.equal(finding.parameter_location,'body');
});

test('POST response reflections never become persisted entries or model inputs',async t=>{
 const {putPostRequests,clearPostRequests}=await import('../src/services/scanPostRequests.js');
 const db=database(t);let turn=0,requests=0;
 const secret='private-query-marker';
 putPostRequests(parent.pipeline_id,task.created_by,target,[{url:target+'lookup',encoding:'json',fields:{id:secret},parameters:['id'],read_only_confirmed:true}],()=>true);t.after(()=>clearPostRequests(parent.pipeline_id));
 await scanWebAgent(task,{db,parent,anonymous:true,request:async(url,options)=>{
  requests++;assert.ok(!url.includes(secret));
  if(options.method==='POST'){assert.equal(JSON.parse(options.body).id,secret);return new Response(`<a href="/echo/${secret}">reflected</a>`);}
  return new Response('<h1>Fixture</h1>');
 },llm:async messages=>{
  assert.doesNotMatch(JSON.stringify(messages),/private-query-marker/);turn++;
  if(turn>1)return response({action:'finish',reason:'结束'});
  const e=JSON.parse(messages[1].content).entries.find(e=>e.method==='POST');return response({action:'inspect_entry',entry_id:e.id,evidence_id:e.source_evidence_id,reason:'模板'});
 },runner:()=>assert.fail('no scan requested')});
 assert.equal(requests,2);
 for(const table of ['task_entries','task_checks','scan_results'])assert.doesNotMatch(JSON.stringify(db.prepare('SELECT * FROM '+table).all()),/private-query-marker/);
});
