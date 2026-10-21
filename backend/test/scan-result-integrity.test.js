import {directoryProbeFixture} from './helpers/directoryProbeFixture.js';
import test, {mock} from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import http from 'node:http';
import express from 'express';
import {getDb,closeDb} from '../src/db/connection.js';
import migrate from '../src/db/migrations/029_scan_result_integrity.js';
import {parseResults,parseScanOutput,createScanOutputCollector} from '../src/services/scanResultParsers.js';
import {beginToolRun,finishToolRun} from '../src/services/scanResultStore.js';
import {scanPage,scanCollection} from '../src/services/scanResultQuery.js';
import {resultCategory,publicScanRecord} from '../src/services/scanResultCatalog.js';
let behavior=async()=>({exitCode:0,stdout:'[a] [http] [high] http://fixture.invalid',stderr:''});
const calls=[];
let probeBehavior=directoryProbeFixture;
const probeCalls=[];
let afterAnalysis=()=>{};
await mock.module('../src/tools/toolRunner.js',{namedExports:{runTool:async(...args)=>{if(args[0]==='target-request'){probeCalls.push(args);return probeBehavior(args[1]);} calls.push(args);return behavior(...args);}}});
await mock.module('../src/services/scanAnalyzer.js',{namedExports:{analyzeScanResults:async()=>{afterAnalysis();return {ok:true,data:{}};}}});
const {executeScan,requestScanAbort}=await import('../src/services/scanExecutor.js');
const {default:scanRoutes}=await import('../src/routes/scans.js');
const {default:resultRoutes}=await import('../src/routes/taskResults.js');
const {cancelPipeline,runPipeline}=await import('../src/services/pipelineEngine.js');
function schema(db,modern=true) {
 db.exec(`CREATE TABLE users(username TEXT PRIMARY KEY,role TEXT,is_active INTEGER);
 INSERT INTO users VALUES ('alice','user',1),('bob','user',1),('admin','admin',1);
 CREATE TABLE pipelines(pipeline_id TEXT PRIMARY KEY,target TEXT,created_by TEXT,status TEXT,scan_task_id TEXT,config TEXT,updated_at TEXT,error_message TEXT,result TEXT,analysis_result TEXT);
 CREATE TABLE pipeline_steps(id INTEGER PRIMARY KEY,pipeline_id TEXT,step_order INTEGER,step_type TEXT,status TEXT,input_data TEXT,output_data TEXT,started_at TEXT,completed_at TEXT,error_message TEXT);
 CREATE TABLE scan_tasks(id INTEGER PRIMARY KEY,scan_task_id TEXT UNIQUE,target TEXT,scan_type TEXT,target_class TEXT,parameters TEXT,created_by TEXT,status TEXT DEFAULT 'PENDING',created_at TEXT,started_at TEXT,completed_at TEXT,error_message TEXT,target_profile TEXT);
 CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,severity TEXT,confidence REAL,mitre_technique_id TEXT,source_tool TEXT,captured_at TEXT);`);
 if(modern) migrate(db);
}
function task(db,id,type='vuln_scan',pipeline=null) {
 db.prepare('INSERT INTO scan_tasks(scan_task_id,target,scan_type,created_by,pipeline_id) VALUES (?,?,?,?,?)').run(id,'http://fixture.invalid',type,'alice',pipeline);
}
const finding=(n=0)=>`[template-${n}] [http] [high] http://fixture.invalid/${n}`;

test('manual API page scans retain parameter discovery but never start FFuf',async()=>{
 const db=getDb(':memory:');schema(db);calls.length=0;probeCalls.length=0;
 task(db,'api-page','api_fuzz');
 db.prepare('UPDATE scan_tasks SET target=?').run('http://fixture.invalid/login.php');
 behavior=async tool=>{assert.equal(tool,'arjun');return {success:true,exitCode:0,stdout:'[+] Parameter: id found in URL query',stderr:''};};
 try {
  const result=await executeScan('api-page');
  assert.equal(result.status,'PARTIAL');
  assert.deepEqual(calls.map(x=>x[0]),['arjun']);assert.equal(probeCalls.length,0);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='scan_error' AND source_tool='ffuf'").get().n,1);
 } finally {closeDb();}
});

test('wildcard preflight prevents candidate flooding, retains history and does not replay completed tasks',async()=>{
 const db=getDb(':memory:');schema(db);calls.length=0;probeCalls.length=0;
 task(db,'wildcard','web_scan');
 db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool) VALUES ('wildcard','web_vuln','{}','low','nikto')").run();
 probeBehavior=()=>({success:true,stdout:JSON.stringify({complete:true,truncated:false,status_code:200,response:'same login page fixture-secret'})});
 behavior=async()=>assert.fail('dictionary scanner must not start');
 try {
  const result=await executeScan('wildcard');
  assert.equal(result.status,'PARTIAL');assert.equal(calls.length,0);assert.equal(probeCalls.length,3);
  const records=db.prepare('SELECT * FROM scan_results').all();
  assert.equal(records.filter(x=>x.result_type==='web_vuln').length,1);
  assert.ok(records.some(x=>x.result_type==='scan_evidence' && JSON.parse(x.result_data).allowed===false));
  assert.doesNotMatch(JSON.stringify(records),/fixture-secret/);
  assert.equal((await executeScan('wildcard')).ok,false);assert.equal(probeCalls.length,3);
 } finally {probeBehavior=directoryProbeFixture;closeDb();}
});

test('API calibration probes the actual api prefix, passes the same cookie, and honors cancellation',async()=>{
 const db=getDb(':memory:');schema(db);calls.length=0;probeCalls.length=0;
 task(db,'api-root','api_fuzz');
 db.prepare('UPDATE scan_tasks SET parameters=?').run(JSON.stringify({cookie:'session=fixture-secret'}));
 behavior=async()=>({success:true,exitCode:0,stdout:'',stderr:''});
 try {
  assert.equal((await executeScan('api-root')).status,'COMPLETED');
  assert.equal(probeCalls.length,3);
  for(const call of probeCalls) {
    const spec=JSON.parse(call[1][0]);assert.ok(new URL(spec.url).pathname.startsWith('/api/'));
    assert.equal(spec.headers.cookie,'session=fixture-secret');
  }
  const ffuf=calls.find(x=>x[0]==='ffuf')[1];
  assert.equal(ffuf[ffuf.indexOf('-H')+1],'Cookie: session=fixture-secret');
  assert.equal(ffuf[ffuf.indexOf('-u')+1],'http://fixture.invalid/api/FUZZ');
  assert.doesNotMatch(JSON.stringify(db.prepare('SELECT result_data FROM scan_results').all()),/fixture-secret/);
  calls.length=0;probeCalls.length=0;task(db,'cancel-probe','web_scan');
  probeBehavior=()=>{requestScanAbort('cancel-probe');return {success:false,aborted:true};};
  await executeScan('cancel-probe');
  assert.equal(calls.length,0);assert.equal(probeCalls.length,1);
  assert.notEqual(db.prepare("SELECT status FROM scan_tasks WHERE scan_task_id='cancel-probe'").get().status,'COMPLETED');
 } finally {probeBehavior=directoryProbeFixture;closeDb();}
});

test('target overrides and incomplete probes never start a dictionary tool',async()=>{
 const db=getDb(':memory:');schema(db);calls.length=0;probeCalls.length=0;
 behavior=async()=>assert.fail('scanner must not start');
 try {
  for(const [id,parameters] of [['root-override',{extra_args:'-root /login.php'}],['port-override',{ports:8080}],['cookie',{cookie:'session=fixture'}]]) {
   task(db,id,'web_scan');db.prepare('UPDATE scan_tasks SET parameters=? WHERE scan_task_id=?').run(JSON.stringify(parameters),id);
   assert.equal((await executeScan(id)).status,'FAILED');
  }
  assert.equal(probeCalls.length,0);
  for(const [id,result] of [['timeout-probe',{success:false,timedOut:true}],['bad-probe',{success:true,stdout:'not-json'}]]) {
   task(db,id,'web_scan');probeBehavior=()=>result;
   assert.equal((await executeScan(id)).status,'FAILED');
  }
  assert.equal(calls.length,0);
 } finally {probeBehavior=directoryProbeFixture;closeDb();}
});

test('direct or legacy queued page scans never run Nikto or widen to a parent directory',async()=>{
 for(const legacy of [false,true]) {
  const db=getDb(':memory:');schema(db);calls.length=0;
  const scanId=legacy?'legacy-page':'page';
  task(db,scanId,'web_scan');
  db.prepare('UPDATE scan_tasks SET target=? WHERE scan_task_id=?').run('http://fixture.invalid/login.php',scanId);
  if(legacy) db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool) VALUES (?,'web_vuln',?,'low','nikto')")
    .run(scanId,JSON.stringify({finding:'Historical candidate, kept for review'}));
  try {
   const result=await executeScan(scanId);
   assert.equal(calls.length,0);
   assert.equal(result.status,legacy?'PARTIAL':'FAILED');
   assert.match(result.error,/页面或接口不能作为目录字典扫描入口/);
   assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='scan_error'").get().n,1);
   assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='web_vuln'").get().n,legacy?1:0);
  } finally {closeDb();}
 }
});

test('page guard preserves explicit SQL verification and bare-host root scanning',async()=>{
 const db=getDb(':memory:');schema(db);calls.length=0;
 task(db,'page-sql','web_scan');
 db.prepare('UPDATE scan_tasks SET target=?,parameters=? WHERE scan_task_id=?')
  .run('http://fixture.invalid/login.php',JSON.stringify({sqli_url:'http://fixture.invalid/item.php?id=1'}),'page-sql');
 behavior=async tool=>{
  assert.equal(tool,'sqlmap');
  return {success:true,exitCode:0,stdout:'Parameter: id\nTarget is vulnerable\nback-end DBMS: fixture',stderr:''};
 };
 try {
  assert.equal((await executeScan('page-sql')).status,'PARTIAL');
  assert.deepEqual(calls.map(call=>call[0]),['sqlmap']);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='sql_injection'").get().n,1);
  calls.length=0;task(db,'host-root','web_scan');
  db.prepare("UPDATE scan_tasks SET target='192.0.2.2:8080' WHERE scan_task_id='host-root'").run();
  behavior=async tool=>{
   assert.equal(tool,'nikto');
   return {success:true,exitCode:0,stdout:'+ The X-Frame-Options header is not present.',stderr:''};
  };
  assert.equal((await executeScan('host-root')).status,'COMPLETED');
  assert.deepEqual(calls.map(call=>call[0]),['nikto']);
 } finally {closeDb();}
});

test('parser preserves info, unknown evidence and real severity without turning errors into findings',()=>{
 const parsed=parseScanOutput('vuln_scan',finding()+'\n[info] [http] [info] http://fixture.invalid\nunknown output','connection refused');
 assert.equal(parsed.records.filter(r=>r.result_type==='vulnerability').length,2);
 assert.equal(resultCategory(parsed.records[1]),'information');
 assert.equal(parsed.diagnostics.tool_reported_count,null);
 assert.equal(parsed.diagnostics.unparsed_lines,1);
 assert.match(parsed.records.at(-1).result_data.stdout,/unknown output/);
 assert.equal(parseResults('auth_audit',finding())[0].severity,'high');
 const safe=publicScanRecord({result_type:'scan_evidence',result_data:JSON.stringify({stdout:'Cookie: first=fixture-secret; second=fixture-secret\nAuthorization: Bearer fixture-secret'})});
 assert.doesNotMatch(safe.result_data,/fixture-secret/);
 assert.equal(parseResults('auth_audit',JSON.stringify({'template-id':'x',info:{severity:'high'},'matched-at':'http://fixture.invalid'}))[0].result_data.template,'x');
 assert.equal(parseScanOutput('vuln_scan','',finding()).records.filter(r=>r.result_type==='vulnerability').length,0,'stderr is evidence, not findings');
 const sql='Parameter: first (GET)\n Type: boolean-based blind\n Title: first title\nParameter: second (POST)\n Type: time-based blind\n Title: second title';
 assert.equal(parseResults('web_scan_sqlmap',sql).length,2);
});

test('streaming parses split UTF8 and discoveries beyond bounded evidence',()=>{
 const collector=createScanOutputCollector('vuln_scan');
 const output=Buffer.from('banner '.repeat(350000)+'\n'+finding(1)+'\n'+finding(2)+'\n');
 for(let i=0;i<output.length;i+=4093) collector.push(output.subarray(i,i+4093),'stdout');
 const parsed=collector.finish({stdout:'truncated',outputLimitExceeded:true});
 assert.equal(parsed.records.filter(r=>r.result_type==='vulnerability').length,2);
 assert.equal(parsed.diagnostics.evidence_truncated,true);
});

test('additive migration, transactional idempotency, rollback and legacy rows',()=>{
 const db=new Database(':memory:');schema(db);task(db,'s');
 db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES ('s','legacy','not json')").run();
 migrate(db);
 const id=beginToolRun(db,'s','nuclei','vuln_scan');
 const parsed=parseScanOutput('vuln_scan',finding());
 finishToolRun(db,id,'s','nuclei',{success:true,exitCode:0},parsed);
 finishToolRun(db,id,'s','nuclei',{success:true,exitCode:0},parsed);
 assert.equal(db.prepare('SELECT COUNT(*) n FROM scan_results').get().n,3);
 const failing=beginToolRun(db,'s','nuclei','vuln_scan');
 db.exec("CREATE TRIGGER reject_result BEFORE INSERT ON scan_results WHEN NEW.result_type='vulnerability' BEGIN SELECT RAISE(ABORT,'fixture write failure'); END");
 assert.throws(()=>finishToolRun(db,failing,'s','nuclei',{success:true},parsed),/fixture write failure/);
 assert.equal(db.prepare('SELECT state FROM scan_tool_runs WHERE tool_run_id=?').get(failing).state,'running');
 assert.equal(db.prepare('SELECT COUNT(*) n FROM scan_results').get().n,3);
 db.close();
});

test('nonzero, timeout and cancellation preserve valid records with terminal completeness',async t=>{
 for(const mode of ['normal','nonzero','timeout','cancel']) await t.test(mode,async()=>{
   const db=getDb(':memory:');schema(db);task(db,mode);calls.length=0;
   behavior=async(tool,args,options)=>{
     if(mode==='cancel') {
       requestScanAbort(mode);
       return new Promise(resolve=>options.signal.addEventListener('abort',()=>resolve({exitCode:-1,aborted:true,stdout:finding(),stderr:'cancelled'}),{once:true}));
     }
     return {exitCode:mode==='normal'?0:1,timedOut:mode==='timeout',stdout:finding(),stderr:mode==='normal'?'':'fixture failure'};
   };
   try {
     const result=await executeScan(mode);
     assert.equal(result.status,mode==='normal'?'COMPLETED':mode==='cancel'?'CANCELLED':'PARTIAL');
     assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='vulnerability'").get().n,1);
     const run=db.prepare('SELECT * FROM scan_tool_runs').get();
     assert.equal(run.state,{normal:'completed',nonzero:'failed',timeout:'timed_out',cancel:'cancelled'}[mode]);
     const before=db.prepare('SELECT COUNT(*) n FROM scan_results').get().n;
     assert.equal((await executeScan(mode)).ok,false);
     assert.equal(db.prepare('SELECT COUNT(*) n FROM scan_results').get().n,before);
   } finally {closeDb();}
 });
});

test('pipeline cancellation links child before await and stops dispatch',async()=>{
 const db=getDb(':memory:');schema(db);
 db.prepare('INSERT INTO pipelines(pipeline_id,target,created_by,status,config) VALUES (?,?,?,?,?)').run('p','http://fixture.invalid','alice','created','{}');
 behavior=async(tool,args,options)=>{
   const pipeline=db.prepare("SELECT * FROM pipelines WHERE pipeline_id='p'").get();
   assert.ok(pipeline.scan_task_id,'child link persisted before tool dispatch');
   cancelPipeline('p');
   return new Promise(resolve=>options.signal.addEventListener('abort',()=>resolve({exitCode:-1,aborted:true,stdout:'Nmap scan report for fixture.invalid\n80/tcp open http',stderr:''}),{once:true}));
 };
 try {
   await runPipeline('p');
   assert.equal(db.prepare('SELECT COUNT(*) n FROM scan_tasks').get().n,1);
   assert.equal(db.prepare('SELECT status FROM pipelines').get().status,'cancelled');
   assert.equal(db.prepare('SELECT status FROM scan_tasks').get().status,'CANCELLED');
 } finally {closeDb();}
});

test('pagination >150, same-target isolation, legacy data and route permissions',async t=>{
 const db=getDb(':memory:');schema(db);
 db.exec("INSERT INTO pipelines(pipeline_id,target,created_by,status,scan_task_id) VALUES ('p','http://fixture.invalid','alice','completed','s,legacy,other'),('q','http://fixture.invalid','alice','completed','other');");
 task(db,'s','vuln_scan','p');task(db,'legacy');task(db,'other','vuln_scan','q');
 const insert=db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,severity) VALUES (?,?,?,?)');
 for(let i=0;i<235;i++) insert.run('s','vulnerability',JSON.stringify({finding:'fixture '+i}),'high');
 insert.run('legacy','unknown_kind','old text','info');insert.run('other','vulnerability','{}','high');
 const pipeline=db.prepare("SELECT * FROM pipelines WHERE pipeline_id='p'").get();
 const ids=[];let after=0;
 do {const page=scanPage(db,pipeline,{limit:'100',after:String(after)});ids.push(...page.scan_records.map(r=>r.id));after=page.page.next_after;if(!page.page.has_more)break;}while(true);
 assert.equal(ids.length,236);assert.equal(new Set(ids).size,236);
 const page=scanPage(db,pipeline,{category:'vulnerability'});assert.equal(page.page.total,235);
 assert.equal(page.scan_summary.vulnerability_instance_count,null);
 const app=express();app.use(express.json(),(req,res,next)=>{const sub=req.headers['x-user']||'alice';req.user={sub,role:sub==='admin'?'admin':'user'};next();});
 app.use('/pipelines/:id/results',resultRoutes(db));app.use('/scans',scanRoutes(db));
 app.use((err,req,res,next)=>res.status(err.status||500).json({error:err.message}));
 const server=http.createServer(app);await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const base='http://127.0.0.1:'+server.address().port;
 try {
  assert.equal((await fetch(base+'/pipelines/p/results?view=scans',{headers:{'x-user':'bob'}})).status,403);
  assert.equal((await fetch(base+'/pipelines/p/results?view=scans',{headers:{'x-user':'missing'}})).status,401);
  assert.equal((await fetch(base+'/pipelines/p/results?view=scans&scan_task_id=other')).status,404);
  assert.equal((await fetch(base+'/pipelines/p/results?view=scans&limit=-1')).status,400);
  assert.equal((await fetch(base+'/pipelines/p/results/records/'+(ids.at(-1)+1))).status,404);
  assert.equal((await fetch(base+'/pipelines/p/results?view=scans',{headers:{'x-user':'admin'}})).status,200);
  db.prepare("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id='s'").run();
  behavior=async()=>({exitCode:0,stdout:finding(),stderr:''});
  const retry=await fetch(base+'/scans/s/retry',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({request_id:'fixture-retry'})});assert.equal(retry.status,202);
  const child=(await retry.json()).data.scan_task_id;
  assert.notEqual(child,'s');
  const repeated=await fetch(base+'/scans/s/retry',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({request_id:'fixture-retry'})});
  assert.equal((await repeated.json()).data.scan_task_id,child,'same request is idempotent after completion');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE scan_task_id='s'").get().n,235);
  assert.equal(db.prepare('SELECT retry_of_scan_task_id FROM scan_tasks WHERE scan_task_id=?').get(child).retry_of_scan_task_id,'s');
  assert.equal(scanCollection(db,pipeline).rows.length,236,'retry is not mixed into original run');
  let releaseCancelledTool;
  behavior=async(tool,args,options)=>new Promise(resolve=>options.signal.addEventListener('abort',()=>{
    releaseCancelledTool=()=>resolve({exitCode:-1,aborted:true,stdout:finding(),stderr:''});
  },{once:true}));
  const pendingResponse=await fetch(base+'/scans/s/retry',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({request_id:'fixture-cancel'})});
  const pending=(await pendingResponse.json()).data.scan_task_id;
  assert.equal((await fetch(base+'/scans/'+pending+'/abort',{method:'POST'})).status,200);
  assert.equal((await fetch(base+'/scans/'+pending+'/retry',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({request_id:'fixture-too-early'})})).status,409);
  assert.equal(typeof releaseCancelledTool,'function','cancel signal is delivered before the tool finishes shutting down');
  releaseCancelledTool();
  for(let i=0;i<30 && db.prepare('SELECT state FROM scan_tool_runs WHERE scan_task_id=?').get(pending)?.state==='running';i++) await new Promise(r=>setTimeout(r,50));
  assert.equal(db.prepare('SELECT state FROM scan_tool_runs WHERE scan_task_id=?').get(pending).state,'cancelled');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE scan_task_id=? AND result_type='vulnerability'").get(pending).n,1);

 } finally {await new Promise(r=>server.close(r));closeDb();}
});

test('HTTP redirects preserve earlier observations and expose timeout',async()=>{
 const {probeTarget}=await import('../src/services/targetDiscovery.js');
 let calls=0;
 await assert.rejects(probeTarget('http://fixture.invalid',{timeoutMs:15,request:async(url,{signal})=>{
   if(calls++===0) return new Response('redirect page',{status:302,headers:{location:'/next'}});
   return new Promise((resolve,reject)=>signal.addEventListener('abort',()=>reject(new Error('fixture timeout')),{once:true}));
 }}),error=>error.timedOut===true && error.partialResults.length===1 && error.partialResults[0].result_data.status_code===302);
});

test('page watermark excludes concurrent arrivals and statistics remain explicit',()=>{
 const db=new Database(':memory:');schema(db);
 db.exec("INSERT INTO pipelines(pipeline_id,target,created_by,scan_task_id) VALUES ('p','http://fixture.invalid','alice','s');");task(db,'s');
 const insert=db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,severity) VALUES ('s','vulnerability','{}','high')");
 for(let i=0;i<120;i++) insert.run();
 const pipeline=db.prepare('SELECT * FROM pipelines').get();
 const first=scanPage(db,pipeline);insert.run();
 const second=scanPage(db,pipeline,{after:first.page.next_after,through:first.page.through});
 assert.equal(second.scan_records.length,20);assert.equal(second.page.total,120);assert.equal(second.scan_summary.record_count,120);
 assert.equal(scanPage(db,pipeline).page.total,121);
 assert.equal(second.scan_summary.legacy_completeness_unknown,true);
 db.close();
});

test('HTTP interrupted response body retains status and already received title',async()=>{
 const {probeTarget}=await import('../src/services/targetDiscovery.js');
 let reads=0;
 await assert.rejects(probeTarget('http://fixture.invalid',{request:async()=>({status:200,headers:new Headers(),body:{getReader:()=>({
  read:async()=>{if(reads++===0)return {done:false,value:Buffer.from('<title>partial fixture</title>')};throw new Error('fixture body disconnect');},
  cancel:async()=>{}
 })}})}),error=>error.partialResults[0].result_data.title==='partial fixture' && error.partialResults[0].result_data.body_incomplete===true);
});


test('unmigrated legacy schema remains readable without fabricating completeness',()=>{
 const db=new Database(':memory:');schema(db,false);
 db.exec("INSERT INTO pipelines(pipeline_id,target,created_by,scan_task_id) VALUES ('p','http://fixture.invalid','alice','s'); INSERT INTO scan_tasks(scan_task_id,target,scan_type,created_by,status) VALUES ('s','http://fixture.invalid','vuln_scan','alice','COMPLETED'); INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES ('s','old_type','not-json');");
 const page=scanPage(db,db.prepare('SELECT * FROM pipelines').get());
 assert.equal(page.scan_records.length,1);assert.match(page.scan_records[0].result_data,/not-json/);
 assert.equal(page.scan_summary.completeness,'unknown');assert.equal(page.scan_summary.tool_reported_count,null);
 db.close();
});

test('parent cancellation reaches explicitly linked children absent from legacy comma list',async()=>{
 const db=getDb(':memory:');schema(db);
 db.prepare("INSERT INTO pipelines(pipeline_id,target,created_by,status,scan_task_id,config) VALUES ('p','http://fixture.invalid','alice','running','','{}')").run();
 task(db,'extra','vuln_scan','p');let signalled=false;
 behavior=async(tool,args,options)=>new Promise(resolve=>options.signal.addEventListener('abort',()=>{
  signalled=true;resolve({exitCode:-1,aborted:true,stdout:finding(),stderr:''});
 },{once:true}));
 const execution=executeScan('extra');
 try {
  assert.equal(cancelPipeline('p').ok,true);
  await Promise.race([execution,new Promise(resolve=>setTimeout(resolve,750))]);
  assert.equal(signalled,true,'parent must cancel all verified children, including explicit pipeline_id links');
  assert.equal(db.prepare("SELECT status FROM scan_tasks WHERE scan_task_id='extra'").get().status,'CANCELLED');
 } finally {requestScanAbort('extra');await execution;closeDb();}
});


test('acceptance: real parent scan orchestration reaches HTTP pages with all partial web discoveries',async()=>{
 const db=getDb(':memory:');schema(db);const originalFetch=globalThis.fetch;
 let server;
 db.prepare("INSERT INTO pipelines(pipeline_id,target,created_by,status,config) VALUES ('multi','http://fixture.invalid','alice','created','{}')").run();
 // Only tool output, target HTTP and analysis are fixtures. Orchestration, parser,
 // persistence, parent ownership and result routes execute real project code.
 globalThis.fetch=async url=>{assert.equal(String(url),'http://fixture.invalid/');return new Response('<title>fixture application</title>');};
 behavior=async(tool,args)=>{
  if(tool==='nmap') return {success:true,exitCode:0,stdout:args.includes('--iflist')?'':'Nmap scan report for fixture.invalid\nHost is up.\n80/tcp open http',stderr:''};
  if(tool==='whatweb') return {success:true,exitCode:0,stdout:'http://fixture.invalid [200 OK] Apache[2.4]',stderr:''};
  if(tool==='httpx') return {success:true,exitCode:0,stdout:JSON.stringify({url:'http://fixture.invalid',status_code:200,title:'fixture'}),stderr:''};
  assert.equal(tool,'nikto');
  return {success:false,exitCode:1,timedOut:true,stdout:Array.from({length:240},(_,i)=>'+ /path-'+i+': Configuration fixture finding '+i).join('\n'),stderr:'fixture timeout'};
 };
 afterAnalysis=()=>cancelPipeline('multi'); // Stop at the acceptance boundary; never generate or execute a playbook.
 try {
  await runPipeline('multi');globalThis.fetch=originalFetch;afterAnalysis=()=>{};
  const scans=db.prepare("SELECT * FROM scan_tasks WHERE pipeline_id='multi' ORDER BY id").all();
  assert.deepEqual(scans.map(s=>s.scan_type),['port_scan','app_discovery','web_scan']);
  assert.deepEqual(scans.map(s=>s.status),['COMPLETED','COMPLETED','PARTIAL']);
  const web=scans[2];const tool=db.prepare("SELECT * FROM scan_tool_runs WHERE scan_task_id=? AND tool_id='nikto'").get(web.scan_task_id);
  assert.equal(JSON.parse(tool.diagnostics).parsed_records,240);
  assert.equal(JSON.parse(tool.diagnostics).persisted_records,242,'240 discoveries plus output evidence plus timeout error');
  assert.equal(tool.state,'timed_out');
  const app=express();app.use((req,res,next)=>{req.user={sub:'alice',role:'user'};next();});
  app.use('/pipelines/:id/results',resultRoutes(db));server=http.createServer(app);
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const base='http://127.0.0.1:'+server.address().port;
  const returned=[];let after=0,through;
  while(true) {
   const response=await fetch(base+'/pipelines/multi/results?view=scans&limit=97&after='+after+(through===undefined?'':'&through='+through));
   assert.equal(response.status,200);const {data}=await response.json();
   assert.equal(data.scan_sources.length,3);assert.equal(data.scan_summary.completeness,'incomplete');
   returned.push(...data.scan_records);after=data.page.next_after;through=data.page.through;
   if(!data.page.has_more)break;
  }
  assert.equal(returned.filter(r=>r.result_type==='web_vuln').length,240);
  const stored=db.prepare('SELECT id FROM scan_results ORDER BY id').all().map(r=>r.id);
  assert.deepEqual(returned.map(r=>r.id),stored);
  assert.ok(returned.some(r=>r.result_type==='web_vuln' && r.result_data.includes('finding 239')));
  assert.ok(returned.some(r=>r.result_type==='scan_error'));
  console.log('acceptance parent-to-HTTP reconciliation:',JSON.stringify({subscans:scans.length,tool_findings_in_fixture:240,parsed_web_findings:240,persisted_web_records:242,all_stored_records:stored.length,all_api_records:returned.length}));
 } finally {
  globalThis.fetch=originalFetch;afterAnalysis=()=>{};
  if(server)await new Promise(r=>server.close(r));closeDb();
 }
});
