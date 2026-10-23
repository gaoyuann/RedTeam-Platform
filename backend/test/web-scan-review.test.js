import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import {rm,stat} from 'node:fs/promises';
import {discoverWebEntries,entryFromUrl} from '../src/services/webScanEntries.js';
import {createWebScanSession} from '../src/services/webScanSession.js';
import {sqlDetectionArgs,sqlDetectionResult,detectWebSql} from '../src/services/webSqlDetector.js';
import {scanWebAgent} from '../src/services/webScanAgent.js';
import {webTargetBusy,hasWebScanSchema,validateWebScanConfig} from '../src/services/webScanConfig.js';
import migration from '../src/db/migrations/036_web_scan_entries.js';
const target='http://dvwa.test/';
const auth=()=>({username:'review-user',password:'review-password'});
const login='<title>DVWA</title><form method="POST"><input type="password" name="password"><input name="user_token" value="review-login-token"></form>';
const home='<a href="logout.php">Logout</a><form method="GET"><input name="id" value="1"><input type="submit" name="Submit" value="Submit"></form>';
const positive='Parameter: id (GET)\n    Type: boolean-based blind\n    Title: private page snippet\n[*] ending @ 10:00';
const ok=d=>({ok:true,content:JSON.stringify(d)});
function dbFor(t){
 const db=new Database(':memory:');t.after(()=>db.close());
 db.exec(`CREATE TABLE scan_tasks(scan_task_id TEXT PRIMARY KEY,pipeline_id TEXT,target TEXT);
 CREATE TABLE pipelines(pipeline_id TEXT PRIMARY KEY,target TEXT,status TEXT,config TEXT);
 CREATE TABLE task_entries(entry_id TEXT PRIMARY KEY,pipeline_id TEXT,kind TEXT,value TEXT,state TEXT,source_record_id INTEGER);
 CREATE TABLE task_checks(check_id TEXT PRIMARY KEY,pipeline_id TEXT,entry_id TEXT,check_type TEXT,scan_type TEXT,target TEXT,state TEXT,reason TEXT,scan_task_id TEXT,created_at TEXT,updated_at TEXT);
 CREATE TABLE scan_tool_runs(tool_run_id TEXT PRIMARY KEY,scan_task_id TEXT,tool_id TEXT,scan_type TEXT,state TEXT,started_at TEXT,completed_at TEXT,outcome TEXT,diagnostics TEXT,evidence TEXT);
 CREATE TABLE scan_results(id INTEGER PRIMARY KEY,scan_task_id TEXT,result_type TEXT,result_data TEXT,severity TEXT,source_tool TEXT,captured_at TEXT,tool_run_id TEXT,record_index INTEGER);`);
 migration(db);return db;
}
const parent={pipeline_id:'review-parent',target,created_by:'owner',config:JSON.stringify({task_scope:{includes:[target],excludes:['http://dvwa.test/excluded/']}})};
const task={pipeline_id:'review-parent',scan_task_id:'review-child',target,created_by:'owner'};
function requestFixture({html=home,level='high'}={}){let logged=false;return async(url,o={})=>{
 if(o.method==='POST')logged=true;
 assert.equal(new URL(url).origin,new URL(target).origin);
 assert.ok(!new URL(url).pathname.includes('excluded'));
 return new Response(logged?html:login,{headers:[['set-cookie','PHPSESSID=review-session; Path=/'],['set-cookie',`security=${level}; Path=/`]]});
};}

test('request semantics: missing values, token selects, unsupported controls, repeated parameters and submit ambiguity are blocked',()=>{
 for(const html of [
  '<form><select name="csrf_token"><option value="secret">x</option></select></form>',
  '<form><input name="id" value="1"><input type="submit" name="a" value="a"><input type="submit" name="b" value="b"></form>',
  '<form><input name="id" value="1"><button name="x">Submit</button></form>',
  '<form><input name="day" type="date" value="2026-10-22"></form>',
  '<form><input name="id" value="1" formaction="/other"></form>',
  '<base href="/other/"><form action="target"><input name="id" value="1"></form>',
 ])assert.ok(discoverWebEntries(html,target,()=>true)[0].reason,html);
 assert.ok(entryFromUrl(target+'?id=').reason);
 assert.ok(entryFromUrl(target+'?id=1&id=2').reason);
 const e=discoverWebEntries('<form><input name="id" value="2"><input type="submit" name="Submit" value="Submit"><select disabled name="csrf_token"><option>x</option></select></form>',target,()=>true)[0];
 assert.equal(e.reason,null);assert.equal(e.requestUrl,target+'?id=2&Submit=Submit');
});

test('session pins server security, rejects encoded settings and login POST replay; never assumes browser security',async()=>{
 const calls=[];const s=createWebScanSession({target,credentials:auth(),allowUrl:()=>true,request:async(url,o={})=>{
   calls.push({url,method:o.method||'GET'});
   return new Response(o.method==='POST'?home:login,{headers:{'set-cookie':'PHPSESSID=review-session; Path=/, security=high; Path=/'}});
 }});
 await s.login();assert.equal(s.securityLevelFor(target),'high');
 assert.match(s.cookieFor(target),/security=high/);
 await assert.rejects(s.read(target+'%73ecurity.php'),/超出/);
 assert.equal(calls.length,2);s.close();
 const missing=createWebScanSession({target,credentials:auth(),allowUrl:()=>true,request:async(url,o)=>new Response(o.method==='POST'?home:login)});
 await assert.rejects(missing.login(),/安全等级 Cookie/);missing.close();
 let n=0;
 const change=createWebScanSession({target,credentials:auth(),allowUrl:()=>true,request:async(url,o)=>new Response(o.method==='POST'?home:login,{headers:{'set-cookie':`security=${++n===1?'high':'low'}; Path=/`}})});
 await assert.rejects(change.login(),/等级发生变化/);change.close();
 const replay=createWebScanSession({target,credentials:auth(),allowUrl:()=>true,request:async(url,o)=>o.method==='POST'?new Response('',{status:307,headers:{location:'/other'}}):new Response(login)});
 await assert.rejects(replay.login(),/拒绝.*重放/);replay.close();
});

test('SQL output requires a successful matching complete report; errors and raw titles never become positive evidence',()=>{
 const result={stdout:positive,success:true,exitCode:0,processStopped:true};
 assert.equal(sqlDetectionResult({...result,success:false},'id').status,'inconclusive');
 assert.equal(sqlDetectionResult({...result,stderr:'[ERROR] connection failed'},'id').status,'inconclusive');
 assert.equal(sqlDetectionResult({...result,stdout:positive+'\ngot a refresh intent'},'id').status,'inconclusive');
 const a=sqlDetectionResult({...result,stdout:positive+'\nParameter: id (GET)\n Type: boolean-based blind\n Title: duplicate'},'id');
 assert.equal(a.techniques.length,1);assert.doesNotMatch(JSON.stringify(a),/private page snippet|duplicate/);
 assert.ok(sqlDetectionArgs(target+'?id=1','id','security=high').includes('--answers=refresh=N,redirect=N,follow=N,extend=N'));
});

test('throwing or ambiguous runner retains protected directory and fails stop confirmation; known preflight failure cleans it',async t=>{
 for(const kind of ['throw','ambiguous','preflight']){
   let dir;
   const r=await detectWebSql({url:target+'?id=1',parameter:'id',runner:async(tool,args,o)=>{
     dir=o.privateOutputDir;
     if(kind==='throw')throw new Error('review-session must not escape');
     return {success:false,exitCode:-1,...(kind==='preflight'?{toolStarted:false}:{})};
   }});
   assert.equal(r.result.processStopped,kind==='preflight');assert.equal(r.assessment.status,'inconclusive');
   assert.doesNotMatch(JSON.stringify(r),/review-session/);
   if(kind==='preflight')await assert.rejects(stat(dir),{code:'ENOENT'});
   else {assert.equal((await stat(dir)).mode&0o777,0o700);t.after(()=>rm(dir,{recursive:true,force:true}));assert.ok(r.result.privateRunRef);}
 }
});

test('agent rejects check-before-inspect, loops after rejection, deduplicates URL/parameter across entry kinds and never stores model exceptions',async t=>{
 const db=dbFor(t);let turn=0,checks=0;const histories=[];
 const html=home+'<a href="?id=1&Submit=Submit">same parameter</a>';
 await scanWebAgent(task,{db,parent,credentials:auth(),request:requestFixture({html}),llm:async m=>{
  const input=JSON.parse(m[1].content);histories.push(input.history);turn++;
  const form=input.entries.find(e=>e.kind==='form'),link=input.entries.find(e=>e.kind==='link');
  const choices=[{action:'check_sqli',entry_id:form.id,parameter:'id',evidence_id:form.source_evidence_id},
    {action:'inspect_entry',entry_id:form.id,evidence_id:form.source_evidence_id},
    {action:'check_sqli',entry_id:form.id,parameter:'id',evidence_id:form.source_evidence_id},
    {action:'inspect_entry',entry_id:link.id,evidence_id:link.source_evidence_id},
    {action:'check_sqli',entry_id:link.id,parameter:'id',evidence_id:link.source_evidence_id},
    {action:'finish'}];
  return ok({...choices[turn-1],reason:'review'});
 },runner:async()=>{checks++;return {success:true,exitCode:0,processStopped:true,stdout:positive};}});
 assert.equal(checks,1);assert.equal(turn,6);assert.equal(histories[1][0].action,'rejected');
 assert.ok(histories[3].some(h=>h.result==='tool_positive'));
 assert.equal(db.prepare("SELECT COUNT(*) n FROM scan_results WHERE result_type='sql_injection'").get().n,1);
 const all=JSON.stringify(db.prepare('SELECT * FROM scan_results').all());assert.doesNotMatch(all,/review-session|review-password|review-login-token|private page snippet/);
 const evidence=JSON.parse(db.prepare("SELECT result_data FROM scan_results WHERE result_type='scan_evidence'").get().result_data);
 assert.equal(evidence.url,target);assert.equal(evidence.security_level,'high');assert.ok(evidence.request_sha256);
 await scanWebAgent({...task,scan_task_id:'model-error'},{db,parent,credentials:auth(),request:requestFixture(),llm:async()=>{throw new Error('unrelated-provider-secret');}});
 assert.doesNotMatch(JSON.stringify(db.prepare('SELECT * FROM scan_results').all()),/unrelated-provider-secret/);
});

test('same-origin busy lock covers concurrent tasks and unknown tools on a different path; metadata migration preserves old entries',t=>{
 const db=dbFor(t);assert.equal(hasWebScanSchema(db),true);
 db.prepare('INSERT INTO task_entries(entry_id,kind,value) VALUES (?,?,?)').run('old','form','legacy');migration(db);
 assert.equal(db.prepare('SELECT metadata FROM task_entries').get().metadata,'{}');
 const config=JSON.stringify({scan_parameters:{web:{mode:'react_sqli'}}});
 db.prepare('INSERT INTO pipelines VALUES (?,?,?,?)').run('other',target+'other/','running',config);
 assert.equal(webTargetBusy(db,target),true);assert.equal(webTargetBusy(db,target,'other'),false);
 db.prepare("UPDATE pipelines SET status='failed'").run();
 db.prepare('INSERT INTO scan_tasks VALUES (?,?,?)').run('oldscan','other',target+'sqli/');
 db.prepare('INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,state,outcome) VALUES (?,?,?,?)').run('oldrun','oldscan','failed','{"stopped":false}');
 assert.equal(webTargetBusy(db,target),true);assert.equal(webTargetBusy(db,'http://elsewhere.test/'),false);
 db.exec('ALTER TABLE task_entries RENAME COLUMN metadata TO old_metadata');assert.equal(hasWebScanSchema(db),false);
 assert.throws(()=>validateWebScanConfig({scan_parameters:{web:{version:1,mode:'react_sqli',auth_mode:'dvwa_ephemeral'}},execution_parameters:{cookie:'not-persisted'}},target));
});

test('encoded exclusion aliases and base-relative links cannot be requested; different normal requests retain identity',()=>{
 const allow=u=>!new URL(u).pathname.startsWith('/excluded/');
 const entries=discoverWebEntries('<a href="/%65xcluded/item?id=1">alias</a><a href="/excluded/item?id=1">excluded</a>',target,allow);
 assert.equal(entries.length,0);
 const base=discoverWebEntries('<base href="/excluded/"><a href="item?id=1">relative</a>',target,allow);
 assert.ok(base[0].reason);
 assert.notEqual(entryFromUrl(target+'?id=1').id,entryFromUrl(target+'?id=2').id);
 for(const html of ['<form><select name="id"><option disabled value="1">one</option><option value="2">two</option></select></form>',
 '<form><select name="id"><option selected value="1">one</option><option selected value="2">two</option></select></form>'])
 assert.ok(discoverWebEntries(html,target,allow)[0].reason);
});

test('agent checks distinct request contexts without copying input values into public records',async t=>{
 const db=dbFor(t);let turn=0,checks=0;
 const html='<a href="logout.php">Logout</a><a href="?id=1&context=first-context">one</a><a href="?id=1&context=second-context">two</a>';
 await scanWebAgent(task,{db,parent,credentials:auth(),request:requestFixture({html}),llm:async m=>{
  const {entries}=JSON.parse(m[1].content);turn++;
  if(turn>4)return ok({action:'finish',reason:'done'});
  const e=entries[Math.floor((turn-1)/2)];return ok({action:turn%2?'inspect_entry':'check_sqli',entry_id:e.id,evidence_id:e.source_evidence_id,...(turn%2?{}:{parameter:'id'}),reason:'observed'});
 },runner:async()=>{checks++;return {success:true,exitCode:0,processStopped:true,stdout:positive};}});
 assert.equal(checks,2);
 assert.doesNotMatch(JSON.stringify(db.prepare('SELECT * FROM task_entries').all()),/first-context|second-context/);
});

test('explicit sqlmap negative terminal is not confused with a genuine CRITICAL tool failure',()=>{
 const result={success:false,exitCode:0,processStopped:true,stdout:'[12:00:00] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values.\n[*] ending @ 12:00'};
 assert.equal(sqlDetectionResult(result,'id').status,'not_detected');
 for(const extra of [{stderr:'[ERROR] connection failed'},{stdout:result.stdout+'\n[CRITICAL] connection refused'},{timedOut:true},{processStopped:false},{exitCode:1}])
   assert.equal(sqlDetectionResult({...result,...extra},'id').status,'inconclusive');
});

test('credential-bearing path identities never reach coverage storage or model entries',async t=>{
 const db=dbFor(t);
 await scanWebAgent(task,{db,parent,credentials:auth(),request:requestFixture({html:'<a href="logout.php">Logout</a><a href="/review-password/?id=1">secret echo</a>'}),llm:async m=>{
   assert.doesNotMatch(JSON.stringify(m),/review-password/);return ok({action:'finish',reason:'no entry'});
 }});
 for(const table of ['task_entries','task_checks','scan_results'])assert.doesNotMatch(JSON.stringify(db.prepare('SELECT * FROM '+table).all()),/review-password/);
});
