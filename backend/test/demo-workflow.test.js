import test, {mock} from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import {fileURLToPath} from 'node:url';
import {getDb,closeDb} from '../src/db/connection.js';
import {runMigrations} from '../src/db/migrate.js';

let scenario='web', analysisCalls=0;
// The discovery boundary is controlled. The task API, pipeline, verification
// runner, real HTTP transport, evidence and completion are exercised together.
await mock.module('../src/services/scanExecutor.js',{namedExports:{
  requestScanAbort:()=>{},isScanActive:()=>false,
  executeScan:async id=>{
    const db=getDb(),scan=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(id);
    const store=(type,data,severity='info',tool='fixture')=>db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool) VALUES(?,?,?,?,?)')
      .run(id,type,JSON.stringify(data),severity,tool);
    if(scenario==='all-failed') {
      db.prepare("UPDATE scan_tasks SET status='FAILED',error_message='fixture connection failed' WHERE scan_task_id=?").run(id);
      store('scan_error',{error:'fixture connection failed'});
      return {ok:false,status:'FAILED',error:'fixture connection failed'};
    }
    if(scan.scan_type==='port_scan')store('host_discovery',{host:'127.0.0.1',status:'up'});
    else if(scenario==='unreachable') {
      store('scan_error',{error:'fixture EHOSTUNREACH'});
      db.prepare("UPDATE scan_tasks SET status='FAILED',error_message='fixture EHOSTUNREACH' WHERE scan_task_id=?").run(id);
      return {ok:false,status:'FAILED',error:'fixture EHOSTUNREACH'};
    } else if(scenario==='source' || scenario==='runtime') {
      store(scenario==='source'?'source_finding':'program_finding',
        {title:'Controlled fixture observation',file:'fixture.c',start_line:1,url:scan.target,reason:'Fixture only'},'medium');
    } else if(scenario!=='empty') {
      store('web_vuln',{finding:'The X-Content-Type-Options header is not set.',url:scan.target},'medium','nikto');
    }
    db.prepare("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id=?").run(id);
    return {ok:true,status:'COMPLETED',resultsCount:1};
  }
}});
await mock.module('../src/services/scanAnalyzer.js',{namedExports:{analyzeScanResults:async()=>{
  analysisCalls++;return {ok:true,data:{tech_stack:[],attack_surface:[],risk_assessment:[],recommended_strategy:[]}};
}}});
const {default:pipelines}=await import('../src/routes/pipelines.js');
const {runPipeline}=await import('../src/services/pipelineEngine.js');
const {scanPage}=await import('../src/services/scanResultQuery.js');

async function fixture(t) {
  const db=getDb(':memory:');
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  for(const name of ['demo-owner','demo-other'])db.prepare("INSERT INTO users(username,password,role,is_active) VALUES(?,'fixture','user',1)").run(name);
  const targetServer=http.createServer((_req,res)=>{res.setHeader('content-type','text/html');res.end('<html>controlled fixture</html>');});
  await new Promise(resolve=>targetServer.listen(0,'127.0.0.1',resolve));
  const target=`http://127.0.0.1:${targetServer.address().port}/`;
  const app=express();app.use(express.json(),(req,res,next)=>{req.user={sub:req.headers['x-user'] || 'demo-owner',role:'user'};next();});
  app.use('/pipelines',pipelines(db));
  app.use((e,req,res,_next)=>res.status(e.status || 500).json({status:'error',error:{message:e.message}}));
  const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(async()=>{
    for(const s of [server,targetServer]) {s.closeAllConnections();await new Promise(resolve=>s.close(resolve));}
    closeDb();
  });
  const api=`http://127.0.0.1:${server.address().port}`;
  async function request(path,body,method='POST',user='demo-owner') {
    const r=await fetch(api+path,{method,headers:{'content-type':'application/json','x-user':user},...(body===undefined?{}:{body:JSON.stringify(body)})});
    return {status:r.status,body:await r.json()};
  }
  async function create(config={workflow:'per_finding'}) {
    const r=await request('/pipelines',{target,config});assert.equal(r.status,201,JSON.stringify(r.body));return r.body.data.pipeline_id;
  }
  const current=id=>db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(id);
  return {db,target,request,create,current};
}
async function until(check) {
  const deadline=Date.now()+5000;
  while(!check() && Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,10));
  assert.ok(check(),'expected workflow state');
}

test('new task → scan → actual finding → explicit verification → HTTP evidence → statistics → completion',async t=>{
  scenario='web';analysisCalls=0;const f=await fixture(t),id=await f.create();
  const base='/pipelines/'+id;
  assert.equal((await f.request(base+'/start',{})).status,202);
  await until(()=>f.current(id).status==='awaiting_approval');
  assert.equal(analysisCalls,0,'discovery must not invent an AI attack plan');
  assert.equal(f.current(id).generated_playbook_id,null);
  const page=(await f.request(base+'/results?view=scans&category=vulnerability',undefined,'GET')).body.data;
  assert.ok(page.scan_records.length>0);
  assert.equal(page.verification_statistics.tested_records,0);
  assert.equal((await f.request(base+'/approve',{})).status,409);
  assert.equal((await f.request(base+'/plan',{})).status,409);
  assert.equal((await f.request(base,{config:{workflow:'legacy'}},'PUT')).status,409);
  const finding=page.scan_records[0].id;
  const item=(await f.request(base+'/verifications',{finding_id:finding})).body.data;
  const verify=base+'/verifications/'+item.id;
  assert.equal((await f.request(verify+'/select-template',{playbook_id:'f08-web-headers-v1',expected_revision:0})).status,200);
  const detail=(await f.request(verify,undefined,'GET')).body.data;
  assert.equal(detail.readiness.ready,true);
  const input={revision:detail.revision,fingerprint:detail.readiness.fingerprint,confirmed:true,request_id:'demo-first'};
  const started=await f.request(verify+'/start',input);assert.equal(started.status,200,JSON.stringify(started.body));
  const attempt=started.body.data;
  await until(()=>f.db.prepare('SELECT state FROM finding_verification_attempts WHERE id=?').get(attempt.id).state==='completed');
  assert.equal((await f.request(verify+'/start',input)).body.data.id,attempt.id,'retrying a request never starts another tool');
  const stats=scanPage(f.db,f.current(id)).verification_statistics;
  assert.equal(stats.attempt_count,1);assert.equal(stats.tested_records,1);assert.equal(stats.confirmed_records,1);
  assert.equal(stats.expected_count,null);
  const retry=await f.request(verify+'/start',{...input,request_id:'demo-retry'});
  assert.equal(retry.status,200);
  await until(()=>f.db.prepare('SELECT state FROM finding_verification_attempts WHERE id=?').get(retry.body.data.id).state==='completed');
  const repeated=scanPage(f.db,f.current(id)).verification_statistics;
  assert.equal(repeated.attempt_count,2);assert.equal(repeated.tested_records,1);assert.equal(repeated.confirmed_records,1);
  assert.equal((await f.request(base+'/complete-verifications',{confirmed:true},'POST','demo-other')).status,403);
  const done=await f.request(base+'/complete-verifications',{confirmed:true});assert.equal(done.status,200);
  assert.equal(f.current(id).status,'completed');
  assert.deepEqual((await f.request(base+'/complete-verifications',{confirmed:true})).body.data,done.body.data,'completion is idempotent');
  assert.equal((await f.request(verify+'/start',{...input,request_id:'new-after-finish'})).status,409);
  assert.equal(f.db.prepare('SELECT count(*) n FROM evidence_records WHERE run_id=?').get(attempt.run_id).n,1,'completion preserves evidence');
});

test('source and runtime tasks use the same finding selection; absent workflow preserves the source baseline',async t=>{
  const f=await fixture(t);analysisCalls=0;
  for(const kind of ['source','runtime']) {
    scenario=kind;
    const id=await f.create({workflow:'per_finding',test_type:'program',input_kind:kind,
      ...(kind==='source'?{source_url:f.target+'source/',runtime_target:f.target}:{})});
    const result=await runPipeline(id);assert.equal(result.ok,true);
    assert.equal(JSON.parse(f.current(id).result).paused_at,'finding_selection');
    const page=scanPage(f.db,f.current(id),{category:'vulnerability'});
    assert.ok(page.scan_records.some(r=>r.result_type===(kind==='source'?'source_finding':'program_finding')));
    const base='/pipelines/'+id;
    const item=(await f.request(base+'/verifications',{finding_id:page.scan_records[0].id})).body.data;
    const verify=base+'/verifications/'+item.id;
    const saved=await f.request(verify+'/plans',{expected_revision:0,name:'Program response observation',target:f.target,
      prerequisites:['Controlled program runtime corresponding to this finding'],missing_conditions:[],
      success_criteria:'A successful response only establishes reachability; manual review must not infer exploitation',
      cleanup:'Read-only local fixture',max_attempts:2,duration_ms:5000,
      steps:[{name:'Observe actual program response',tool_id:'target-request',consumption:'none',
        args_template:[JSON.stringify({url:f.target,method:'GET'})],expected_evidence:'Actual runtime response'}]});
    assert.equal(saved.status,200,JSON.stringify(saved.body));
    const plan=(await f.request(verify,undefined,'GET')).body.data;
    const started=await f.request(verify+'/start',{revision:plan.revision,fingerprint:plan.readiness.fingerprint,
      confirmed:true,request_id:kind+'-runtime-observation'});
    assert.equal(started.status,200,JSON.stringify(started.body));
    await until(()=>f.db.prepare('SELECT state FROM finding_verification_attempts WHERE id=?').get(started.body.data.id)?.state==='completed');
    const executed=(await f.request(verify,undefined,'GET')).body.data;
    assert.equal(executed.summary.conclusion,'pending','successful software response does not prove a vulnerability');
    const evidence=executed.attempts[0].evidence;
    assert.ok(evidence.length>0);assert.equal(evidence[0].observation.status_code,200);
    const review=await f.request(verify+'/reviews',{attempt_id:started.body.data.id,conclusion:'inconclusive',
      evidence_ids:[evidence[0].id],note:'The runtime responded, but no vulnerability-specific effect was established.'});
    assert.equal(review.status,200,JSON.stringify(review.body));
    const stats=scanPage(f.db,f.current(id)).verification_statistics;
    assert.equal(stats.tested_records,1);assert.equal(stats.confirmed_records,0);assert.equal(stats.inconclusive_records,1);
    assert.equal((await f.request(base+'/complete-verifications',{confirmed:true})).status,200);
  }
  assert.equal(analysisCalls,0);
  scenario='runtime';const legacy=await f.create({test_type:'program'});
  await runPipeline(legacy);
  assert.equal(JSON.parse(f.current(legacy).result).paused_at,'program_selection');
  assert.equal(analysisCalls,1,'the legacy branch remains operational');
  assert.equal((await f.request('/pipelines/'+legacy+'/complete-verifications',{confirmed:true})).status,409);
});

test('empty, partially unreachable and fully failed scans do not generate model risks or execute attacks',async t=>{
  const f=await fixture(t);analysisCalls=0;
  for(const kind of ['empty','unreachable','all-failed']) {
    scenario=kind;const id=await f.create();await runPipeline(id);
    const pipeline=f.current(id),page=scanPage(f.db,pipeline);
    assert.equal(page.verification_statistics.candidate_records,0);
    assert.equal(page.verification_statistics.tested_records,0);
    assert.equal(pipeline.generated_playbook_id,null);
    assert.equal(pipeline.status,kind==='all-failed'?'failed':'awaiting_approval');
    if(kind==='unreachable') assert.equal(page.scan_summary.completeness,'incomplete');
  }
  assert.equal(analysisCalls,0);
  assert.equal(f.db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
});

test('source-only findings cannot execute against the source file server, even with a manually saved plan',async t=>{
  scenario='source';const f=await fixture(t);
  const id=await f.create({workflow:'per_finding',test_type:'program',input_kind:'source',source_url:f.target+'source/'});
  await runPipeline(id);
  const finding=scanPage(f.db,f.current(id),{category:'vulnerability'}).scan_records[0].id;
  const base='/pipelines/'+id+'/verifications';
  const item=(await f.request(base,{finding_id:finding})).body.data;
  const detail=(await f.request(base+'/'+item.id,undefined,'GET')).body.data;
  assert.equal(detail.default_target,null);
  assert.match(detail.entry_context.missing_conditions.join(' '),/运行入口/);
  const saved=await f.request(base+'/'+item.id+'/plans',{expected_revision:0,name:'Fixture manual draft',target:f.target,
    prerequisites:['fixture'],missing_conditions:[],success_criteria:'Fixture response only',cleanup:'Read-only fixture',max_attempts:2,duration_ms:1000,
    steps:[{name:'Observe',tool_id:'target-request',args_template:[JSON.stringify({url:f.target,method:'GET'})],
      consumption:'none',description:'fixture',expected_evidence:'fixture response'}]});
  assert.equal(saved.status,200);
  assert.equal((await f.request(base+'/'+item.id+'/preflight',{revision:1})).status,409);
  assert.equal(f.db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
});

test('completion rejects unfinished scans and unconfirmed stops; statistics never count blocked work as actual testing',async t=>{
  scenario='web';const f=await fixture(t),id=await f.create();await runPipeline(id);
  const base='/pipelines/'+id,scan=f.db.prepare('SELECT scan_task_id FROM scan_tasks WHERE pipeline_id=? LIMIT 1').get(id);
  f.db.prepare("UPDATE scan_tasks SET status='RUNNING' WHERE scan_task_id=?").run(scan.scan_task_id);
  assert.equal((await f.request(base+'/complete-verifications',{confirmed:true})).status,409);
  f.db.prepare("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id=?").run(scan.scan_task_id);
  const finding=scanPage(f.db,f.current(id),{category:'vulnerability'}).scan_records[0].id;
  const item=(await f.request(base+'/verifications',{finding_id:finding})).body.data;
  const verify=base+'/verifications/'+item.id;
  await f.request(verify+'/select-template',{playbook_id:'f08-web-headers-v1',expected_revision:0});
  const detail=(await f.request(verify,undefined,'GET')).body.data;
  // Create an accepted attempt with no actual tool-start evidence, as can
  // happen after preflight rejection or loss of a process handle.
  f.db.prepare("INSERT INTO execution_runs(run_id,playbook_id,status,target) VALUES('blocked-run','f08-web-headers-v1','FAILED',?)").run(f.target);
  f.db.prepare(`INSERT INTO finding_verification_attempts(id,verification_id,pipeline_id,revision,run_id,request_id,state,stop_confirmed)
    VALUES('blocked-attempt',?,?,?,'blocked-run','blocked-request','unknown',0)`).run(item.id,id,detail.revision);
  assert.equal((await f.request(base+'/complete-verifications',{confirmed:true})).status,409);
  assert.equal((await f.request(base+'/cancel',{})).status,409);
  let stats=scanPage(f.db,f.current(id)).verification_statistics;
  assert.equal(stats.attempt_count,1);assert.equal(stats.submitted_records,1);assert.equal(stats.tested_records,0);
  f.db.prepare("UPDATE finding_verification_attempts SET state='failed',stop_confirmed=1 WHERE id='blocked-attempt'").run();
  assert.equal((await f.request(base+'/complete-verifications',{confirmed:true})).status,200);
  stats=scanPage(f.db,f.current(id)).verification_statistics;
  assert.equal(stats.failed_records,1);assert.equal(stats.confirmed_records,0);assert.equal(stats.tested_records,0);
});
