import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { runMigrations } from '../src/db/migrate.js';
import { fileURLToPath } from 'node:url';
import { ensureVerification,saveVerificationPlan,confirmVerificationPlan,createVerificationAttempt,reviewVerification,verificationDetail,checkVerificationPlan } from '../src/services/findingVerification.js';
import { launchVerification,reconcileVerificationAttempts,cancelVerification } from '../src/services/findingVerificationRunner.js';
import { payloadVersion } from '../src/services/findingPayloads.js';
import { getPayloadById } from '../src/services/payloadLoader.js';
import routes from '../src/routes/findingVerifications.js';
import express from 'express';
import http from 'node:http';

const actor={sub:'f08_alice',role:'user'};
async function fixture(existingDb) {
  const db=existingDb || new Database(':memory:');db.pragma('foreign_keys=ON');
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  for(const name of ['f08_alice','f08_bob'])db.prepare("INSERT INTO users(username,password,role,is_active) VALUES(?,'fixture','user',1)").run(name);
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,config,scan_task_id) VALUES('f08_p','http://fixture.invalid','completed','f08_alice','{}','f08_s')").run();
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id) VALUES('f08_s','http://fixture.invalid','web_scan','COMPLETED','f08_alice','f08_p')").run();
  const insert=db.prepare("INSERT INTO scan_results(scan_task_id,result_type,severity,result_data) VALUES('f08_s','sql_injection','high',?)");
  const finding=Number(insert.run(JSON.stringify({finding:'SQL injection parameter id',url:'http://fixture.invalid/item'})).lastInsertRowid);
  const second=Number(insert.run(JSON.stringify({finding:'SQL injection parameter other'})).lastInsertRowid);
  const pipeline=db.prepare("SELECT * FROM pipelines WHERE pipeline_id='f08_p'").get();
  const item=ensureVerification(db,pipeline,finding);
  const plan={expected_revision:0,name:'Specific finding verification',target:pipeline.target,prerequisites:['fixture baseline'],missing_conditions:[],
    success_criteria:'Compare the observed result against the documented finding and baseline; manual evidence review required',cleanup:'Read-only fixture; no cleanup',max_attempts:2,duration_ms:10000,
    steps:[{name:'Observe',tool_id:'target-request',args_template:[JSON.stringify({url:pipeline.target,method:'GET'})],consumption:'none',description:'Known entry',expected_evidence:'Actual response and baseline'}]};
  return {db,pipeline,item,plan,finding,second};
}
function prepare(f){saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,f.plan);confirmVerificationPlan(f.db,f.pipeline,actor,f.item.id,{revision:1,conditions_confirmed:true,criteria_confirmed:true});}
const request={revision:1,request_id:'fixture-request-1'};

test('F08 migration is additive and repeatable; frozen revisions, scope and idempotency remain independent of parent run',async()=>{
  const f=await fixture();try {
    assert.deepEqual(await runMigrations(f.db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url))),[]);
    assert.equal(ensureVerification(f.db,f.pipeline,f.finding).id,f.item.id);
    assert.throws(()=>saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,{...f.plan,target:'http://outside.invalid'}),/范围/);
    prepare(f);assert.throws(()=>saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,f.plan),/已更新/);
    const a=createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,request);
    assert.equal(createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,request).id,a.id);
    assert.equal(f.db.prepare("SELECT run_id FROM pipelines WHERE pipeline_id='f08_p'").get().run_id,null);
    assert.throws(()=>createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,{...request,request_id:'second'}),/活动验证/);
    reconcileVerificationAttempts(f.db,'f08_p');
    assert.equal(f.db.prepare('SELECT state FROM finding_verification_attempts WHERE id=?').get(a.id).state,'unknown');
    assert.throws(()=>createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,{...request,request_id:'second'}),/未确认停止/);
    assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
  } finally {f.db.close();}
});

test('F08 tool success leaves conclusion pending; reviews require evidence of this finding and attempt; retry preserves history and is bounded',async()=>{
  const f=await fixture();try {
    prepare(f);
    const engine={executeRun:async runId=>{
      const run=f.db.prepare('SELECT * FROM execution_runs WHERE run_id=?').get(runId);
      const linkage=JSON.parse(run.plan_data).finding_verification;
      f.db.prepare("INSERT INTO evidence_records(run_id,step_index,tool_id,evidence_data,recorded_at) VALUES(?,0,'target-request',?,datetime('now'))").run(runId,JSON.stringify({success:true,finding_verification:linkage}));
      f.db.prepare("INSERT INTO execution_steps(run_id,step_index,tool_id,success) VALUES(?,0,'target-request',1)").run(runId);
      f.db.prepare("UPDATE execution_runs SET status='COMPLETED' WHERE run_id=?").run(runId);
      return {status:'COMPLETED',processStopped:true};
    }};
    const a=createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,request);await launchVerification(f.db,a,actor,{engine});
    let detail=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(detail.summary.conclusion,'pending');assert.equal(detail.attempts[0].state,'completed');
    const evidence=detail.attempts[0].evidence[0].id;
    assert.throws(()=>reviewVerification(f.db,f.pipeline,actor,f.item.id,{attempt_id:a.id,conclusion:'confirmed',evidence_ids:[99999],note:'Observed'}),/证据不属于/);
    reviewVerification(f.db,f.pipeline,actor,f.item.id,{attempt_id:a.id,conclusion:'not_verified',evidence_ids:[evidence],note:'Expected evidence absent'});
    assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).summary.conclusion,'not_verified');
    const b=createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,{...request,request_id:'retry-2'});await launchVerification(f.db,b,actor,{engine});
    assert.throws(()=>reviewVerification(f.db,f.pipeline,actor,f.item.id,{attempt_id:b.id,conclusion:'confirmed',evidence_ids:[evidence],note:'Wrong attempt'}),/证据不属于/);
    assert.throws(()=>createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,{...request,request_id:'retry-3'}),/上限/);
    assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).attempts.length,2);
  }finally{f.db.close();}
});

test('F08 cancellation waits for actual stop and preserves unknown stop failures',async()=>{
  const f=await fixture();try {
    prepare(f);let finish;let entered;const started=new Promise(r=>entered=r);
    const engine={executeRun:async runId=>{entered();await new Promise(r=>finish=r);f.db.prepare("UPDATE execution_runs SET status='ABORTED' WHERE run_id=?").run(runId);return {processStopped:false};},requestAbort:()=>{}};
    const a=createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,request);const running=launchVerification(f.db,a,actor,{engine});await started;
    await cancelVerification(f.db,a,{engine});assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).state,'cancelling');
    assert.throws(()=>createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,{...request,request_id:'retry'}),/活动验证/);
    finish();await running;assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).state,'unknown');
  }finally{f.db.close();}
});

test('F08 unavailable remote or authentication conditions cannot be confirmed; invalid and changed payloads are rejected',async()=>{
  const f=await fixture();try{
    const blocked={...f.pipeline,config:JSON.stringify({task_scope:{includes:[f.pipeline.target],execution_location:'remote'}})};
    saveVerificationPlan(f.db,blocked,actor,f.item.id,f.plan);
    assert.throws(()=>confirmVerificationPlan(f.db,blocked,actor,f.item.id,{revision:1,conditions_confirmed:true,criteria_confirmed:true}),/远端/);
    assert.throws(()=>saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,{...f.plan,expected_revision:1,steps:[{...f.plan.steps[0],consumption:'independent',payload_id:'missing',payload_version:'old'}]}),/载荷/);
  }finally{f.db.close();}
});

test('F08 API enforces owner, selected finding identity and bounded model correction without tool execution',async()=>{
  const f=await fixture();let calls=0;
  const app=express();app.use(express.json(),(req,res,next)=>{req.user={sub:req.headers['x-user'] || actor.sub,role:'user'};next();});
  app.use('/tasks/:id/verifications',routes(f.db,{llm:async()=>{calls++;return {ok:true,content:'{}'};}}));
  app.use((err,req,res,next)=>res.status(err.status || 500).json({error:err.message}));
  const server=http.createServer(app);await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const base=`http://127.0.0.1:${server.address().port}/tasks/f08_p/verifications`;
  const post=(path,body,user=actor.sub)=>fetch(base+path,{method:'POST',headers:{'content-type':'application/json','x-user':user},body:JSON.stringify(body)});
  try{
    assert.equal((await post('',{finding_id:f.finding},'f08_bob')).status,403);
    assert.equal((await post('',{finding_id:999999})).status,404);
    assert.equal((await post('/'+f.item.id+'/generate',{expected_revision:0})).status,422);assert.equal(calls,2);
    assert.equal(f.db.prepare('SELECT count(*) n FROM finding_verification_plans').get().n,0);
    const detail=verificationDetail(f.db,f.pipeline,f.item.id);
    assert.equal(detail.state,'preparation_failed');assert.match(detail.reason,/未启动新的验证执行/);
    assert.equal(detail.attempts.length,0);assert.equal(detail.summary.conclusion,'pending');
  }finally{await new Promise(r=>server.close(r));f.db.close();}
});

test('F08 generated payload is frozen, consumed by the real engine and linked to evidence; changed versions cannot start',async()=>{
  const {getDb,closeDb}=await import('../src/db/connection.js');
  const server=http.createServer((req,res)=>{res.writeHead(200,{'content-type':'text/plain'});res.end('isolated baseline response');});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const f=await fixture(getDb(':memory:'));
  try {
    const target=`http://127.0.0.1:${server.address().port}/`;
    f.db.prepare("UPDATE pipelines SET target=? WHERE pipeline_id='f08_p'").run(target);
    f.db.prepare("UPDATE scan_tasks SET target=? WHERE scan_task_id='f08_s'").run(target);
    f.pipeline=f.db.prepare("SELECT * FROM pipelines WHERE pipeline_id='f08_p'").get();f.plan.target=target;
    const payload={id:'f08_fixture_sqli',name:'SQL injection fixture',tags:['sqli'],version:1,
      consumption:{type:'tool_args',tool_id:'target-request',args_template:[JSON.stringify({url:'<target>',method:'GET'})]},validation:{runtime_verified:false}};
    f.db.prepare("INSERT INTO generated_payloads(payload_id,name,payload_type,payload_data,import_status) VALUES(?,?,'web',?,'accepted')")
      .run(payload.id,payload.name,JSON.stringify(payload));
    const loaded=getPayloadById(payload.id,f.db), version=payloadVersion(loaded);
    f.plan.steps=[{...f.plan.steps[0],args_template:[],consumption:'independent',payload_id:payload.id,payload_version:version}];
    prepare(f);
    const a=createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,request);
    await launchVerification(f.db,a,actor);
    const detail=verificationDetail(f.db,f.pipeline,f.item.id);
    assert.equal(detail.attempts[0].state,'completed',JSON.stringify(detail.attempts[0]));
    assert.equal(detail.attempts[0].stop_confirmed,1);
    assert.equal(detail.summary.conclusion,'pending');
    const evidence=detail.attempts[0].evidence[0].evidence_data;
    assert.equal(evidence.payload_id,payload.id);
    assert.equal(evidence.finding_verification.payload_version,version);
    assert.equal(evidence.finding_verification.finding_id,f.finding);
    assert.match(detail.attempts[0].evidence[0].raw_stdout,/isolated baseline response/);
    f.db.prepare('UPDATE generated_payloads SET payload_data=? WHERE payload_id=?').run(JSON.stringify({...payload,version:2}),payload.id);
    assert.throws(()=>createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,{...request,request_id:'changed'}),/版本/);
    assert.equal(JSON.parse(f.db.prepare('SELECT content FROM finding_verification_plans WHERE verification_id=?').get(f.item.id).content).steps[0].payload_snapshot.version,1);
  } finally {closeDb();await new Promise(r=>server.close(r));}
});

test('F08 internal inputs and no-payload plans work; authentication and cross-finding evidence cannot bypass checks',async()=>{
  const f=await fixture();try{
    f.plan.steps[0].consumption='internal';prepare(f);
    const a=createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,request);
    await launchVerification(f.db,a,actor,{engine:{executeRun:async runId=>{
      f.db.prepare("UPDATE execution_runs SET status='COMPLETED' WHERE run_id=?").run(runId);
      f.db.prepare("INSERT INTO execution_steps(run_id,step_index,tool_id,success) VALUES(?,0,'target-request',0)").run(runId);
      return {processStopped:true};
    }}});
    assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).state,'failed','a completed engine run with a failed step is an execution error');
    const badEvidence=Number(f.db.prepare("INSERT INTO evidence_records(run_id,step_index,tool_id,evidence_data) VALUES(?,0,'target-request',?)")
      .run(a.run_id,JSON.stringify({finding_verification:{finding_id:f.second,attempt_id:a.id,revision:1}})).lastInsertRowid);
    assert.throws(()=>reviewVerification(f.db,f.pipeline,actor,f.item.id,{attempt_id:a.id,conclusion:'confirmed',evidence_ids:[badEvidence],note:'different finding'}),/证据不属于/);
    const auth={...f.pipeline,config:JSON.stringify({task_scope:{includes:[f.pipeline.target],auth_config_ref:'fixture-auth'}})};
    saveVerificationPlan(f.db,auth,actor,f.item.id,{...f.plan,expected_revision:1});
    assert.throws(()=>confirmVerificationPlan(f.db,auth,actor,f.item.id,{revision:2,conditions_confirmed:true,criteria_confirmed:true}),/凭据提供方/);
  }finally{f.db.close();}
});

test('F08 acknowledged cancellation permits a new attempt and late completion cannot claim vulnerability success',async()=>{
  const f=await fixture();try{
    prepare(f);let entered,finish;const started=new Promise(r=>entered=r);
    const engine={executeRun:async runId=>{entered();await new Promise(r=>finish=r);f.db.prepare("UPDATE execution_runs SET status='ABORTED' WHERE run_id=?").run(runId);return {processStopped:true};},requestAbort:()=>finish()};
    const a=createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,request);const pending=launchVerification(f.db,a,actor,{engine});await started;
    await cancelVerification(f.db,a,{engine});await pending;
    const detail=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(detail.state,'aborted');assert.equal(detail.summary.conclusion,'pending');
    assert.notEqual(createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,{...request,request_id:'retry-after-stop'}).id,a.id);
  }finally{f.db.close();}
});

test('generated plan inherits authoritative target only when omitted, while explicit outside targets remain rejected',async()=>{
  const f=await fixture();const app=express();let outside=false;
  app.use(express.json(),(req,res,next)=>{req.user=actor;next();});
  app.use('/tasks/:id/verifications',routes(f.db,{llm:async()=>{
    const {target,expected_revision,...content}=f.plan;
    return {ok:true,content:JSON.stringify({...content,...(outside?{target:'http://outside.invalid'}:{})})};
  }}));
  app.use((error,req,res,next)=>res.status(error.status||500).json({error:error.message}));
  const server=http.createServer(app);await new Promise(r=>server.listen(0,'127.0.0.1',r));
  const url=`http://127.0.0.1:${server.address().port}/tasks/f08_p/verifications/${f.item.id}/generate`;
  try {
    const post=revision=>fetch(url,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({expected_revision:revision})});
    assert.equal((await post(0)).status,200);
    assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).plans[0].content.target,'http://fixture.invalid/item');
    outside=true;assert.equal((await post(1)).status,422);
    assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).revision,1);
  }finally{await new Promise(r=>server.close(r));f.db.close();}
});

test('ordinary Nikto method enumeration is information for new and legacy findings, with consistent paging and F08 rejection',async()=>{
  const {parseScanOutput}=await import('../src/services/scanResultParsers.js');
  const {resultCategory}=await import('../src/services/scanResultCatalog.js');
  const {scanPage}=await import('../src/services/scanResultQuery.js');
  const {matchPayloads}=await import('../src/services/findingPayloads.js');
  const parsed=parseScanOutput('web_scan_nikto','+ Allowed HTTP Methods: POST, OPTIONS, HEAD, GET','');
  const row=parsed.records.find(r=>r.source_tool==='nikto' && r.result_data.finding);
  assert.equal(row.result_type,'information');assert.equal(row.severity,'info');
  for(const text of ['Allowed HTTP Methods: GET, POST, OPTIONS, HEAD','Allowed HTTP Methods: HEAD GET'])
    assert.equal(resultCategory({source_tool:'nikto',result_type:'web_vuln',severity:'low',result_data:JSON.stringify({finding:text})}),'information');
  for(const text of ['Allowed HTTP Methods: GET, PUT, DELETE','Allowed HTTP Methods: TRACE','Allowed HTTP Methods: GET, POST. Authentication bypass found','The X-Frame-Options header is not present.'])
    assert.equal(resultCategory({source_tool:'nikto',result_type:'web_vuln',severity:'low',result_data:JSON.stringify({finding:text})}),'vulnerability');
  const f=await fixture();try {
    const raw=JSON.stringify({finding:'Allowed HTTP Methods: POST, OPTIONS, HEAD, GET'});
    const id=Number(f.db.prepare("INSERT INTO scan_results(scan_task_id,result_type,severity,source_tool,result_data) VALUES('f08_s','web_vuln','low','nikto',?)").run(raw).lastInsertRowid);
    const page=scanPage(f.db,f.pipeline,{category:'information'});
    assert.equal(page.page.total,1);assert.equal(page.scan_records[0].id,id);assert.equal(page.scan_records[0].category,'information');
    assert.equal(scanPage(f.db,f.pipeline,{category:'vulnerability'}).page.total,2);
    const old=f.db.prepare('SELECT * FROM scan_results WHERE id=?').get(id);
    assert.deepEqual(matchPayloads(f.db,old),[]);
    assert.throws(()=>ensureVerification(f.db,f.pipeline,id),/信息/);
    assert.equal(old.result_data,raw);assert.equal(old.result_type,'web_vuln');
  }finally{f.db.close();}
});

test('missing conditions and model connection failures are preparation outcomes and never create execution attempts',async()=>{
 const f=await fixture();let mode='conditions';
 const app=express();app.use(express.json(),(req,res,next)=>{req.user=actor;next();});
 app.use('/tasks/:id/verifications',routes(f.db,{llm:async()=>{
   if(mode==='error')throw new Error('internal connection error');
   return {ok:true,content:JSON.stringify({missing_conditions:['缺少已授权的认证配置'],steps:[]})};
 }}));
 const server=http.createServer(app);await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try {
  const send=()=>fetch(`http://127.0.0.1:${server.address().port}/tasks/f08_p/verifications/${f.item.id}/generate`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({expected_revision:0})});
  const missing=await send();assert.equal(missing.status,200);assert.equal((await missing.json()).data.state,'needs_conditions');
  mode='error';const failed=await send();assert.equal(failed.status,502);assert.match((await failed.json()).error.message,/方案准备失败.*未启动/);
  const detail=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(detail.state,'preparation_failed');assert.equal(detail.attempts.length,0);assert.equal(detail.summary.conclusion,'pending');
 }finally{await new Promise(r=>server.close(r));f.db.close();}
});

test('preparation with missing conditions preserves an already confirmed plan and reports concurrent changes',async()=>{
  const f=await fixture();prepare(f);
  let started,finish;
  const entered=new Promise(resolve=>started=resolve);
  let delayed=false;
  const app=express();app.use(express.json(),(req,res,next)=>{req.user=actor;next();});
  app.use('/tasks/:id/verifications',routes(f.db,{llm:async()=>{
    if(delayed){started();await new Promise(resolve=>finish=resolve);}
    return {ok:true,content:JSON.stringify({missing_conditions:['缺少目标部署版本'],steps:[]})};
  }}));
  const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const send=()=>fetch(`http://127.0.0.1:${server.address().port}/tasks/f08_p/verifications/${f.item.id}/generate`,{
    method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({expected_revision:1})});
  try {
    const original=f.db.prepare('SELECT * FROM finding_verification_plans WHERE verification_id=?').get(f.item.id);
    assert.equal((await send()).status,200);
    const detail=verificationDetail(f.db,f.pipeline,f.item.id);
    assert.equal(detail.state,'ready','an unusable replacement must not change the confirmed plan state');
    assert.equal(detail.plans[0].content.target,f.plan.target);
    assert.deepEqual(f.db.prepare('SELECT * FROM finding_verification_plans WHERE verification_id=?').get(f.item.id),original);
    assert.equal(detail.attempts.length,0);
    delayed=true;const pending=send();await entered;
    saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,{...f.plan,expected_revision:1,name:'Newer saved version'});
    finish();assert.equal((await pending).status,409,'late generation must report conflict rather than claim it updated conditions');
    assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).revision,2);
    assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).reason,null);
  } finally {await new Promise(resolve=>server.close(resolve));f.db.close();}
});

test('preparation cannot accept empty or malformed missing conditions as a useful result',async()=>{
  const f=await fixture();let missing;
  const app=express();app.use(express.json(),(req,res,next)=>{req.user=actor;next();});
  app.use('/tasks/:id/verifications',routes(f.db,{llm:async()=>({ok:true,content:JSON.stringify({steps:[],missing_conditions:missing})})}));
  const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try {
    for(missing of [[''],['   '],[{}],Array(31).fill('condition')]) {
      const response=await fetch(`http://127.0.0.1:${server.address().port}/tasks/f08_p/verifications/${f.item.id}/generate`,{
        method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({expected_revision:0})});
      assert.equal(response.status,422,'invalid missing conditions must be rejected');
    }
    const detail=verificationDetail(f.db,f.pipeline,f.item.id);
    assert.equal(detail.state,'preparation_failed');assert.equal(detail.attempts.length,0);
  } finally {await new Promise(resolve=>server.close(resolve));f.db.close();}
});

test('reclassified informational findings retain readable history and allow cancellation but reject new preparation',async()=>{
  const f=await fixture();prepare(f);let entered,finish;const started=new Promise(resolve=>entered=resolve);let aborted=0,modelCalls=0;
  const engine={executeRun:async runId=>{entered();await new Promise(resolve=>finish=resolve);f.db.prepare("UPDATE execution_runs SET status='ABORTED' WHERE run_id=?").run(runId);return {processStopped:true};},requestAbort:()=>{aborted++;finish();}};
  const app=express();app.use(express.json(),(req,res,next)=>{req.user=actor;next();});
  app.use('/tasks/:id/verifications',routes(f.db,{engine,llm:async()=>{modelCalls++;return {ok:true,content:'{}'};}}));
  const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const base=`http://127.0.0.1:${server.address().port}/tasks/f08_p/verifications`;
  let pending;
  try {
    const attempt=createVerificationAttempt(f.db,f.pipeline,actor,f.item.id,request);
    pending=launchVerification(f.db,attempt,actor,{engine});await started;
    f.db.prepare("UPDATE scan_results SET result_type='web_vuln',source_tool='nikto',severity='low',result_data=? WHERE id=?")
      .run(JSON.stringify({finding:'Allowed HTTP Methods: GET, HEAD, POST, OPTIONS'}),f.finding);
    const history=await fetch(base+'/'+f.item.id);assert.equal(history.status,200);
    const detail=(await history.json()).data;assert.equal(detail.eligible,false);assert.equal(detail.attempts[0].id,attempt.id);
    const post=(path,body)=>fetch(base+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
    assert.equal((await post('/'+f.item.id+'/generate',{expected_revision:1})).status,400);
    assert.equal((await post('',{finding_id:f.finding})).status,400);assert.equal(modelCalls,0);
    assert.equal((await post('/'+f.item.id+'/execute',{revision:1,request_id:'reclassified'})).status,400);
    assert.equal((await post('/'+f.item.id+'/cancel',{})).status,200);await pending;
    assert.equal(aborted,1);
    const final=(await (await fetch(base+'/'+f.item.id)).json()).data;
    assert.equal(final.attempts[0].state,'aborted');assert.equal(final.attempts[0].stop_confirmed,1);
  } finally {if(finish)finish();if(pending)await pending;await new Promise(resolve=>server.close(resolve));f.db.close();}
});

test('model schema envelope contains a real plan and is validated without a needless retry',async()=>{
 const f=await fixture();let calls=0;
 const app=express();app.use(express.json(),(req,res,next)=>{req.user=actor;next();});
 app.use('/tasks/:id/verifications',routes(f.db,{llm:async()=>{calls++;const {expected_revision,...plan}=f.plan;return {ok:true,content:JSON.stringify({type:'verification_plan',schema:plan})};}}));
 const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try {
  const result=await fetch(`http://127.0.0.1:${server.address().port}/tasks/f08_p/verifications/${f.item.id}/generate`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({expected_revision:0})});
  assert.equal(result.status,200);assert.equal(calls,1);
  const detail=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(detail.plans[0].content.steps.length,1);assert.equal(detail.attempts.length,0);
 }finally{await new Promise(resolve=>server.close(resolve));f.db.close();}
});

test('correction receives the failing output, including wrapped plans, and cannot bypass target checks',async()=>{
 const f=await fixture();let calls=0;
 const {expected_revision,...plan}=f.plan;
 const invalid=JSON.stringify({type:'verification_plan',schema:{...plan,target:'http://outside.invalid'}});
 const app=express();app.use(express.json(),(req,res,next)=>{req.user=actor;next();});
 app.use('/tasks/:id/verifications',routes(f.db,{llm:async(messages)=>{
  calls++;if(calls===2){assert.equal(messages.at(-2).role,'assistant');assert.equal(messages.at(-2).content,invalid);assert.match(messages.at(-1).content,/范围/);}
  return {ok:true,content:calls===1?invalid:JSON.stringify(plan)};
 }}));
 const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try {
  const result=await fetch(`http://127.0.0.1:${server.address().port}/tasks/f08_p/verifications/${f.item.id}/generate`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({expected_revision:0})});
  assert.equal(result.status,200);assert.equal(calls,2);assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).plans[0].content.target,f.plan.target);
 }finally{await new Promise(resolve=>server.close(resolve));f.db.close();}
});

test('Nikto paths resolve through observed same-task HTTP entry without guessing ports or crossing scope',async()=>{
 const f=await fixture();try {
  f.db.prepare("UPDATE pipelines SET target='192.0.2.10' WHERE pipeline_id='f08_p'").run();
  f.db.prepare("UPDATE scan_tasks SET target='192.0.2.10' WHERE scan_task_id='f08_s'").run();
  f.db.prepare("UPDATE scan_results SET result_type='web_vuln',source_tool='nikto',result_data=? WHERE id=?")
    .run(JSON.stringify({finding:'Apache default file found.',path:'/index.html:'}),f.finding);
  f.pipeline=f.db.prepare("SELECT * FROM pipelines WHERE pipeline_id='f08_p'").get();
  const addProbe=(url,scan='f08_s')=>Number(f.db.prepare("INSERT INTO scan_results(scan_task_id,result_type,severity,source_tool,result_data) VALUES(?,'http_probe','info','http',?)").run(scan,JSON.stringify({url,status_code:200})).lastInsertRowid);
  let detail=verificationDetail(f.db,f.pipeline,f.item.id);
  assert.equal(detail.entry_context.source,'unresolved');assert.equal(detail.default_target,'192.0.2.10');
  addProbe('http://other.invalid:8080/');
  const observed=addProbe('http://192.0.2.10:8080/');
  detail=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(detail.default_target,'http://192.0.2.10:8080/index.html');
  assert.equal(detail.entry_context.source_record_id,observed);
  const another=addProbe('https://192.0.2.10:8443/');
  assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).entry_context.source,'unresolved');
  f.db.prepare('DELETE FROM scan_results WHERE id=?').run(another);
  f.db.prepare("UPDATE scan_results SET result_data=? WHERE id=?").run(JSON.stringify({finding:'Directory indexing found.',path:'//outside.invalid/'}),f.finding);
  assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).default_target,null);
  f.pipeline={...f.pipeline,config:JSON.stringify({task_scope:{includes:['http://192.0.2.10:8080/allowed/']}})};
  // A task's own root target must itself remain in its structured includes.
  f.pipeline.target='http://192.0.2.10:8080/allowed/';
  f.db.prepare("UPDATE scan_tasks SET target=? WHERE scan_task_id='f08_s'").run(f.pipeline.target);
  f.db.prepare("UPDATE scan_results SET result_data=? WHERE id=?").run(JSON.stringify({finding:'Directory indexing found.',path:'/outside/'}),f.finding);
  assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).entry_context.source,'out_of_scope');
 }finally{f.db.close();}
});

test('generation refuses to invent an HTTP entry for Nikto and ignores unassociated task observations',async()=>{
 const f=await fixture();let calls=0;
 f.db.prepare("UPDATE pipelines SET target='192.0.2.10' WHERE pipeline_id='f08_p'").run();
 f.db.prepare("UPDATE scan_tasks SET target='192.0.2.10' WHERE scan_task_id='f08_s'").run();
 f.db.prepare("UPDATE scan_results SET result_type='web_vuln',source_tool='nikto',result_data=? WHERE id=?")
   .run(JSON.stringify({finding:'Admin login page/section found.',path:'/admin/'}),f.finding);
 f.db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by) VALUES('other-scan','192.0.2.10','web_scan','COMPLETED','f08_alice')").run();
 f.db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data) VALUES('other-scan','http_probe',?)").run(JSON.stringify({url:'http://192.0.2.10:8080/'}));
 const app=express();app.use(express.json(),(req,res,next)=>{req.user=actor;next();});
 app.use('/tasks/:id/verifications',routes(f.db,{llm:async()=>{calls++;return {ok:true,content:'{}'};}}));
 const server=http.createServer(app);await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 try {
  const response=await fetch(`http://127.0.0.1:${server.address().port}/tasks/f08_p/verifications/${f.item.id}/generate`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({expected_revision:0})});
  assert.equal(response.status,200);const body=await response.json();assert.equal(body.data.state,'needs_conditions');assert.match(body.data.reason,/协议、端口/);
  assert.equal(calls,0);assert.equal(f.db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
 }finally{await new Promise(resolve=>server.close(resolve));f.db.close();}
});

test('schema wrapper handling rejects mixed roots and literal JSON schema instead of finding arbitrary executable content',async()=>{
 const {parseVerificationGeneration}=await import('../src/services/findingVerificationGeneration.js');
 const plan={name:'fixture',steps:[{name:'Check'}]};
 assert.deepEqual(parseVerificationGeneration('```JSON\n'+JSON.stringify({type:'plan',schema:plan})+'\n```'),plan);
 const mixed={steps:[],schema:plan};assert.deepEqual(parseVerificationGeneration(JSON.stringify(mixed)),mixed);
 const schema={type:'object',schema:{type:'object',properties:{steps:{type:'array'}}}};
 assert.deepEqual(parseVerificationGeneration(JSON.stringify(schema)),schema);
 assert.throws(()=>parseVerificationGeneration('[]'),/格式/);
});
