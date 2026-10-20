import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import express from 'express';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {runMigrations} from '../src/db/migrate.js';
import {ensureVerification,verificationDetail,saveVerificationPlan,selectVerificationTemplate,confirmAndStart,changeStepPayload} from '../src/services/findingVerification.js';
import {payloadVersion} from '../src/services/findingPayloads.js';
import {prepareVerificationPayload} from '../src/services/findingVerificationPayloads.js';
import {getPayloadById} from '../src/services/payloadLoader.js';
import {launchVerification} from '../src/services/findingVerificationRunner.js';
import {assessVerificationAttempt} from '../src/services/findingVerificationAssessment.js';
import {evaluateFindingRule,findingRule} from '../src/services/findingVerificationRules.js';
import routes from '../src/routes/findingVerifications.js';
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


async function api(f,dependencies={}) {
 const app=express();app.use(express.json(),(req,res,next)=>{req.user={sub:req.headers['x-user'] || actor.sub,role:'user'};next();});
 app.use('/tasks/:id/verifications',routes(f.db,dependencies));
 app.use((e,req,res,next)=>res.status(e.status||500).json({status:'error',error:{message:e.message}}));
 const server=http.createServer(app);await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const base=`http://127.0.0.1:${server.address().port}/tasks/f08_p/verifications/${f.item.id}`;
 return {close:()=>new Promise(r=>server.close(r)),request:async(path,body,user=actor.sub)=>{
  const res=await fetch(base+path,{method:body?'POST':'GET',headers:{'content-type':'application/json','x-user':user},...(body?{body:JSON.stringify(body)}:{})});
  return {status:res.status,body:await res.json()};
 }};
}
function setFinding(f,finding) {
 f.db.prepare("UPDATE scan_results SET source_tool='nikto',result_type='web_vuln',result_data=? WHERE id=?")
   .run(JSON.stringify({finding,url:f.plan.target}),f.finding);
}
test('template selection, manual payload binding, one confirmation, actual consumption and automatic/manual result form one chain',async()=>{
 const f=await fixture();setFinding(f,'The X-Content-Type-Options header is not set.');
 let modelCalls=0,toolCalls=0;
 const engine={executeRun:async runId=>{
   toolCalls++;const run=f.db.prepare('SELECT * FROM execution_runs WHERE run_id=?').get(runId);
   const linkage=JSON.parse(run.plan_data).finding_verification;
   const step=f.db.prepare('SELECT * FROM playbook_steps WHERE playbook_id=?').get(run.playbook_id);
   const cfg=JSON.parse(step.evidence_config);
   f.db.prepare("INSERT INTO execution_steps(run_id,step_index,tool_id,success) VALUES(?,0,'target-request',1)").run(runId);
   f.db.prepare(`INSERT INTO evidence_records(run_id,step_index,tool_id,evidence_data,raw_stdout) VALUES(?,0,'target-request',?,?)`)
     .run(runId,JSON.stringify({success:true,exit_code:0,payload_id:step.payload_id,finding_verification:{...linkage,tool_started:true,payload_consumed:true}}),
       JSON.stringify({url:run.target,method:'GET',connected:true,complete:true,status_code:200,response_headers:{'content-type':'text/html'},response:'<html>Fixture</html>'}));
   f.db.prepare("UPDATE execution_runs SET status='COMPLETED' WHERE run_id=?").run(runId);
   return {processStopped:true};
 }};
 const client=await api(f,{engine,llm:async()=>{modelCalls++;return {ok:true,content:'{}'};}});
 try {
  const sources=await client.request('/sources');assert.equal(sources.status,200);assert.equal(sources.body.data.items[0].playbook_id,'f08-web-headers-v1');
  assert.equal(toolCalls,0);assert.equal(modelCalls,0);
  const selected=await client.request('/select-template',{playbook_id:'f08-web-headers-v1',expected_revision:0});assert.equal(selected.status,200);
  let detail=(await client.request('')).body.data;assert.equal(detail.plans[0].content.provenance.kind,'builtin');assert.equal(detail.readiness.ready,true);
  const generated={id:'workflow_header',name:'Header observation',tags:['headers'],version:1,consumption:{type:'tool_args',tool_id:'target-request',args_template:[JSON.stringify({url:'<target>',method:'GET'})]}};
  // Match via exact signature, as a real F07 generated payload does.
  const {findingSignature}=await import('../src/services/findingPayload.js');
  generated.applicability={signature:findingSignature(f.db,f.db.prepare('SELECT * FROM scan_results WHERE id=?').get(f.finding))};
  f.db.prepare("INSERT INTO generated_payloads(payload_id,name,payload_type,payload_data,import_status) VALUES(?,?,'web',?,'accepted')").run(generated.id,generated.name,JSON.stringify(generated));
  detail=(await client.request('')).body.data;const candidate=detail.payloads.matches.find(p=>p.payload_id===generated.id);assert.ok(candidate);assert.ok(candidate.preview.some(p=>p.label==='方法'));
  assert.equal(detail.plans[0].content.steps[0].payload_id,null,'candidate must not auto-bind');
  const bind=await client.request('/payloads/bind',{expected_revision:1,step_id:'finding_step_0',payload_id:generated.id,version:candidate.version});assert.equal(bind.status,200);
  detail=(await client.request('')).body.data;assert.equal(detail.revision,2);assert.equal(detail.plans[0].content.provenance.kind,'builtin');assert.equal(detail.plans[0].confirmed_at,null);assert.equal(detail.payloads.events[0].action,'bound');
  assert.equal((await client.request('/start',{revision:1,fingerprint:detail.plans[0].fingerprint,request_id:'old',confirmed:true})).status,409);
  const start={revision:2,fingerprint:detail.plans[0].fingerprint,request_id:'start-workflow',confirmed:true};
  assert.equal((await client.request('/start',start,'f08_bob')).status,403);
  const began=await client.request('/start',start);assert.equal(began.status,200);
  const repeated=await client.request('/start',start);assert.equal(repeated.body.data.id,began.body.data.id);
  for(let i=0;i<60;i++){detail=(await client.request('')).body.data;if(detail.attempts[0]?.state==='completed')break;await new Promise(r=>setTimeout(r,5));}
  assert.equal(toolCalls,1);assert.equal(detail.summary.method,'automatic');assert.equal(detail.summary.conclusion,'confirmed');
  const attempt=detail.attempts[0];assert.equal(attempt.evidence[0].evidence_data.payload_id,generated.id);assert.equal(attempt.assessments.length,1);
  assessVerificationAttempt(f.db,attempt.id);assert.equal(f.db.prepare('SELECT count(*) n FROM finding_verification_assessments').get().n,1);
  assert.equal((await client.request('/reviews',{attempt_id:attempt.id,conclusion:'inconclusive',evidence_ids:[attempt.evidence[0].id],note:'Need application context'})).status,200);
  detail=(await client.request('')).body.data;assert.equal(detail.summary.method,'manual');assert.equal(detail.summary.conclusion,'inconclusive');assert.equal(detail.attempts[0].assessments[0].conclusion,'confirmed');
 }finally{await client.close();f.db.close();}
});

function evidenceFixture(finding,target='https://fixture.invalid/dir/') {
 const row={source_tool:'nikto',result_data:JSON.stringify({finding})};
 const rule={...findingRule(row,target),step_id:'s'};
 const attempt={id:'a',verification_id:'v',revision:1,state:'completed',stop_confirmed:1,fingerprint:'f'};
 const plan={finding_id:3,steps:[{step_index:0,step_id:'s'}]};
 const obs={url:target,method:'GET',connected:true,complete:true,status_code:200,response_headers:{'content-type':'text/html'},response:'<html>ok</html>',cookie_attributes_complete:true};
 const record={id:1,step_index:0,tool_id:'target-request',evidence_data:JSON.stringify({success:true,exit_code:0,finding_verification:{attempt_id:'a',verification_id:'v',finding_id:3,revision:1,fingerprint:'f'}}),raw_stdout:''};
 const judge=(change={},a=attempt)=>evaluateFindingRule(rule,[{...record,raw_stdout:JSON.stringify({...obs,...change})}],a,plan);
 return {rule,attempt,plan,obs,record,judge};
}
test('versioned header rules require complete same-entry HTML, honor alternative controls and never use status alone',()=>{
 const f=evidenceFixture('The X-Frame-Options header is not present.');
 assert.equal(f.judge().conclusion,'confirmed');
 assert.equal(f.judge({response_headers:{'content-type':'text/html','content-security-policy':"default-src 'self'; frame-ancestors 'self'"}}).conclusion,'not_verified');
 assert.equal(f.judge({response_headers:{'content-type':'text/html','x-frame-options':'SAMEORIGIN'}}).conclusion,'not_verified');
 assert.equal(f.judge({response_headers:{'content-type':'text/html','content-security-policy':'frame-ancestors *'}}).conclusion,'inconclusive');
 for(const change of [{complete:false},{truncated:true},{status_code:403},{status_code:302},{url:'https://outside.invalid/'},{response_headers:{'content-type':'application/json'}},{response:'<input type="password">'}])assert.equal(f.judge(change).conclusion,'inconclusive');
 assert.equal(f.judge({}, {...f.attempt,state:'aborted'}).conclusion,'inconclusive');
 const bad={...f.record,evidence_data:JSON.stringify({success:true,exit_code:0,finding_verification:{attempt_id:'other'}}),raw_stdout:JSON.stringify(f.obs)};
 assert.equal(evaluateFindingRule(f.rule,[bad],f.attempt,f.plan).conclusion,'inconclusive');
 const n=evidenceFixture('The X-Content-Type-Options header is not set.');assert.equal(n.judge().conclusion,'confirmed');
 assert.equal(n.judge({response_headers:{'content-type':'text/html','x-content-type-options':'nosniff'}}).conclusion,'not_verified');
});
test('cookie rules inspect only exact names and booleans; secure requires HTTPS',()=>{
 const f=evidenceFixture('Cookie PHPSESSID created without the httponly flag');
 assert.equal(f.judge({cookie_attributes:[{name:'PHPSESSID',httponly:false,secure:true}]}).conclusion,'confirmed');
 assert.equal(f.judge({cookie_attributes:[{name:'PHPSESSID',httponly:true,secure:true}]}).conclusion,'not_verified');
 assert.equal(f.judge({cookie_attributes:[{name:'other',httponly:false}]}).conclusion,'inconclusive');
 assert.equal(f.judge({cookie_attributes:[{name:'PHPSESSID',httponly:false},{name:'PHPSESSID',httponly:true}]}).conclusion,'inconclusive');
 assert.equal(findingRule({source_tool:'nikto',result_data:JSON.stringify({finding:'Cookie PHPSESSID created without the secure flag'})},'http://fixture.invalid/'),null);
});
test('directory rule checks the path-specific title, parent navigation and same-directory children together',()=>{
 const f=evidenceFixture('Directory indexing found.');
 const html='<title>Index of /dir/</title><a href="../">Parent Directory</a><a href="file.txt">file.txt</a>';
 assert.equal(f.judge({response:html}).conclusion,'confirmed');
 for(const response of ['Index of /dir/',html.replace('/dir/','/other/'),html.replace('<a href="../">Parent Directory</a>',''),html.replace('file.txt','https://outside.invalid/file.txt')])assert.equal(f.judge({response}).conclusion,'not_verified');
 assert.equal(f.judge({response:html,complete:false}).conclusion,'inconclusive');
 assert.equal(findingRule({source_tool:'nikto',result_data:JSON.stringify({finding:'Admin login page/section found.'})},'http://fixture.invalid/'),null);
});

test('payload preparation is scoped to the step, records generated/reused events, and never binds automatically',async()=>{
 const f=await fixture();saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,f.plan);let calls=0;
 const generator=async args=>{
  calls++;assert.equal(args.constraints.required_tool_id,'target-request');
  const p={id:'workflow_generated',name:'SQL injection fixture payload',version:1,tags:['sqli'],applicability:{signature:args.findingContext.signature},
    consumption:{type:'tool_args',tool_id:'target-request',args_template:[JSON.stringify({url:'<target>',method:'GET'})]}};
  f.db.prepare("INSERT INTO generated_payloads(payload_id,name,payload_type,payload_data,import_status) VALUES(?,?,'web',?,'accepted')").run(p.id,p.name,JSON.stringify(p));return {ok:true,payload:p};
 };
 const client=await api(f,{generatePayload:generator});
 try {
  const request={expected_revision:1,step_id:'finding_step_0'};
  assert.equal((await client.request('/payloads/prepare',{...request,step_id:'unknown'})).status,400);
  const created=await client.request('/payloads/prepare',request);assert.equal(created.status,200);assert.equal(created.body.data.state,'generated');assert.equal(created.body.data.bound,false);
  let detail=(await client.request('')).body.data;assert.equal(detail.revision,1);assert.equal(detail.plans[0].content.steps[0].payload_id,null);
  assert.equal(detail.payloads.matches.find(m=>m.payload_id==='workflow_generated').created_here,true);
  assert.equal((await client.request('/payloads/prepare',request)).body.data.state,'existing');assert.equal(calls,1);
  assert.deepEqual((await client.request('')).body.data.payloads.events.map(e=>e.action),['generated','reused']);
  assert.equal((await client.request('/payloads/bind',{expected_revision:1,step_id:'finding_step_0',payload_id:'workflow_generated',version:'old'})).status,409);
  const current=getPayloadById('workflow_generated',f.db);const version=payloadVersion(current);
  assert.equal((await client.request('/payloads/bind',{expected_revision:1,step_id:'finding_step_0',payload_id:current.id,version})).status,200);
  assert.equal((await client.request('/payloads/unbind',{expected_revision:2,step_id:'finding_step_0'})).status,200);
  detail=(await client.request('')).body.data;assert.equal(detail.revision,3);assert.equal(detail.plans[0].content.steps[0].consumption,'pending');assert.equal(detail.readiness.ready,false);
  // A new finding reuses the stored input, but must not inherit the original
  // verification's "generated here" badge or manual step association.
  const otherFinding=Number(f.db.prepare(`INSERT INTO scan_results(scan_task_id,result_type,severity,result_data)
    SELECT scan_task_id,result_type,severity,result_data FROM scan_results WHERE id=?`).run(f.finding).lastInsertRowid);
  const other=ensureVerification(f.db,f.pipeline,otherFinding);
  saveVerificationPlan(f.db,f.pipeline,actor,other.id,f.plan);
  const before=verificationDetail(f.db,f.pipeline,other.id);
  const reused=await prepareVerificationPayload(f.db,f.pipeline,actor,before,
    f.db.prepare('SELECT * FROM scan_results WHERE id=?').get(otherFinding),before.plans[0].content,
    {step_id:'finding_step_0'},{generatePayload:generator});
  assert.equal(reused.state,'existing');assert.equal(calls,1,'reuse does not call the model again');
  const after=verificationDetail(f.db,f.pipeline,other.id);
  const reusedMatch=after.payloads.matches.find(m=>m.payload_id==='workflow_generated');
  assert.equal(reusedMatch.created_here,false);assert.equal(reusedMatch.provenance,'ai');
  assert.equal(after.plans[0].content.steps[0].payload_id,null,'reuse still requires explicit binding');
 }finally{await client.close();f.db.close();}
});

test('actual built-in transport stores only cookie names and flags and the real engine evaluates the frozen rule',async()=>{
 const {getDb,closeDb}=await import('../src/db/connection.js');
 const server=http.createServer((req,res)=>{res.writeHead(200,{'content-type':'text/html','set-cookie':'PHPSESSID=NEVER_PERSIST_COOKIE_VALUE; Path=/; Secure'});res.end('<html>fixture page</html>');});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));const f=await fixture(getDb(':memory:'));
 try {
  const url=`http://127.0.0.1:${server.address().port}/`;
  f.db.prepare("UPDATE pipelines SET target=? WHERE pipeline_id='f08_p'").run(url);f.db.prepare("UPDATE scan_tasks SET target=? WHERE scan_task_id='f08_s'").run(url);
  f.pipeline=f.db.prepare("SELECT * FROM pipelines WHERE pipeline_id='f08_p'").get();f.plan.target=url;setFinding(f,'Cookie PHPSESSID created without the httponly flag');
  selectVerificationTemplate(f.db,f.pipeline,actor,f.item.id,{playbook_id:'f08-cookie-flags-v1',expected_revision:0});
  let detail=verificationDetail(f.db,f.pipeline,f.item.id);
  const a=confirmAndStart(f.db,f.pipeline,actor,f.item.id,{revision:1,fingerprint:detail.plans[0].fingerprint,request_id:'cookie-real',confirmed:true});
  await launchVerification(f.db,a,actor);
  detail=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(detail.summary.conclusion,'confirmed');assert.equal(detail.summary.method,'automatic');
  const stored=f.db.prepare('SELECT * FROM evidence_records WHERE run_id=?').all(a.run_id);assert.equal(JSON.stringify(stored).includes('NEVER_PERSIST_COOKIE_VALUE'),false);
  const obs=JSON.parse(stored[0].raw_stdout);assert.deepEqual(obs.cookie_attributes,[{name:'PHPSESSID',httponly:false,secure:true}]);
  assert.deepEqual(detail.attempts[0].evidence[0].evidence_data.cookie_attributes || JSON.parse(detail.attempts[0].evidence[0].raw_stdout).cookie_attributes,[{name:'PHPSESSID',httponly:false,secure:true}]);
 }finally{closeDb();await new Promise(r=>server.close(r));}
});

test('AI provenance is server-owned; edits keep parent lineage; rules never attach to another entry',async()=>{
 const f=await fixture();setFinding(f,'The X-Content-Type-Options header is not set.');
 const client=await api(f,{llm:async()=>({ok:true,content:JSON.stringify({...f.plan,provenance:{kind:'builtin'},assessment_rule:{id:'forged'}})})});
 try {
  assert.equal((await client.request('/generate',{expected_revision:0})).status,200);
  let d=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(d.plans[0].content.provenance.kind,'ai_generated');
  assert.equal(d.plans[0].content.assessment_rule,undefined,'finding URL is /item but plan targets root; no automatic conclusion');
  assert.equal((await client.request('/generate',{expected_revision:1,mode:'adjust'})).status,200);
  d=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(d.plans[0].content.provenance.kind,'ai_adjusted');assert.equal(d.plans[0].content.provenance.parent_revision,1);
 }finally{await client.close();f.db.close();}
});

test('source browse, draft prerequisites and provenance respect visibility, single-finding matching and legacy input',async()=>{
 const f=await fixture();let modelCalls=0;const client=await api(f,{llm:async()=>{modelCalls++;return {ok:true,content:'{}'};}});
 try {
  f.db.prepare("INSERT INTO playbooks(playbook_id,name,description,target_type,author,metadata) VALUES('manual','Owned SQL plan','fixture','[\"web_url\"]','tester','{}')").run();
  f.db.prepare("INSERT INTO playbook_steps(playbook_id,step_index,step_id,name,tool_id,args_template,description) VALUES('manual',0,'m','Manual check','target-request',?,'fixture')").run(JSON.stringify([JSON.stringify({url:f.plan.target,method:'GET'})]));
  const page=await client.request('/sources?mode=all&q=Owned&limit=1');assert.equal(page.body.data.items.length,1);assert.equal(page.body.data.items[0].source.kind,'manual_template');
  assert.ok(page.body.data.items[0].missing_conditions.length);
  assert.equal((await client.request('/select-template',{expected_revision:0,playbook_id:'manual'})).status,200);
  const d=(await client.request('')).body.data;assert.equal(d.readiness.ready,false);assert.equal(d.plans[0].content.success_criteria,'');
  assert.equal((await client.request('/start',{revision:1,fingerprint:d.plans[0].fingerprint,request_id:'missing',confirmed:true})).status,409);
  assert.equal(modelCalls,0);
  const draft=d.plans[0].content;
  saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,{...draft,expected_revision:1,success_criteria:'Specific observed effect',cleanup:'No cleanup',steps:draft.steps.map(s=>({...s,args_template:JSON.parse(s.args_template),expected_evidence:'Observed response'}))});
  assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).plans[0].content.provenance.kind,'template_adjusted');
  assert.equal((await client.request('/sources?mode=all&offset=-1')).status,400);
  assert.equal((await client.request('/sources',undefined,'f08_bob')).status,403);
 }finally{await client.close();f.db.close();}
});

test('additive workflow migration preserves old plans and reruns without rewriting source data',async()=>{
 const f=await fixture();try {
  const {default:up}=await import('../src/db/migrations/034_finding_workflow.js');
  saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,f.plan);
  const original=f.db.prepare('SELECT * FROM finding_verification_plans').get();
  // Simulate a pre-upgrade version snapshot which never recorded provenance.
  const old=JSON.parse(original.content);delete old.provenance;delete old.assessment_rule;delete old.blockers;
  f.db.prepare('UPDATE finding_verification_plans SET content=?').run(JSON.stringify(old));
  up(f.db);up(f.db);
  const d=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(d.plans[0].content.provenance.kind,'legacy');
  assert.equal(f.db.prepare("SELECT count(*) n FROM playbooks WHERE playbook_id LIKE 'f08-%-v1'").get().n,3);
  assert.equal(f.db.prepare('SELECT content FROM finding_verification_plans').get().content,JSON.stringify(old));
  assert.deepEqual(f.db.pragma('foreign_key_check'),[]);
 }finally{f.db.close();}
});

test('payloads unavailable after plan confirmation block start and all binding changes require explicit current step',async()=>{
 const f=await fixture();saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,f.plan);
 const {findingSignature}=await import('../src/services/findingPayload.js');
 const payload={id:'revoke_test',name:'SQL injection',version:1,tags:['sqli'],applicability:{signature:findingSignature(f.db,f.db.prepare('SELECT * FROM scan_results WHERE id=?').get(f.finding))},consumption:{type:'tool_args',tool_id:'target-request',args_template:[JSON.stringify({url:'<target>',method:'GET'})]}};
 f.db.prepare("INSERT INTO generated_payloads(payload_id,name,payload_type,payload_data,import_status) VALUES(?,?,'web',?,'accepted')").run(payload.id,payload.name,JSON.stringify(payload));
 const version=payloadVersion(getPayloadById(payload.id,f.db));const client=await api(f);
 try {
  assert.equal((await client.request('/payloads/'+payload.id)).status,200);assert.equal((await client.request('/payloads/unknown')).status,404);
  assert.equal((await client.request('/payloads/bind',{expected_revision:1,step_id:'wrong',payload_id:payload.id,version})).status,400);
  changeStepPayload(f.db,f.pipeline,actor,f.item.id,{expected_revision:1,step_id:'finding_step_0',payload_id:payload.id,version});
  const d=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(d.revision,2);
  f.db.prepare("UPDATE generated_payloads SET import_status='rejected' WHERE payload_id=?").run(payload.id);
  assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).readiness.ready,false);
  const start=await client.request('/start',{revision:2,fingerprint:d.plans[0].fingerprint,request_id:'revoked',confirmed:true});assert.equal(start.status,400);
  assert.equal(f.db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
 }finally{await client.close();f.db.close();}
});

test('generated payload prepared for an incompatible tool is rejected without association or binding events',async()=>{
 const f=await fixture();saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,f.plan);
 const client=await api(f,{generatePayload:async args=>{
  const p={id:'wrong-tool',name:'SQL injection incompatible',version:1,tags:['sqli'],applicability:{signature:args.findingContext.signature},consumption:{type:'tool_args',tool_id:'nmap',args_template:['-sV','<target>']}};
  f.db.prepare("INSERT INTO generated_payloads(payload_id,name,payload_type,payload_data,import_status) VALUES(?,?,'web',?,'accepted')").run(p.id,p.name,JSON.stringify(p));return {ok:true,payload:p};
 }});
 try {
  assert.equal((await client.request('/payloads/prepare',{expected_revision:1,step_id:'finding_step_0'})).status,422);
  const d=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(d.payloads.events.length,0);assert.equal(d.plans[0].content.steps[0].payload_id,null);
  assert.equal(f.db.prepare('SELECT count(*) n FROM finding_payload_links').get().n,0);
 }finally{await client.close();f.db.close();}
});

test('AI proposals cannot silently bind a suggested payload; binding remains an explicit user operation',async()=>{
 const f=await fixture();const client=await api(f,{llm:async()=>({ok:true,content:JSON.stringify({...f.plan,steps:[{...f.plan.steps[0],consumption:'independent',payload_id:'guessed',payload_version:'guessed-version'}]})})});
 try {
  const response=await client.request('/generate',{expected_revision:0});assert.equal(response.status,200);
  const d=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(d.plans[0].content.steps[0].consumption,'pending');assert.equal(d.plans[0].content.steps[0].payload_id,null);
  assert.equal(d.readiness.ready,false);assert.equal(d.payloads.events.length,0);
 }finally{await client.close();f.db.close();}
});

test('a legacy static payload remains a reference rather than an implicit independent binding',async()=>{
 const f=await fixture();try {
  f.db.prepare("INSERT INTO playbooks(playbook_id,name,target_type,metadata) VALUES('ref-template','SQL check','[\"web_url\"]',?)")
    .run(JSON.stringify({verification:{success_criteria:'Review actual SQL evidence',cleanup:'Read only'}}));
  f.db.prepare("INSERT INTO playbook_steps(playbook_id,step_index,step_id,name,tool_id,args_template,payload_id,evidence_config) VALUES('ref-template',0,'check','Specific check','target-request',?,'sqli-mysql-basic',?)")
    .run(JSON.stringify([JSON.stringify({url:f.plan.target,method:'GET'})]),JSON.stringify({expected_evidence:'Observe response'}));
  selectVerificationTemplate(f.db,f.pipeline,actor,f.item.id,{playbook_id:'ref-template',expected_revision:0});
  const step=verificationDetail(f.db,f.pipeline,f.item.id).plans[0].content.steps[0];
  assert.equal(step.consumption,'none');assert.equal(step.payload_id,null);assert.equal(step.reference_payload_id,'sqli-mysql-basic');
 }finally{f.db.close();}
});

test('unbinding a payload with no original request leaves a blocked draft instead of executing fallback input',async()=>{
 const f=await fixture();try {
  const {findingSignature}=await import('../src/services/findingPayload.js');
  const payload={id:'no-fallback',name:'SQL injection fixture',version:1,tags:['sqli'],applicability:{signature:findingSignature(f.db,f.db.prepare('SELECT * FROM scan_results WHERE id=?').get(f.finding))},consumption:{type:'tool_args',tool_id:'target-request',args_template:[JSON.stringify({url:'<target>',method:'GET'})]}};
  f.db.prepare("INSERT INTO generated_payloads(payload_id,name,payload_type,payload_data,import_status) VALUES(?,?,'web',?,'accepted')").run(payload.id,payload.name,JSON.stringify(payload));
  const version=payloadVersion(getPayloadById(payload.id,f.db));
  saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,{...f.plan,steps:[{...f.plan.steps[0],args_template:[],consumption:'independent',payload_id:payload.id,payload_version:version}]});
  changeStepPayload(f.db,f.pipeline,actor,f.item.id,{expected_revision:1,step_id:'finding_step_0'},true);
  const d=verificationDetail(f.db,f.pipeline,f.item.id);assert.equal(d.revision,2);assert.equal(d.readiness.ready,false);assert.equal(d.plans[0].content.steps[0].payload_id,null);
  assert.throws(()=>confirmAndStart(f.db,f.pipeline,actor,f.item.id,{revision:2,fingerprint:d.plans[0].fingerprint,request_id:'blocked',confirmed:true}),e=>e.status===409);
  assert.equal(f.db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
 }finally{f.db.close();}
});


test('cookie assessment rejects incomplete, malformed and legacy unqualified observations',()=>{
 const f=evidenceFixture('Cookie PHPSESSID created without the httponly flag');
 for(const change of [{cookie_attributes_complete:false},{cookie_attributes_complete:undefined},{cookie_attributes:{}},{cookie_attributes:[null]}])
  assert.equal(f.judge({cookie_attributes:[{name:'PHPSESSID',httponly:false}],...change}).conclusion,'inconclusive');
 for(const raw_stdout of ['null','[]','false'])assert.equal(evaluateFindingRule(f.rule,[{...f.record,raw_stdout}],f.attempt,f.plan).conclusion,'inconclusive');
});

test('transport marks capped cookie observations incomplete and does not expose values',async()=>{
 const {runTargetRequest}=await import('../src/tools/targetRequest.js');
 const server=http.createServer((req,res)=>{res.writeHead(200,{'content-type':'text/html','set-cookie':[
  'PHPSESSID=DO_NOT_STORE; Path=/',...Array.from({length:19},(_,i)=>`fixture${i}=DO_NOT_STORE; HttpOnly`),'PHPSESSID=DO_NOT_STORE; HttpOnly'
 ]});res.end('<html>fixture</html>');});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));
 try {
  const target=`http://127.0.0.1:${server.address().port}/`;
  const result=await runTargetRequest([JSON.stringify({url:target,method:'GET'})],{target});
  assert.equal(result.success,true);assert.equal(result.stdout.includes('DO_NOT_STORE'),false);
  const obs=JSON.parse(result.stdout);assert.equal(obs.cookie_attributes.length,20);assert.equal(obs.cookie_attributes_complete,false);
  const f=evidenceFixture('Cookie PHPSESSID created without the httponly flag',target);
  assert.equal(f.judge(obs).conclusion,'inconclusive');
 }finally{await new Promise(r=>server.close(r));}
});

test('AI adjustment retains only unchanged manually bound inputs and never silently changes their variables',async()=>{
 const f=await fixture();saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,f.plan);
 const {findingSignature}=await import('../src/services/findingPayload.js');
 const payload={id:'adjust-bound',name:'SQL injection fixture',version:1,tags:['sqli'],applicability:{signature:findingSignature(f.db,f.db.prepare('SELECT * FROM scan_results WHERE id=?').get(f.finding))},consumption:{type:'tool_args',tool_id:'target-request',args_template:[JSON.stringify({url:'<target>',method:'GET'})]}};
 f.db.prepare("INSERT INTO generated_payloads(payload_id,name,payload_type,payload_data,import_status) VALUES(?,?,'web',?,'accepted')").run(payload.id,payload.name,JSON.stringify(payload));
 changeStepPayload(f.db,f.pipeline,actor,f.item.id,{expected_revision:1,step_id:'finding_step_0',payload_id:payload.id,version:payloadVersion(getPayloadById(payload.id,f.db))});
 let proposal;const client=await api(f,{llm:async()=>({ok:true,content:JSON.stringify(proposal)})});
 try {
  const current=verificationDetail(f.db,f.pipeline,f.item.id).plans[0].content;
  proposal={...current,steps:current.steps.map(s=>({...s,args_template:JSON.parse(s.args_template)}))};
  assert.equal((await client.request('/generate',{expected_revision:2,mode:'adjust'})).status,200);
  assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).plans[0].content.steps[0].payload_id,payload.id);
  proposal.steps[0].payload_variables={input:'changed'};
  assert.equal((await client.request('/generate',{expected_revision:3,mode:'adjust'})).status,200);
  const d=verificationDetail(f.db,f.pipeline,f.item.id);
  assert.equal(d.plans[0].content.steps[0].consumption,'pending');assert.equal(d.plans[0].content.steps[0].payload_id,null);
  assert.equal(d.readiness.ready,false);assert.equal(d.payloads.events.filter(e=>e.action==='bound').length,1);
  assert.equal(f.db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
 }finally{await client.close();f.db.close();}
});

test('long login-page evidence retains structured facts after redaction without exposing response content',async()=>{
 const f=await fixture();
 try {
  saveVerificationPlan(f.db,f.pipeline,actor,f.item.id,f.plan);
  const detail=verificationDetail(f.db,f.pipeline,f.item.id);
  const a=confirmAndStart(f.db,f.pipeline,actor,f.item.id,{revision:1,fingerprint:detail.plans[0].fingerprint,request_id:'public-observation',confirmed:true});
  const obs={url:'http://fixture.invalid/login.php',method:'GET',status_code:200,connected:true,complete:true,received_bytes:12000,
    response_headers:{'content-type':'text/html','set-cookie':'SENSITIVE_COOKIE=secret'},cookie_attributes_complete:true,
    cookie_attributes:[{name:'fixture',httponly:true,secure:false,value:'SENSITIVE_COOKIE_VALUE'}],
    response:'<form><input type="password" value="SENSITIVE_FORM_VALUE"></form>'+('x'.repeat(12000)),private_field:'SENSITIVE_UNKNOWN'};
  const data=JSON.stringify(obs);
  f.db.prepare("INSERT INTO evidence_records(run_id,step_index,tool_id,evidence_type,evidence_data,raw_stdout) VALUES(?,0,'target-request','unknown','{}',?)").run(a.run_id,data);
  const shown=verificationDetail(f.db,f.pipeline,f.item.id).attempts[0].evidence[0];
  assert.equal(shown.observation.status_code,200);assert.equal(shown.observation.login_form_present,true);
  assert.equal(shown.observation.complete,true);assert.equal(shown.observation.cookie_attributes_complete,true);
  assert.equal(shown.observation.received_bytes,12000);assert.deepEqual(JSON.parse(shown.raw_stdout),shown.observation);
  assert.equal(JSON.stringify(shown).includes('SENSITIVE_'),false);assert.equal(shown.observation.response,undefined);
  assert.equal(f.db.prepare('SELECT raw_stdout FROM evidence_records WHERE run_id=?').get(a.run_id).raw_stdout,data);
  f.db.prepare("UPDATE evidence_records SET raw_stdout='broken' WHERE run_id=?").run(a.run_id);
  assert.equal(verificationDetail(f.db,f.pipeline,f.item.id).attempts[0].evidence[0].observation,null);
 }finally{f.db.close();}
});
