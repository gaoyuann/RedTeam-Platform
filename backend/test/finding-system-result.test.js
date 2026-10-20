import {findingVerificationExecution} from '../src/services/findingVerificationExecution.js';
import {taskExecutionSnapshot} from '../src/services/taskExecution.js';
import {taskSummary} from '../src/services/taskActivity.js';
import {directoryEvidenceCriteria} from '../src/services/findingVerificationRules.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {runMigrations} from '../src/db/migrate.js';
import {buildVerificationContract,projectVerificationResult} from '../src/services/findingVerificationResult.js';
import {attemptVerificationSummary} from '../src/services/findingVerificationSummary.js';
import {saveVerificationPlan,verificationDetail,confirmAndStart} from '../src/services/findingVerification.js';
import {launchVerification,cancelVerification} from '../src/services/findingVerificationRunner.js';
const hash=p=>createHash('sha256').update(JSON.stringify(p)).digest('hex');
async function setup({contract=true,rule=true}={}) {
 const db=new Database(':memory:');await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
 db.exec("INSERT INTO users(username,password,role) VALUES('fixture-user','fixture','user')");
 db.exec("INSERT INTO pipelines(pipeline_id,target,created_by,status) VALUES('system-p','http://fixture.invalid/','fixture-user','completed')");
 db.exec("INSERT INTO scan_tasks(scan_task_id,pipeline_id,target,scan_type,created_by) VALUES('system-s','system-p','http://fixture.invalid/','web_scan','fixture-user'); INSERT INTO scan_results(id,scan_task_id,result_type) VALUES(1,'system-s','web_vuln'); INSERT INTO finding_verifications(id,pipeline_id,finding_id,scan_task_id,revision,state) VALUES('system-v','system-p',1,'system-s',1,'completed')");
 const target='http://fixture.invalid/login.php';
 const plan={target,steps:[{step_id:'observe',step_index:0,name:'Read page',tool_id:'target-request',consumption:'none',args_template:JSON.stringify([JSON.stringify({url:target,method:'GET'})])}]};
 if(rule)plan.assessment_rule={id:'f08-web-headers-v1',version:1,kind:'headers',attribute:'nosniff',target,step_id:'observe',limitations:'只确认响应头配置'};
 if(contract)plan.verification_contract=buildVerificationContract(plan,1);
 const fingerprint=hash(plan),link={verification_id:'system-v',pipeline_id:'system-p',finding_id:1,attempt_id:'system-a',revision:1,fingerprint,tool_started:true};
 db.prepare('INSERT INTO finding_verification_plans(verification_id,revision,content,fingerprint) VALUES(?,1,?,?)').run('system-v',JSON.stringify(plan),fingerprint);
 db.prepare("INSERT INTO execution_runs(run_id,target,user_sub,status,plan_data) VALUES('system-r',?,'fixture-user','COMPLETED',?)").run(target,JSON.stringify({finding_verification:link}));
 db.exec("INSERT INTO finding_verification_attempts(id,verification_id,pipeline_id,revision,run_id,request_id,state,stop_confirmed) VALUES('system-a','system-v','system-p',1,'system-r','system-request','completed',1)");
 const call=Number(db.prepare("INSERT INTO execution_attempts(run_id,step_index,tool_id) VALUES('system-r',0,'target-request')").run().lastInsertRowid);
 db.exec("INSERT INTO execution_steps(run_id,step_index,tool_id,success,exit_code) VALUES('system-r',0,'target-request',1,0)");
 const obs={url:target,method:'GET',status_code:200,connected:true,complete:true,response_headers:{'content-type':'text/html'},response:'<html>fixture</html>'};
 const data={success:true,exit_code:0,finding_verification:link};
 db.prepare("INSERT INTO evidence_records(id,run_id,step_index,tool_id,evidence_data,raw_stdout) VALUES(991,'system-r',0,'target-request',?,?)").run(JSON.stringify(data),JSON.stringify(obs));
 db.prepare('UPDATE evidence_records SET target=?,attempt_id=? WHERE id=991').run(target,call);
 if(rule)db.exec("INSERT INTO finding_verification_assessments(attempt_id,rule_id,rule_version,conclusion,evidence_ids,reason,limitations) VALUES('system-a','f08-web-headers-v1',1,'confirmed','[991]','缺少防护响应头','仅此入口')");
 const summary=()=>attemptVerificationSummary(db,db.prepare("SELECT * FROM finding_verifications WHERE id='system-v'").get(),db.prepare("SELECT * FROM finding_verification_attempts WHERE id='system-a'").get());
 const updateObs=value=>db.prepare('UPDATE evidence_records SET raw_stdout=? WHERE id=991').run(JSON.stringify(value));
 const updateData=value=>db.prepare('UPDATE evidence_records SET evidence_data=? WHERE id=991').run(JSON.stringify(value));
 const opinion=conclusion=>db.prepare("INSERT INTO finding_verification_reviews(attempt_id,conclusion,evidence_ids,note,reviewed_by) VALUES('system-a',?,'[991]','true','fixture-user')").run(conclusion);
 return {db,plan,link,obs,data,summary,updateObs,updateData,opinion};
}
function planInput(f,extra={}) {
 return {...f.plan,name:'Fixture objective',prerequisites:[],missing_conditions:[],success_criteria:'Compare fixture observations',
  cleanup:'No target changes',expected_revision:1,max_attempts:3,duration_ms:1000,
  steps:f.plan.steps.map(s=>({...s,description:s.name,expected_evidence:'Fixture response',args_template:JSON.parse(s.args_template)})),...extra};
}
test('system result requires a versioned objective and linked complete evidence; opinions never change it',async()=>{
 const f=await setup();try{
  const before=f.summary().result;assert.equal(before.status,'achieved');assert.equal(before.objective.category,'configuration_exposure');
  f.opinion('false_positive');assert.deepEqual(f.summary().result,before);assert.equal(f.summary().method,'automatic');assert.equal(f.summary().human_opinions.length,1);
  for(const value of [{...f.obs,status_code:200,complete:false},{...f.obs,truncated:true},{...f.obs,status_code:302},{...f.obs,response:'<input type="password">'},{...f.obs,url:'http://other.invalid/'}]) {
   f.updateObs(value);assert.equal(f.summary().result.status,'inconclusive');
  }
  f.updateObs(f.obs);
  for(const key of ['attempt_id','verification_id','pipeline_id','finding_id','fingerprint','revision']) {
   f.updateData({...f.data,finding_verification:{...f.link,[key]:'wrong'}});assert.equal(f.summary().result.status,'inconclusive');
  }
  f.updateData(f.data);
  f.db.exec("UPDATE finding_verification_assessments SET conclusion='not_verified'");
  f.updateObs({...f.obs,response_headers:{'content-type':'text/html','x-content-type-options':'nosniff'}});
  assert.equal(f.summary().result.status,'not_achieved');f.opinion('confirmed');assert.equal(f.summary().result.status,'not_achieved');
  f.db.exec("UPDATE finding_verification_attempts SET state='failed'");assert.equal(f.summary().result.status,'inconclusive');
  f.db.exec("UPDATE finding_verification_attempts SET state='unknown',stop_confirmed=0");assert.equal(f.summary().result.reason_code,'stop_unconfirmed');
  f.db.exec("UPDATE finding_verification_attempts SET state='queued'");assert.equal(f.summary().result.status,'pending');
  f.db.exec("UPDATE finding_verification_attempts SET state='failed',stop_confirmed=1; UPDATE execution_runs SET preflight_status='FAILED'");
  f.updateData({...f.data,finding_verification:{...f.link,tool_started:false}});assert.equal(f.summary().result.status,'not_performed');
 }finally{f.db.close();}
});
test('legacy 200/404 accessibility checks and true opinion never become successful effect verification',async()=>{
 const f=await setup({contract:false,rule:false});try{
  const second={...f.obs,url:'http://fixture.invalid/missing.php',status_code:404};
  // Existing single entry is enough to classify the bounded read operation, never to infer another effect.
  f.opinion('confirmed');assert.equal(f.summary().result.status,'not_performed');assert.equal(f.summary().result.reason_code,'legacy_accessibility_only');
  assert.equal(f.summary().legacy_summary.conclusion,'confirmed');assert.equal(f.summary().human_opinions[0].note,'true');
  const old=f.db.prepare('SELECT * FROM finding_verification_plans').all();const changes=f.db.prepare('SELECT total_changes() n').get().n;
  f.summary();assert.equal(f.db.prepare('SELECT total_changes() n').get().n,changes);assert.deepEqual(f.db.prepare('SELECT * FROM finding_verification_plans').all(),old);
  f.updateObs(second);assert.notEqual(f.summary().result.status,'achieved');
 }finally{f.db.close();}
 const legacy=await setup({contract:false});try{assert.equal(legacy.summary().result.status,'inconclusive');assert.equal(legacy.summary().result.reason_code,'missing_contract');}finally{legacy.db.close();}
});
test('malformed historical plan shapes remain readable and never repair snapshots or infer success',async()=>{
 const f=await setup();try {
  const pipeline=f.db.prepare("SELECT * FROM pipelines WHERE pipeline_id='system-p'").get();
  f.opinion('confirmed');
  for(const content of ['{','null','[]','true','42','"legacy"','{}','{"steps":[null]}',
    JSON.stringify({...f.plan,steps:'invalid'}),JSON.stringify({...f.plan,steps:[{...f.plan.steps[0],args_template:'null'}]}),
    JSON.stringify({...f.plan,steps:[{...f.plan.steps[0],payload_variables:'null'}]}),
    JSON.stringify({...f.plan,missing_conditions:{unexpected:true}})]) {
   f.db.prepare('UPDATE finding_verification_plans SET content=?').run(content);
   const before=f.db.prepare('SELECT total_changes() n').get().n;
   const detail=verificationDetail(f.db,pipeline,'system-v');
   assert.equal(detail.readiness.ready,false,content);
   assert.match(detail.readiness.reasons.join('; '),/历史方案结构无效/,content);
   assert.notEqual(detail.summary.result.status,'achieved',content);
   assert.notEqual(detail.attempts[0].summary.result.status,'achieved',content);
   assert.equal(detail.attempts[0].human_opinions[0].note,'true',content);
   assert.deepEqual(detail.plans[0].content.steps,[],content);
   assert.equal(f.db.prepare('SELECT total_changes() n').get().n,before,content);
   assert.equal(f.db.prepare('SELECT content FROM finding_verification_plans').get().content,content);
  }
 }finally{f.db.close();}
});
test('missing assessment, unknown rule and forged contract remain inconclusive',async()=>{
 const f=await setup();try{
  f.db.exec('DELETE FROM finding_verification_assessments');assert.equal(f.summary().result.reason_code,'assessment_missing');
  f.opinion('confirmed');assert.equal(f.summary().result.status,'inconclusive');
  const plan={...f.plan,verification_contract:{...f.plan.verification_contract,capability:{automatic:true,reason:'user-forged'}}};
  f.db.prepare('UPDATE finding_verification_plans SET content=?,fingerprint=?').run(JSON.stringify(plan),hash(plan));
  f.db.prepare('UPDATE execution_runs SET plan_data=?').run(JSON.stringify({finding_verification:{...f.link,fingerprint:hash(plan)}}));
  assert.equal(f.summary().result.reason_code,'invalid_contract');
 }finally{f.db.close();}
});


test('bound payload version and actual consumption are part of the effect evidence contract',async()=>{
 const f=await setup();try {
  f.plan.steps[0]={...f.plan.steps[0],consumption:'independent',payload_id:'fixture-payload',payload_version:'version-1'};
  f.plan.verification_contract=buildVerificationContract(f.plan,1);
  const fingerprint=hash(f.plan),link={...f.link,fingerprint,payload_version:'version-1',payload_consumed:true};
  f.db.prepare('UPDATE finding_verification_plans SET content=?,fingerprint=?').run(JSON.stringify(f.plan),fingerprint);
  f.db.prepare('UPDATE execution_runs SET plan_data=?').run(JSON.stringify({finding_verification:link}));
  const data={...f.data,payload_id:'fixture-payload',finding_verification:link};f.updateData(data);
  assert.equal(f.summary().result.status,'achieved');
  for(const fields of [{payload_version:'old'},{payload_consumed:false},{tool_started:false}]) {
   f.updateData({...data,finding_verification:{...link,...fields}});assert.equal(f.summary().result.status,fields.tool_started===false?'not_performed':'inconclusive');
  }
 }finally{f.db.close();}
});

test('only explicit plain page reads are classified as accessibility, never internal or parameterized operations',()=>{
 const step={step_id:'read',step_index:0,name:'Read',tool_id:'target-request',consumption:'none',args_template:JSON.stringify([JSON.stringify({url:'http://fixture.invalid/page',method:'GET'})])};
 const contract=(change={},spec)=>buildVerificationContract({target:'http://fixture.invalid/page',steps:[{...step,...change,...(spec?{args_template:JSON.stringify([JSON.stringify(spec)])}:{})}]},1);
 assert.equal(contract().objective.category,'accessibility');
 assert.equal(contract({consumption:undefined},{url:'<target>',method:'HEAD',timeout_ms:1000}).objective.category,'accessibility');
 for(const change of [{consumption:'internal'},{consumption:'pending'},{payload_id:'fixture'},{reference_payload_id:'reference'},
   {payload_snapshot:{}},{payload_variables:{entry:'http://fixture.invalid/page'}},
   {args_template:JSON.stringify([JSON.stringify({url:'http://fixture.invalid/page'}),'another argument'])}])
  assert.equal(contract(change).objective.category,'effect',JSON.stringify(change));
 for(const spec of [{url:'http://fixture.invalid/page?q=fixture'},{url:'http://fixture.invalid/page?'},{url:'http://fixture.invalid/page#'},
   {url:'http://fixture.invalid/page',headers:{}},{url:'http://fixture.invalid/page',body:''},{url:'http://fixture.invalid/page',exchanges:[]},
   {url:'{{entry}}'},{url:'http://fixture.invalid/page',method:'POST'},{url:'http://name@fixture.invalid/page'}])
  assert.equal(contract({},spec).objective.category,'effect',JSON.stringify(spec));
});

test('objective drafts are frozen and fingerprinted, while automatic capability remains service controlled',async()=>{
 const f=await setup({rule:false});try {
  const pipeline=f.db.prepare("SELECT * FROM pipelines WHERE pipeline_id='system-p'").get();
  const actor={sub:'fixture-user',role:'user'};
  const input=planInput(f,{objective_draft:{label:'核对本次授权入口的指定效果',category:'effect'}});
  saveVerificationPlan(f.db,pipeline,actor,'system-v',input);
  let detail=verificationDetail(f.db,pipeline,'system-v'),record=detail.plans[0];
  assert.deepEqual(record.content.objective_draft,input.objective_draft);
  assert.equal(record.content.verification_contract.objective.label,input.objective_draft.label);
  assert.equal(record.content.verification_contract.objective.category,'effect');
  assert.equal(record.content.verification_contract.capability.automatic,false);
  assert.equal(record.content.verification_contract.criterion,null);
  const originalId=record.content.verification_contract.objective.id;
  assert.equal(buildVerificationContract(record.content,1).objective.id,originalId);
  const oldFingerprint=record.fingerprint;
  saveVerificationPlan(f.db,pipeline,actor,'system-v',{...input,expected_revision:2,objective_draft:{label:'调整后的具体目标',category:'configuration_exposure'}});
  detail=verificationDetail(f.db,pipeline,'system-v');record=detail.plans[0];
  assert.notEqual(record.fingerprint,oldFingerprint);assert.notEqual(record.content.verification_contract.objective.id,originalId);
  assert.equal(detail.plans[1].content.objective_draft.label,input.objective_draft.label);
  assert.throws(()=>confirmAndStart(f.db,pipeline,actor,'system-v',{revision:2,fingerprint:oldFingerprint,request_id:'stale-objective',confirmed:true}),{status:409});
  for(const draft of [null,{},[],{label:'',category:'effect'},{label:'x'.repeat(201),category:'effect'},
    {label:'valid',category:'unknown'},{label:'valid',category:'effect',capability:{automatic:true}}])
   assert.throws(()=>saveVerificationPlan(f.db,pipeline,actor,'system-v',{...input,expected_revision:3,objective_draft:draft}),{status:400});
  const registered=buildVerificationContract({...f.plan,assessment_rule:{id:'f08-web-headers-v1',kind:'headers',version:1,step_id:'observe'},objective_draft:input.objective_draft},1);
  assert.equal(registered.capability.automatic,true);assert.equal(registered.objective.category,'configuration_exposure');
  assert.notEqual(registered.objective.label,input.objective_draft.label);
  const changes=f.db.prepare('SELECT total_changes() n').get().n;verificationDetail(f.db,pipeline,'system-v');
  assert.equal(f.db.prepare('SELECT total_changes() n').get().n,changes);
 }finally{f.db.close();}
});

test('a saved plan without an attempt shows its current objective without inventing execution',async()=>{
 const f=await setup();try {
  f.db.exec("DELETE FROM finding_verification_assessments; DELETE FROM finding_verification_attempts");
  const item=f.db.prepare("SELECT * FROM finding_verifications WHERE id='system-v'").get();
  const before=f.db.prepare('SELECT total_changes() n').get().n;
  const result=projectVerificationResult(f.db,item,null,null);
  assert.equal(result.status,'not_performed');assert.equal(result.reason_code,'no_attempt');
  assert.deepEqual(result.object,f.plan.verification_contract.object);assert.deepEqual(result.objective,f.plan.verification_contract.objective);
  assert.deepEqual(result.operations,[]);assert.deepEqual(result.evidence_ids,[]);
  assert.equal(f.db.prepare('SELECT total_changes() n').get().n,before);
 }finally{f.db.close();}
});

test('missing HTML, explicit failed steps and incomplete required records cannot become target achieved',async()=>{
 const f=await setup();try {
  assert.equal(f.summary().result.status,'achieved');
  const {response,...missingHtml}=f.obs;f.updateObs(missingHtml);
  assert.equal(f.summary().result.reason_code,'response_body_missing');
  f.updateObs(f.obs);f.updateData({...f.data,success:false});
  assert.equal(f.summary().result.status,'inconclusive');
  f.updateData(f.data);f.db.exec("UPDATE execution_steps SET success=0,exit_code=1 WHERE run_id='system-r'");
  assert.equal(f.summary().result.reason_code,'required_steps_incomplete');
  f.db.exec("DELETE FROM execution_steps WHERE run_id='system-r'");
  assert.equal(f.summary().result.reason_code,'required_steps_incomplete');
 }finally{f.db.close();}
 const cookie=await setup();try {
  cookie.plan.assessment_rule={id:'f08-cookie-flags-v1',kind:'cookie',version:1,step_id:'observe',attribute:'httponly',cookie_name:'FixtureCookie',target:cookie.plan.target,limitations:'Fixture Cookie flag only'};
  cookie.plan.verification_contract=buildVerificationContract(cookie.plan,1);
  const fingerprint=hash(cookie.plan),link={...cookie.link,fingerprint};
  cookie.db.prepare('UPDATE finding_verification_plans SET content=?,fingerprint=?').run(JSON.stringify(cookie.plan),fingerprint);
  cookie.db.prepare('UPDATE execution_runs SET plan_data=?').run(JSON.stringify({finding_verification:link}));
  cookie.db.exec("UPDATE finding_verification_assessments SET rule_id='f08-cookie-flags-v1'");
  cookie.updateData({...cookie.data,finding_verification:link});
  const observation={...cookie.obs,cookie_attributes_complete:true,cookie_attributes:[{name:'FixtureCookie',httponly:false}]};
  cookie.updateObs(observation);assert.equal(cookie.summary().result.status,'achieved');
  const {response,...missingBody}=observation;cookie.updateObs(missingBody);
  assert.equal(cookie.summary().result.reason_code,'response_body_missing');
 }finally{cookie.db.close();}
});

test('explicit non-dispatch and blocked independent payload observations prove no start, never unknown stop',async()=>{
 const f=await setup();try {
  f.db.exec("DELETE FROM evidence_records; UPDATE finding_verification_attempts SET state='aborted'; UPDATE execution_runs SET status='ABORTED',final_summary='{\"existing\":true,\"verification_dispatch_started\":false}'");
  assert.equal(f.summary().result.reason_code,'dispatch_not_started');
  f.db.exec("UPDATE finding_verification_attempts SET state='unknown',stop_confirmed=0");
  assert.equal(f.summary().result.reason_code,'stop_unconfirmed');
 }finally{f.db.close();}
 const blocked=await setup();try {
  blocked.plan.steps[0]={...blocked.plan.steps[0],consumption:'independent',payload_id:'fixture-payload',payload_version:'version-1'};
  blocked.plan.verification_contract=buildVerificationContract(blocked.plan,1);
  const fingerprint=hash(blocked.plan),link={...blocked.link,fingerprint,tool_started:false,payload_consumed:false};
  blocked.db.prepare('UPDATE finding_verification_plans SET content=?,fingerprint=?').run(JSON.stringify(blocked.plan),fingerprint);
  blocked.db.prepare('UPDATE execution_runs SET plan_data=?').run(JSON.stringify({finding_verification:link}));
  blocked.updateData({...blocked.data,success:false,exit_code:1,finding_verification:link});
  assert.equal(blocked.summary().result.status,'not_performed');assert.equal(blocked.summary().result.operations[0].started,false);
 }finally{blocked.db.close();}
});

test('every required operation needs its own successful evidence, not just a successful criterion response',async()=>{
 const f=await setup();try {
  f.plan.steps.push({...f.plan.steps[0],step_id:'baseline',step_index:1,name:'Required baseline'});
  f.plan.verification_contract=buildVerificationContract(f.plan,1);
  const fingerprint=hash(f.plan),link={...f.link,fingerprint};
  f.db.prepare('UPDATE finding_verification_plans SET content=?,fingerprint=?').run(JSON.stringify(f.plan),fingerprint);
  f.db.prepare('UPDATE execution_runs SET plan_data=?').run(JSON.stringify({finding_verification:link}));
  f.updateData({...f.data,finding_verification:link});
  f.db.exec("INSERT INTO execution_steps(run_id,step_index,tool_id,success,exit_code) VALUES('system-r',1,'target-request',1,0)");
  assert.equal(f.summary().result.reason_code,'start_unproven');
  const call=Number(f.db.prepare("INSERT INTO execution_attempts(run_id,step_index,tool_id) VALUES('system-r',1,'target-request')").run().lastInsertRowid);
  const evidence=Number(f.db.prepare("INSERT INTO evidence_records(run_id,step_index,tool_id,target,attempt_id,evidence_data,raw_stdout) VALUES('system-r',1,'target-request',?,?,?,?)")
   .run(f.plan.target,call,JSON.stringify({...f.data,success:false,exit_code:1,finding_verification:link}),JSON.stringify(f.obs)).lastInsertRowid);
  assert.equal(f.summary().result.reason_code,'required_evidence_failed');
  f.db.prepare('UPDATE evidence_records SET evidence_data=? WHERE id=?').run(JSON.stringify({...f.data,finding_verification:link}),evidence);
  assert.equal(f.summary().result.status,'achieved');
 }finally{f.db.close();}
});

test('runner persists a non-dispatch proof for cancellation or permission failure before engine entry',async()=>{
 for(const mode of ['cancel','permission']) {
  const f=await setup({rule:false});try {
   const pipeline=f.db.prepare("SELECT * FROM pipelines WHERE pipeline_id='system-p'").get(),actor={sub:'fixture-user',role:'user'};
   saveVerificationPlan(f.db,pipeline,actor,'system-v',planInput(f));
   const saved=verificationDetail(f.db,pipeline,'system-v').plans[0];
   const attempt=confirmAndStart(f.db,pipeline,actor,'system-v',{revision:2,fingerprint:saved.fingerprint,request_id:`before-dispatch-${mode}`,confirmed:true});
   f.db.prepare('UPDATE execution_runs SET final_summary=? WHERE run_id=?').run(JSON.stringify({existing:true}),attempt.run_id);
   let calls=0;const engine={executeRun:async()=>{calls++;throw new Error('must not enter engine');},requestAbort:()=>{}};
   if(mode==='permission')f.db.exec("UPDATE users SET is_active=0 WHERE username='fixture-user'");
   const running=launchVerification(f.db,attempt,actor,{engine});
   if(mode==='cancel')await cancelVerification(f.db,attempt,{engine});
   await running;
   assert.equal(calls,0);
   const run=f.db.prepare('SELECT final_summary FROM execution_runs WHERE run_id=?').get(attempt.run_id);
   assert.deepEqual(JSON.parse(run.final_summary),{existing:true,verification_dispatch_started:false});
   const detail=verificationDetail(f.db,pipeline,'system-v');
   assert.equal(detail.attempts[0].stop_confirmed,1);assert.equal(detail.summary.result.status,'not_performed');
   assert.equal(detail.summary.result.reason_code,'dispatch_not_started');
  }finally{f.db.close();}
 }
});

test('no-content and partial pages cannot establish either outcome for document-based objectives',async()=>{
 for(const kind of ['headers','directory']) {
  const f=await setup();try {
   if(kind==='directory') {
    f.plan.target='http://fixture.invalid/docs/';f.plan.steps[0].args_template=JSON.stringify([JSON.stringify({url:f.plan.target,method:'GET'})]);
    f.db.prepare('UPDATE execution_runs SET target=?').run(f.plan.target);f.db.prepare('UPDATE evidence_records SET target=?').run(f.plan.target);
    f.plan.assessment_rule={id:'f08-directory-index-v1',kind:'directory',version:2,step_id:'observe',target:f.plan.target,limitations:'Directory fixture'};
    f.plan.verification_contract=buildVerificationContract(f.plan,1);
    const fingerprint=hash(f.plan),link={...f.link,fingerprint};
    f.db.prepare('UPDATE finding_verification_plans SET content=?,fingerprint=?').run(JSON.stringify(f.plan),fingerprint);
    f.db.prepare('UPDATE execution_runs SET plan_data=?').run(JSON.stringify({finding_verification:link}));
    f.updateData({...f.data,finding_verification:link});
    f.db.exec("UPDATE finding_verification_assessments SET rule_id='f08-directory-index-v1',rule_version=2,conclusion='not_verified'");
   }
   const baseline={...f.obs,url:f.plan.target};f.updateObs(baseline);
   assert.equal(f.summary().result.status,kind==='directory'?'not_achieved':'achieved');
   const saved=f.db.prepare('SELECT * FROM finding_verification_assessments').all();
   for(const observation of [
    {...baseline,status_code:204,response:''},{...baseline,status_code:205,response:''},
    {...baseline,status_code:206},{...baseline,response:''},{...baseline,response:'  \n  '},
    {...baseline,response_headers:{...f.obs.response_headers,'content-range':'bytes 0-10/100'}}
   ]) {
    f.updateObs(observation);const before=f.db.prepare('SELECT total_changes() n').get().n;
    const result=f.summary().result;
    assert.equal(result.status,'inconclusive');assert.equal(result.reason_code,'document_incomplete');
    if(kind==='directory') {
     const evidence=f.db.prepare('SELECT * FROM evidence_records WHERE id=991').get();
     const attempt=f.db.prepare("SELECT * FROM finding_verification_attempts WHERE id='system-a'").get();
     const criteria=directoryEvidenceCriteria(f.plan.assessment_rule,evidence,{...attempt,fingerprint:hash(f.plan)},{...f.plan,finding_id:1});
     assert.equal(criteria.checks[0].status,'unknown');assert.ok(criteria.checks.every(c=>c.status!=='passed'));
    }
    assert.equal(f.db.prepare('SELECT total_changes() n').get().n,before);
    assert.deepEqual(f.db.prepare('SELECT * FROM finding_verification_assessments').all(),saved);
   }
  }finally{f.db.close();}
 }
 const cookie=await setup();try {
  cookie.plan.assessment_rule={id:'f08-cookie-flags-v1',kind:'cookie',version:1,step_id:'observe',target:cookie.plan.target,attribute:'httponly',cookie_name:'FixtureCookie',limitations:'Cookie fixture'};
  cookie.plan.verification_contract=buildVerificationContract(cookie.plan,1);
  const fingerprint=hash(cookie.plan),link={...cookie.link,fingerprint};
  cookie.db.prepare('UPDATE finding_verification_plans SET content=?,fingerprint=?').run(JSON.stringify(cookie.plan),fingerprint);
  cookie.db.prepare('UPDATE execution_runs SET plan_data=?').run(JSON.stringify({finding_verification:link}));
  cookie.db.exec("UPDATE finding_verification_assessments SET rule_id='f08-cookie-flags-v1'");cookie.updateData({...cookie.data,finding_verification:link});
  cookie.updateObs({...cookie.obs,status_code:204,response:'',cookie_attributes_complete:true,cookie_attributes:[{name:'FixtureCookie',httponly:false}]});
  assert.equal(cookie.summary().result.status,'achieved','Cookie attributes are header facts and do not require an HTML document');
 }finally{cookie.db.close();}
});


test('finding execution snapshots preserve parent identity and reject mismatched child sources without writes',async()=>{
 const f=await setup();try {
  f.db.exec("INSERT INTO users(username,password,role) VALUES('foreign','fixture','user')");
  const pipeline=f.db.prepare("SELECT * FROM pipelines WHERE pipeline_id='system-p'").get();
  const changes=()=>f.db.prepare('SELECT total_changes() n').get().n;
  const before=changes(),snapshot=taskExecutionSnapshot(f.db,pipeline);
  assert.equal(snapshot.run,null);
  assert.equal(snapshot.verification_runs.total,1);
  assert.equal(snapshot.verification_runs.items[0].run_id,'system-r');
  assert.equal(snapshot.verification_runs.items[0].result.status,'achieved');
  assert.equal(snapshot.verification_runs.items[0].tool_calls,1);
  assert.equal(snapshot.verification_runs.items[0].evidence_count,1);
  assert.equal(JSON.stringify(snapshot).includes('<html>fixture</html>'),false);
  const summary=taskSummary(f.db,pipeline);
  assert.equal(summary.execution,null);assert.equal(summary.finding_verifications.completed,1);
  assert.deepEqual(summary.finding_verifications.items,[]);
  assert.deepEqual(taskExecutionSnapshot(f.db,pipeline).verification_runs,snapshot.verification_runs);
  assert.equal(changes(),before,'repeated snapshots must be read-only');
  assert.equal(findingVerificationExecution(f.db,{...pipeline,pipeline_id:'foreign'}).total,0);
  const reject=()=>{
   const result=findingVerificationExecution(f.db,pipeline);
   assert.equal(result.total,0);assert.equal(result.invalid_source_count,1);assert.deepEqual(result.items,[]);
  };
  for(const key of ['pipeline_id','verification_id','attempt_id','finding_id','revision','fingerprint']) {
   f.db.prepare("UPDATE execution_runs SET plan_data=? WHERE run_id='system-r'")
    .run(JSON.stringify({finding_verification:{...f.link,[key]:'foreign'}}));reject();
  }
  f.db.prepare("UPDATE execution_runs SET plan_data=? WHERE run_id='system-r'").run(JSON.stringify({finding_verification:f.link}));
  f.db.exec("UPDATE execution_runs SET user_sub='foreign' WHERE run_id='system-r'");reject();
  f.db.exec("UPDATE execution_runs SET user_sub='fixture-user',target='http://foreign.invalid/' WHERE run_id='system-r'");reject();
  f.db.prepare("UPDATE execution_runs SET target=? WHERE run_id='system-r'").run(f.plan.target);
  f.db.exec("UPDATE scan_tasks SET created_by='foreign' WHERE scan_task_id='system-s'");reject();
  f.db.exec("UPDATE scan_tasks SET created_by='fixture-user' WHERE scan_task_id='system-s'");
  assert.equal(findingVerificationExecution(f.db,pipeline).total,1);
 }finally{f.db.close();}
});
