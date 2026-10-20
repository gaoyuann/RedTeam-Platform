import {createHash} from 'node:crypto';
import {buildVerificationContract} from '../src/services/findingVerificationResult.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { runMigrations } from '../src/db/migrate.js';
import { syncInstances, findingIdentity } from '../src/services/findingInstances.js';
import { taskStatistics } from '../src/services/taskStatistics.js';
import { importBaseline } from '../src/services/taskBaselines.js';
import { taskResultsSnapshot,createTaskReport,readTaskReport,taskReportHtml } from '../src/services/taskResults.js';
import routes from '../src/routes/taskResults.js';
import pipelines from '../src/routes/pipelines.js';
import scans from '../src/routes/scans.js';
import reportRoutes from '../src/routes/reports.js';

async function fixture() {
  const db=new Database(':memory:');db.pragma('foreign_keys=ON');
  await runMigrations(db,fileURLToPath(new URL('../src/db/migrations/',import.meta.url)));
  for(const name of ['f09alice','f09bob'])db.prepare("INSERT INTO users(username,password,role) VALUES (?,'fixture','user')").run(name);
  db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,config) VALUES ('f09','http://192.0.2.2/','completed','f09alice',?)")
    .run(JSON.stringify({task_scope:{includes:['http://192.0.2.2/'],excludes:[],execution_location:'scanner'}}));
  db.prepare("INSERT INTO scan_tasks(scan_task_id,scan_type,target,status,created_by,pipeline_id) VALUES ('s','web_scan','http://192.0.2.2/','COMPLETED','f09alice','f09')").run();
  const p=db.prepare("SELECT * FROM pipelines WHERE pipeline_id='f09'").get();
  const add=(data={},severity='high')=>Number(db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,source_tool,severity) VALUES ('s','web_vuln',?,'nuclei',?)")
    .run(JSON.stringify({url:'http://192.0.2.2/login',method:'GET',rule_id:'rule-a',...data}),severity).lastInsertRowid);
  return {db,p,add};
}
const actor={sub:'f09alice',role:'user'};
const baseline=()=>({schema_version:1,environment_id:'lab',environment_version:'1',assets_complete:true,vulnerabilities_complete:true,
  assets:[{id:'a',target:'http://192.0.2.2/'}],vulnerabilities:[{id:'v',asset_id:'a',source_tool:'nuclei',location:{url:'http://192.0.2.2/login',method:'GET',rule_id:'rule-a'}}]});

test('conservative identities preserve location, parameter, tool and source versions',()=>{
  const identity=d=>findingIdentity({source_tool:'nuclei',result_data:d});
  assert.equal(identity({url:'http://host/a',rule_id:'r'}),null);
  assert.equal(identity({url:'http://host/a?token=secret',method:'GET',rule_id:'r'}),null);
  assert.notDeepEqual(identity({url:'http://host/a',method:'GET',rule_id:'r'}),identity({url:'http://host/b',method:'GET',rule_id:'r'}));
  assert.notDeepEqual(identity({url:'http://host/a',method:'GET',rule_id:'r',parameter:'id',parameter_location:'query'}),identity({url:'http://host/a',method:'GET',rule_id:'r',parameter:'id',parameter_location:'body'}));
  assert.notDeepEqual(identity({target:'http://host/',file:'a.c',line:5,source_version:'1',rule_id:'r'}),identity({target:'http://host/',file:'a.c',line:5,source_version:'2',rule_id:'r'}));
});

test('full counts, idempotent mapping, unknown denominators and baseline revisions',async()=>{
  const {db,p,add}=await fixture();try{
    for(let n=0;n<510;n++)add();add({rule_id:null});
    let s=taskStatistics(db,p);assert.equal(s.statistics.findings.records,511);assert.equal(s.statistics.baseline,null);
    const before=s.source_fingerprint;syncInstances(db,p);syncInstances(db,p);
    s=taskStatistics(db,p);assert.equal(s.instances.length,1);assert.equal(s.statistics.findings.mapped_records,510);assert.equal(s.statistics.findings.unmapped_records,1);assert.notEqual(s.source_fingerprint,before);
    const imported=importBaseline(db,p,actor,baseline());assert.equal(importBaseline(db,p,actor,baseline()).id,imported.id);
    s=taskStatistics(db,p);assert.equal(s.statistics.baseline.discovery.value,1);
    const partial=baseline();partial.vulnerabilities_complete=false;importBaseline(db,p,actor,partial);
    assert.equal(taskStatistics(db,p).statistics.baseline.discovery.value,null);
    const invalid=baseline();invalid.assets[0].target='http://outside.invalid';assert.throws(()=>importBaseline(db,p,actor,invalid),{status:400});
    const wrong=baseline();wrong.environment_version='2';assert.throws(()=>importBaseline(db,p,actor,wrong),{status:409});
    const secret=baseline();secret.token='sensitive';assert.throws(()=>importBaseline(db,p,actor,secret),{status:400});
    const duplicate=baseline();duplicate.vulnerabilities.push({...duplicate.vulnerabilities[0],id:'v2'});assert.throws(()=>importBaseline(db,p,actor,duplicate),{status:400});
    const empty=baseline();empty.assets=[];empty.vulnerabilities=[];importBaseline(db,p,actor,empty);
    assert.equal(taskStatistics(db,p).statistics.baseline.discovery.reason,'不适用');
    for(let n=0;n<510;n++)db.prepare("INSERT INTO task_checks(check_id,pipeline_id,check_type,state,created_at,updated_at) VALUES (?,'f09','web_security','completed','now','now')").run('check-'+n);
    assert.equal(taskStatistics(db,p).statistics.checks.states.completed,510);
  }finally{db.close();}
});

function attempt(db,finding,n,{conclusion='confirmed',started=true,state='completed',forged=false,manual=null}={}) {
  const verification='verify-'+finding, attemptId='attempt-'+n, run='run-'+n;
  db.prepare("INSERT OR IGNORE INTO finding_verifications(id,pipeline_id,finding_id,scan_task_id,revision,state) VALUES (?,'f09',?,'s',1,'completed')").run(verification,finding);
  const plan={target:'http://192.0.2.2/login',steps:[{step_id:'check',step_index:0,tool_id:'target-request',name:'Observe HTML headers',consumption:'none'}],assessment_rule:{id:'f08-web-headers-v1',version:1,kind:'headers',attribute:'nosniff',target:'http://192.0.2.2/login',step_id:'check',limitations:'Fixture scope'}};
  plan.verification_contract=buildVerificationContract(plan,finding);
  const fingerprint=createHash('sha256').update(JSON.stringify(plan)).digest('hex');
  db.prepare("INSERT OR IGNORE INTO finding_verification_plans(verification_id,revision,content,fingerprint) VALUES (?,1,?,?)").run(verification,JSON.stringify(plan),fingerprint);
  const link={pipeline_id:'f09',finding_id:finding,verification_id:verification,attempt_id:attemptId,revision:1,fingerprint};
  db.prepare("INSERT INTO execution_runs(run_id,target,user_sub,status,plan_data,preflight_status) VALUES (?,'http://192.0.2.2/login','f09alice','COMPLETED',?,'PASSED')").run(run,JSON.stringify({finding_verification:link}));
  db.prepare("INSERT INTO finding_verification_attempts(id,verification_id,pipeline_id,revision,run_id,request_id,state,stop_confirmed) VALUES (?,?,'f09',1,?,?,?,?)")
    .run(attemptId,verification,run,attemptId,state,state==='unknown'?0:1);
  const call=Number(db.prepare("INSERT INTO execution_attempts(run_id,step_index,tool_id) VALUES (?,0,'target-request')").run(run).lastInsertRowid);
  db.prepare("INSERT INTO execution_steps(run_id,step_index,tool_id,success,exit_code) VALUES (?,0,'target-request',1,0)").run(run);
  const evidence=Number(db.prepare("INSERT INTO evidence_records(run_id,step_index,tool_id,evidence_type,evidence_data,target,attempt_id) VALUES (?,0,'target-request','http',?,'http://192.0.2.2/login',?)")
    .run(run,JSON.stringify({success:true,exit_code:0,finding_verification:{...link,attempt_id:forged?'other':attemptId,tool_started:started}}),call).lastInsertRowid);
  db.prepare("INSERT INTO finding_verification_assessments(attempt_id,rule_id,rule_version,conclusion,evidence_ids,reason,limitations) VALUES (?,'f08-web-headers-v1',1,?,?,'fixture','fixture')")
    .run(attemptId,conclusion,JSON.stringify([evidence]));
  db.prepare('UPDATE evidence_records SET raw_stdout=? WHERE id=?').run(JSON.stringify({url:plan.target,method:'GET',connected:true,complete:true,status_code:200,response_headers:{'content-type':'text/html',...(conclusion==='not_verified'?{'x-content-type-options':'nosniff'}:{})},response:'<html>Fixture</html>'}),evidence);
  if(manual)db.prepare("INSERT INTO finding_verification_reviews(attempt_id,conclusion,evidence_ids,note,reviewed_by) VALUES (?,?,?,'review','f09alice')").run(attemptId,manual,JSON.stringify([evidence]));
  return {run,attemptId};
}

test('non-dispatch proof updates start counts only after actual stop is confirmed',async()=>{
 const {db,p,add}=await fixture();try {
  const finding=add();syncInstances(db,p);
  const created=attempt(db,finding,999,{state:'aborted'});
  db.prepare('DELETE FROM evidence_records WHERE run_id=?').run(created.run);
  db.prepare('DELETE FROM execution_steps WHERE run_id=?').run(created.run);
  db.prepare('DELETE FROM execution_attempts WHERE run_id=?').run(created.run);
  db.prepare("UPDATE execution_runs SET status='ABORTED',final_summary=? WHERE run_id=?")
   .run(JSON.stringify({verification_dispatch_started:false}),created.run);
  let result=taskStatistics(db,p);
  assert.equal(result.statistics.verifications.not_started,1);assert.equal(result.statistics.verifications.start_unknown,0);
  assert.equal(result.attempts[0].result.status,'not_performed');
  db.prepare("UPDATE finding_verification_attempts SET state='unknown',stop_confirmed=0 WHERE id=?").run(created.attemptId);
  result=taskStatistics(db,p);
  assert.equal(result.statistics.verifications.not_started,0);assert.equal(result.statistics.verifications.start_unknown,1);
  assert.equal(result.attempts[0].result.status,'inconclusive');
 }finally{db.close();}
});

test('verification counts use starts and scoped evidence, system results and independent opinions',async()=>{
  const {db,p,add}=await fixture();try{
    const a=add(),b=add();syncInstances(db,p);
    attempt(db,a,1);attempt(db,a,2);attempt(db,a,3);
    let s=taskStatistics(db,p);assert.equal(s.statistics.verifications.started,3);assert.equal(s.statistics.verifications.executed_instances,1);assert.equal(s.statistics.verifications.confirmed_instances,1);
    attempt(db,b,4,{manual:'false_positive'});assert.equal(taskStatistics(db,p).instances[0].conclusion,'confirmed');assert.equal(taskStatistics(db,p).statistics.verifications.human_opinions,1);
    attempt(db,a,5,{state:'unknown'});s=taskStatistics(db,p);assert.equal(s.instances[0].conclusion,'confirmed');assert.equal(s.statistics.report_ready,false);
    attempt(db,b,6,{forged:true});s=taskStatistics(db,p);assert.equal(s.instances[0].conclusion,'inconclusive');assert.equal(s.statistics.verifications.confirmed_instances,0);assert.equal(s.statistics.verifications.start_unknown,1);
    attempt(db,a,7,{started:false});s=taskStatistics(db,p);assert.equal(s.statistics.verifications.not_started,1);assert.equal(s.statistics.verifications.confirmed_instances,0);
  }finally{db.close();}
});

test('pure-scan report freezes full data and supports generic permissions and export',async()=>{
  const {db,p,add}=await fixture();let server;try{
    add();syncInstances(db,p);importBaseline(db,p,actor,baseline());
    const snapshot=taskResultsSnapshot(db,p);assert.equal(snapshot.execution.run,null);
    const created=createTaskReport(db,p,actor,{source_fingerprint:snapshot.source_fingerprint});
    assert.equal(createTaskReport(db,p,actor,{source_fingerprint:snapshot.source_fingerprint}).reused,true);
    const document=readTaskReport(db,p,created.report.report_id);assert.equal(document.report.content.schema_version,2);assert.match(taskReportHtml(document),/统一统计/);
    add({url:'http://192.0.2.2/other'});syncInstances(db,p);
    assert.equal(readTaskReport(db,p,created.report.report_id).report.content.results.statistics.findings.instances,1);
    assert.throws(()=>createTaskReport(db,p,actor,{source_fingerprint:snapshot.source_fingerprint}),{status:409});
    const app=express();app.use(express.json());app.use((req,res,next)=>{req.user={sub:req.headers['x-actor']||'f09alice',role:'user'};next();});
    app.use('/api/pipelines/:id/results',routes(db));app.use('/api/reports',reportRoutes(db));
    app.use('/api/pipelines',pipelines(db));app.use('/api/scans',scans(db));
    app.use((e,req,res,next)=>res.status(e.status||500).json({status:'error',error:{message:e.message}}));
    server=app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));
    const root='http://127.0.0.1:'+server.address().port;
    let response=await fetch(root+'/api/reports/'+created.report.report_id+'/export?format=html');assert.equal(response.status,200);assert.match(await response.text(),/统一统计/);
    response=await fetch(root+'/api/reports/'+created.report.report_id+'/export?format=json');
    assert.deepEqual((await response.json()).report.content.results.statistics,document.report.content.results.statistics);
    response=await fetch(root+'/api/reports/'+created.report.report_id,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({content:{}})});assert.equal(response.status,409);
    response=await fetch(root+'/api/reports/'+created.report.report_id,{method:'DELETE'});assert.equal(response.status,409);
    response=await fetch(root+'/api/pipelines/f09',{method:'DELETE'});assert.equal(response.status,409);
    response=await fetch(root+'/api/scans/s',{method:'DELETE'});assert.equal(response.status,409);
    assert.ok(db.prepare("SELECT 1 FROM pipelines WHERE pipeline_id='f09'").get());
    assert.ok(db.prepare("SELECT 1 FROM scan_tasks WHERE scan_task_id='s'").get());
    response=await fetch(root+'/api/reports/index');assert.equal((await response.json()).data.records[0].pipeline_id,'f09');
    response=await fetch(root+'/api/reports/'+created.report.report_id,{headers:{'x-actor':'f09bob'}});assert.equal(response.status,403);
    response=await fetch(root+'/api/pipelines/f09/results/instances?source_fingerprint='+snapshot.source_fingerprint);assert.equal(response.status,409);
    response=await fetch(root+'/api/pipelines/f09/results/instances?limit=1');const first=(await response.json()).data;assert.equal(first.rows.length,1);assert.equal(first.page.total,2);
    response=await fetch(root+'/api/pipelines/f09/results/instances?limit=1&after='+first.page.next_after+'&source_fingerprint='+first.source_fingerprint);assert.equal((await response.json()).data.rows.length,1);
    response=await fetch(root+'/api/pipelines/f09/results/instances',{headers:{'x-actor':'f09bob'}});assert.equal(response.status,403);
    const post=(path,body)=>fetch(root+'/api/pipelines/f09/results'+path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    response=await post('/instances/sync',{source_fingerprint:snapshot.source_fingerprint});assert.equal(response.status,409);
    const current=taskStatistics(db,p).source_fingerprint;
    const beforePreview=db.prepare('SELECT total_changes() n').get().n;
    response=await post('/baselines',{source_fingerprint:current,content:baseline(),preview:true});assert.equal(response.status,200);
    assert.equal(db.prepare('SELECT total_changes() n').get().n,beforePreview);
    response=await post('/instances/sync',{source_fingerprint:current});assert.equal(response.status,200);
    response=await post('/baselines',{source_fingerprint:current,content:{...baseline(),cookie:'not-allowed'}});assert.equal(response.status,400);

  }finally{if(server)await new Promise(resolve=>server.close(resolve));db.close();}
});

test('stopped checks, preflight failure, coverage denominator and source isolation',async()=>{
  const {db,p,add}=await fixture();try{
    const finding=add();syncInstances(db,p);importBaseline(db,p,actor,baseline());
    db.prepare("INSERT INTO task_checks(check_id,pipeline_id,check_type,target,state,created_at,updated_at) VALUES ('covered','f09','web_security','http://192.0.2.2/login','completed','now','now')").run();
    let data=taskStatistics(db,p);assert.equal(data.statistics.assets.coverage.value,1);
    const created=attempt(db,finding,1,{state:'failed',conclusion:'confirmed'});
    assert.equal(taskStatistics(db,p).statistics.verifications.confirmed_instances,0);
    db.prepare('DELETE FROM finding_verification_assessments WHERE attempt_id=?').run(created.attemptId);
    db.prepare('DELETE FROM evidence_records WHERE run_id=?').run(created.run);
    db.prepare('DELETE FROM execution_attempts WHERE run_id=?').run(created.run);
    db.prepare("UPDATE execution_runs SET preflight_status='FAILED' WHERE run_id=?").run(created.run);
    data=taskStatistics(db,p);assert.equal(data.statistics.verifications.not_started,1);assert.equal(data.statistics.verifications.executed_instances,0);
    db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,state,started_at,completed_at,outcome) VALUES ('tr','s','nuclei','timed_out','now','now',?)")
      .run(JSON.stringify({timed_out:true,aborted:false,stopped:false}));
    data=taskStatistics(db,p);assert.equal(data.statistics.checks.tool_outcomes.timed_out,1);assert.equal(data.statistics.checks.total,1);assert.equal(data.statistics.report_ready,false);
    assert.throws(()=>createTaskReport(db,p,actor,{source_fingerprint:data.source_fingerprint}),{status:409});
    db.prepare("UPDATE scan_tool_runs SET outcome=? WHERE tool_run_id='tr'").run(JSON.stringify({timed_out:true,aborted:false,stopped:true}));
    assert.equal(taskStatistics(db,p).statistics.report_ready,true);
    db.prepare("UPDATE execution_runs SET target='http://outside.invalid' WHERE run_id=?").run(created.run);
    data=taskStatistics(db,p);assert.equal(data.statistics.report_ready,false);assert.equal(data.statistics.verifications.start_unknown,1);
    assert.throws(()=>taskStatistics(db,{...p,run_id:created.run}),{status:409});
  }finally{db.close();}
});

test('read paths do not mutate mappings and sync requests remain idempotent',async()=>{
  const {db,p,add}=await fixture();try{
    add();
    const before=db.prepare('SELECT total_changes() n').get().n;taskStatistics(db,p);taskStatistics(db,p);
    assert.equal(db.prepare('SELECT total_changes() n').get().n,before);
    await Promise.all(Array.from({length:8},()=>Promise.resolve().then(()=>syncInstances(db,p))));
    assert.equal(db.prepare('SELECT COUNT(*) n FROM finding_instances').get().n,1);
    assert.equal(db.prepare('SELECT COUNT(*) n FROM finding_instance_records').get().n,1);
    const input=baseline(), reversed=Object.fromEntries(Object.entries(input).reverse());
    const one=importBaseline(db,p,actor,input);assert.equal(importBaseline(db,p,actor,reversed).id,one.id);
  }finally{db.close();}
});

test('legacy v1 reports remain immutable and readable without F09 backfill',async()=>{
  const {db,p,add}=await fixture();try{
    add();db.prepare("INSERT INTO execution_runs(run_id,target,user_sub,status) VALUES ('legacy-run','http://192.0.2.2/','f09alice','COMPLETED')").run();
    db.prepare("UPDATE pipelines SET run_id='legacy-run' WHERE pipeline_id='f09'").run();p.run_id='legacy-run';
    const snapshot=taskResultsSnapshot(db,p);delete snapshot.statistics;delete snapshot.instances;delete snapshot.baseline;delete snapshot.coverage_checks;delete snapshot.verification_attempts;delete snapshot.reports;
    const content={schema_version:1,type:'task_result_report',provenance:{pipeline_id:p.pipeline_id,owner:p.created_by,target:p.target,run_id:p.run_id,source_fingerprint:snapshot.source_fingerprint},results:snapshot};
    const original=JSON.stringify(content);
    db.prepare("INSERT INTO test_reports(report_id,title,run_id,template,status,content,generated_by) VALUES ('old-report','old','legacy-run','task_trace_v1','draft',?,'f09alice')").run(original);
    syncInstances(db,p);importBaseline(db,p,actor,baseline());
    const document=readTaskReport(db,p,'old-report');assert.equal(document.report.kind,'trace_snapshot');assert.equal(document.report.content.results.statistics,undefined);assert.match(taskReportHtml(document),/该历史报告未记录/);
    assert.equal(db.prepare("SELECT content FROM test_reports WHERE report_id='old-report'").get().content,original);
  }finally{db.close();}
});

test('review: baseline rejects nested or irrelevant fields and canonical duplicate assets',async()=>{
  const {db,p}=await fixture();try{
    const nested=baseline();nested.vulnerabilities[0].location.parameter={cookie:'fixture-only'};
    assert.throws(()=>importBaseline(db,p,actor,nested),{status:400});
    const ignored=baseline();ignored.vulnerabilities[0].location.host={token:'fixture-only'};
    assert.throws(()=>importBaseline(db,p,actor,ignored),{status:400});
    const duplicate=baseline();duplicate.assets.push({id:'alias',target:'http://192.0.2.2:80/'});
    assert.throws(()=>importBaseline(db,p,actor,duplicate),{status:400});
    assert.equal(db.prepare('SELECT COUNT(*) n FROM task_baselines').get().n,0);
  }finally{db.close();}
});

test('review: malformed parameter identities and out-of-scope records never merge',async()=>{
  const {db,p,add}=await fixture();try{
    add({parameter:{name:'id'}});add({url:'http://outside.invalid/login'});
    syncInstances(db,p);
    assert.equal(taskStatistics(db,p).statistics.findings.instances,0);
    assert.equal(taskStatistics(db,p).statistics.findings.unmapped_records,2);
    assert.equal(taskStatistics(db,p).statistics.findings.sync_pending,false);
  }finally{db.close();}
});

test('review: active scans hidden by result scope still block terminal reporting',async()=>{
  const {db,p}=await fixture();try{
    db.prepare("INSERT INTO scan_tasks(scan_task_id,scan_type,target,status,created_by,pipeline_id) VALUES ('outside','web_scan','http://outside.invalid','RUNNING','f09alice','f09')").run();
    const snapshot=taskResultsSnapshot(db,p);
    assert.equal(snapshot.statistics.report_ready,false);
    assert.throws(()=>createTaskReport(db,p,actor,{source_fingerprint:snapshot.source_fingerprint}),{status:409});
  }finally{db.close();}
});

test('review: invalid evidence IDs are suppressed in judgement details as well as counters',async()=>{
  const {db,p,add}=await fixture();try{
    const finding=add();syncInstances(db,p);attempt(db,finding,1,{forged:true});
    const data=taskStatistics(db,p),view=data.instances[0].attempts[0];
    assert.equal(view.conclusion,'inconclusive');assert.deepEqual(view.evidence_ids,[]);
    assert.equal(view.judgement,null);
  }finally{db.close();}
});

test('review: source identities include target and UDP baselines obey host scope',async()=>{
  const source={source_tool:'cppcheck',result_data:{target:'192.0.2.2',file:'main.c',line:1,source_version:'v1',rule_id:'r'}};
  assert.notDeepEqual(findingIdentity(source),findingIdentity({...source,result_data:{...source.result_data,target:'192.0.2.3'}}));
  assert.equal(findingIdentity({...source,result_data:{...source.result_data,target:undefined}}),null);
  const {db,p}=await fixture();try{
    const hostPipeline={...p,target:'192.0.2.2',config:JSON.stringify({task_scope:{includes:['192.0.2.2'],excludes:[]}})};
    const b=baseline();b.assets[0].target='192.0.2.2';b.vulnerabilities[0].location={rule_id:'r',host:'192.0.2.2',port:53,protocol:'udp'};
    assert.ok(importBaseline(db,hostPipeline,actor,b).id);
    b.vulnerabilities[0].location.port='53';assert.throws(()=>importBaseline(db,hostPipeline,actor,b),{status:400});
  }finally{db.close();}
});

test('review: changed environment invalidates baseline rates and active verification Run blocks report',async()=>{
  const {db,p,add}=await fixture();try{
    importBaseline(db,p,actor,baseline());
    const changed={...p,config:JSON.stringify({task_scope:{includes:[p.target],environment_ref:'different-lab'}})};
    const s=taskStatistics(db,changed).statistics;assert.equal(s.baseline.applicable,false);assert.equal(s.baseline.discovery.value,null);assert.equal(s.assets.coverage.value,null);
    const finding=add();syncInstances(db,p);const a=attempt(db,finding,1);
    db.prepare("UPDATE execution_runs SET status='RUNNING' WHERE run_id=?").run(a.run);
    assert.equal(taskStatistics(db,p).statistics.verifications.confirmed_instances,0);
    assert.equal(taskStatistics(db,p).statistics.report_ready,false);
    db.prepare("UPDATE scan_results SET result_type='information' WHERE id=?").run(finding);
    assert.equal(taskStatistics(db,p).statistics.report_ready,false,'reclassified findings must not hide active runs');
  }finally{db.close();}
});


test('review: initial security scans count toward asset coverage, discovery alone does not',async()=>{
  const {db,p}=await fixture();try{
    importBaseline(db,p,actor,baseline());
    db.prepare("INSERT INTO task_checks(check_id,pipeline_id,check_type,target,state,created_at,updated_at) VALUES ('initial','f09','port_scan','http://192.0.2.2/','completed','now','now')").run();
    assert.equal(taskStatistics(db,p).statistics.assets.coverage.value,0);
    db.prepare("UPDATE task_checks SET check_type='web_scan' WHERE check_id='initial'").run();
    assert.equal(taskStatistics(db,p).statistics.assets.coverage.value,1);
    db.prepare("UPDATE task_checks SET state='partial' WHERE check_id='initial'").run();
    assert.equal(taskStatistics(db,p).statistics.assets.coverage.value,0);
  }finally{db.close();}
});


test('legacy display targets without a parseable scope retain result snapshots',async()=>{
  const {db,p}=await fixture();try{
    db.prepare("UPDATE pipelines SET target='historical display label',config='{}' WHERE pipeline_id='f09'").run();
    const legacy=db.prepare("SELECT * FROM pipelines WHERE pipeline_id='f09'").get();
    const result=taskResultsSnapshot(db,legacy);
    assert.equal(result.statistics.completeness.scope_available,false);
    assert.equal(result.statistics.findings.instances,0);
    assert.equal(result.statistics.assets.coverage.value,null);
    assert.equal(result.statistics.baseline,null);
  }finally{db.close();}
});
