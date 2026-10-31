import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { runMigrations } from '../src/db/migrate.js';
import { continueScanTest } from '../src/services/scanTestContext.js';
import { pipelineScans } from '../src/services/scanResultQuery.js';
import { ensureVerification, verificationDetail, selectVerificationTemplate, confirmAndStart } from '../src/services/findingVerification.js';
import { launchVerification } from '../src/services/findingVerificationRunner.js';
import { taskResultsSnapshot, createTaskReport, readTaskReport } from '../src/services/taskResults.js';
import { exportTaskReport } from '../src/services/taskReportExport.js';
import scanRoutes from '../src/routes/scans.js';

const actor = { sub: 'context-alice', role: 'user' };
async function fixture() {
  const db = new Database(':memory:');
  db.pragma('foreign_keys=ON');
  await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
  for (const name of [actor.sub, 'context-bob'])
    db.prepare("INSERT INTO users(username,password,role,is_active) VALUES(?,'fixture','user',1)").run(name);
  db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by) VALUES('scan-context','http://fixture.invalid','web_scan','COMPLETED',?)").run(actor.sub);
  const finding = Number(db.prepare("INSERT INTO scan_results(scan_task_id,result_type,severity,source_tool,result_data) VALUES('scan-context','web_vuln','medium','nikto',?)")
    .run(JSON.stringify({ finding: 'The X-Content-Type-Options header is not set.', url: 'http://fixture.invalid/item' })).lastInsertRowid);
  return { db, finding };
}

test('scan continuation is idempotent, retains original records and never starts execution', async () => {
  const { db, finding } = await fixture();
  try {
    const first = continueScanTest(db, actor, 'scan-context');
    assert.equal(first.reused, false);
    assert.match(first.task_no, /^TASK-/);
    const again = continueScanTest(db, actor, 'scan-context');
    assert.equal(again.pipeline_id, first.pipeline_id);
    assert.equal(again.reused, true);
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(first.pipeline_id);
    assert.equal(pipeline.status, 'completed');
    assert.equal(JSON.parse(pipeline.config).authorization_confirmed, false);
    assert.equal(pipelineScans(db, pipeline)[0].scan_task_id, 'scan-context');
    assert.equal(db.prepare('SELECT id FROM scan_results').get().id, finding);
    assert.equal(db.prepare('SELECT count(*) n FROM scan_tasks').get().n, 1);
    assert.equal(db.prepare('SELECT count(*) n FROM pipelines').get().n, 1);
    assert.equal(db.prepare('SELECT count(*) n FROM execution_runs').get().n, 0);
    assert.equal(db.prepare('SELECT count(*) n FROM finding_verifications').get().n, 0);
  } finally { db.close(); }
});

test('running, unsupported, foreign, inconsistent and inactive contexts do not create tasks', async () => {
  const { db } = await fixture();
  const check = (who, status) => assert.throws(() => continueScanTest(db, who, 'scan-context'), error => error.status === status);
  try {
    check({sub:'context-bob',role:'user'},403);
    db.prepare("UPDATE scan_tasks SET status='RUNNING'").run(); check(actor,409);
    db.prepare("UPDATE scan_tasks SET status='COMPLETED',scan_type='topology_scan'").run(); check(actor,400);
    // Simulate a dangling link from an older database without FK enforcement.
    db.pragma('foreign_keys=OFF');
    db.prepare("UPDATE scan_tasks SET scan_type='web_scan',pipeline_id='missing-task'").run();
    db.pragma('foreign_keys=ON');
    check(actor,409);
    db.prepare('UPDATE scan_tasks SET pipeline_id=NULL').run();
    db.prepare("INSERT INTO scan_tool_runs(tool_run_id,scan_task_id,tool_id,state,started_at) VALUES('context-call','scan-context','nikto','running',datetime('now'))").run();
    check(actor,409);
    db.prepare("UPDATE scan_tool_runs SET state='failed',completed_at=datetime('now'),outcome='{\"stopped\":false}'").run();
    check(actor,409);
    db.prepare("UPDATE scan_tool_runs SET outcome='{\"stopped\":true}'").run();
    db.prepare('UPDATE users SET is_active=0 WHERE username=?').run(actor.sub); check(actor,401);
    assert.equal(db.prepare('SELECT count(*) n FROM pipelines').get().n,0);
  } finally { db.close(); }
});

test('legacy links are reused without rebinding, discovery records keep their boundary', async () => {
  const { db } = await fixture();
  try {
    db.prepare("INSERT INTO pipelines(pipeline_id,target,status,created_by,scan_task_id,config) VALUES('old-context','http://fixture.invalid','completed',?,'scan-context','{}')").run(actor.sub);
    assert.equal(continueScanTest(db,actor,'scan-context').pipeline_id,'old-context');
    db.prepare("UPDATE pipelines SET scan_task_id='old-missing-scan, scan-context '").run();
    assert.equal(continueScanTest(db,actor,'scan-context').pipeline_id,'old-context');
    assert.equal(db.prepare('SELECT pipeline_id FROM scan_tasks').get().pipeline_id,null);
    db.prepare("UPDATE pipelines SET config='{\"task_mode\":\"discovery\"}'").run();
    assert.throws(()=>continueScanTest(db,actor,'scan-context'),error=>error.status===409);
    db.prepare("UPDATE pipelines SET config='{}',target='http://other.invalid'").run();
    assert.throws(()=>continueScanTest(db,actor,'scan-context'),error=>error.status===409);
  } finally { db.close(); }
});

test('HTTP continuation checks record ownership and returns the same context on retry', async () => {
  const { db } = await fixture();
  const app = express();
  app.use(express.json(), (req,res,next)=>{req.user={sub:req.headers['x-user'] || actor.sub,role:'user'};next();});
  app.use('/api/scan-tasks',scanRoutes(db));
  app.use((error,req,res,next)=>res.status(error.status || 500).json({status:'error',error:{message:error.message}}));
  const server = app.listen(0,'127.0.0.1');
  await new Promise(resolve=>server.once('listening',resolve));
  const request = user => fetch(`http://127.0.0.1:${server.address().port}/api/scan-tasks/scan-context/test-context`,
    {method:'POST',headers:{'x-user':user,'content-type':'application/json'},body:'{}'});
  try {
    assert.equal((await request('context-bob')).status,403);
    const first = await (await request(actor.sub)).json();
    const second = await (await request(actor.sub)).json();
    assert.equal(first.status,'ok');
    assert.equal(first.data.pipeline_id,second.data.pipeline_id);
    assert.equal(second.data.reused,true);
  } finally { await new Promise(resolve=>server.close(resolve)); db.close(); }
});

for (const outcome of ['confirmed', 'failed']) test(`scan → finding → plan → ${outcome} evidence → assessment → exported report`, async () => {
  const { db, finding } = await fixture();
  try {
    const context = continueScanTest(db,actor,'scan-context');
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(context.pipeline_id);
    const item = ensureVerification(db,pipeline,finding);
    selectVerificationTemplate(db,pipeline,actor,item.id,{playbook_id:'f08-web-headers-v1',expected_revision:0});
    const detail = verificationDetail(db,pipeline,item.id);
    assert.equal(detail.default_target,'http://fixture.invalid/item');
    assert.equal(detail.finding.id,finding);
    assert.equal(db.prepare('SELECT count(*) n FROM execution_runs').get().n,0);
    const body={revision:1,fingerprint:detail.plans[0].fingerprint,request_id:'continue-fixture',confirmed:true};
    const attempt=confirmAndStart(db,pipeline,actor,item.id,body);
    const retry=confirmAndStart(db,pipeline,actor,item.id,body);
    assert.equal(retry.id,attempt.id);
    await launchVerification(db,attempt,actor,{engine:{executeRun:async runId=>{
      const run=db.prepare('SELECT * FROM execution_runs WHERE run_id=?').get(runId);
      const linkage=JSON.parse(run.plan_data).finding_verification;
      db.prepare("INSERT INTO execution_steps(run_id,step_index,tool_id,success) VALUES(?,0,'target-request',?)").run(runId,outcome==='confirmed'?1:0);
      const call=Number(db.prepare("INSERT INTO execution_attempts(run_id,step_index,tool_id) VALUES(?,0,'target-request')").run(runId).lastInsertRowid);
      db.prepare(`INSERT INTO evidence_records(run_id,step_index,tool_id,target,attempt_id,evidence_data,raw_stdout)
        VALUES(?,0,'target-request',?,?,?,?)`).run(runId,run.target,call,
        JSON.stringify({success:outcome==='confirmed',exit_code:outcome==='confirmed'?0:1,finding_verification:{...linkage,tool_started:true}}),
        JSON.stringify({url:run.target,method:'GET',connected:true,complete:true,status_code:200,response_headers:{'content-type':'text/html'},response:'<html>Fixture</html>'}));
      db.prepare('UPDATE execution_runs SET status=? WHERE run_id=?').run(outcome==='confirmed'?'COMPLETED':'FAILED',runId);
      return {processStopped:true};
    }}});
    const final = verificationDetail(db,pipeline,item.id);
    assert.equal(final.attempts[0].state,outcome==='confirmed'?'completed':'failed');
    if (outcome==='confirmed') assert.equal(final.summary.conclusion,'confirmed');
    else assert.notEqual(final.summary.conclusion,'confirmed');
    const snapshot=taskResultsSnapshot(db,pipeline);
    assert.equal(snapshot.statistics.report_ready,true);
    assert.equal(snapshot.verification_attempts[0].finding_id,finding);
    const report=createTaskReport(db,pipeline,actor,{source_fingerprint:snapshot.source_fingerprint});
    const same=createTaskReport(db,pipeline,actor,{source_fingerprint:snapshot.source_fingerprint});
    assert.equal(same.report.report_id,report.report.report_id);
    const document=readTaskReport(db,pipeline,report.report.report_id);
    assert.equal(document.report.content.provenance.pipeline_id,context.pipeline_id);
    assert.equal(document.report.content.results.scan_records[0].id,finding);
    assert.equal(document.report.content.results.verification_attempts[0].run_id,attempt.run_id);
    assert.ok((await exportTaskReport(document,'html')).buffer.length>0);
  } finally { db.close(); }
});
