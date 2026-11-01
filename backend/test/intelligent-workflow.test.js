import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { getDb, closeDb } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';

let scanState, modelFailure, executionFailure, modelCalls, executionCalls, lastFinding;
await mock.module('../src/services/scanAgent.js', { namedExports: {
  runScanAgent: async (db, pipeline) => {
    const id = 'scan-' + pipeline.pipeline_id;
    db.prepare('INSERT INTO scan_tasks(scan_task_id,pipeline_id,target,scan_type,status,created_by) VALUES(?,?,?,?,?,?)')
      .run(id, pipeline.pipeline_id, pipeline.target, 'web_scan', scanState, pipeline.created_by);
    lastFinding = Number(db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool) VALUES(?,?,?,?,?)')
      .run(id, 'web_vuln', JSON.stringify({ finding: 'Missing X-Frame-Options header', url: pipeline.target }), 'low', 'nikto').lastInsertRowid);
    db.prepare('UPDATE pipelines SET scan_task_id=? WHERE pipeline_id=?').run(id, pipeline.pipeline_id);
    return { ok: scanState === 'COMPLETED', cancelled: scanState === 'CANCELLED', scanTaskIds: [id], error: 'fixture scan failed' };
  },
} });
await mock.module('../src/services/llmClient.js', { namedExports: {
  callLlm: async messages => {
    modelCalls++;
    const analysis = messages.at(-1).content.includes('recommended_strategy');
    if (modelFailure === 'analysis' && analysis || modelFailure === 'generation' && !analysis)
      return { ok: false, error: 'fixture model unavailable' };
    if (analysis) return { ok: true, content: JSON.stringify({ tech_stack: [{ name: 'HTTP' }],
      attack_surface: [{ name: 'response headers' }],
      risk_assessment: [{ name: 'Header observation', evidence_ids: [lastFinding] }],
      recommended_strategy: [{ strategy: 'Observe headers; do not infer further impact' }] }) };
    return { ok: true, content: JSON.stringify({ name: 'Fixture header observation', description: 'Observe actual response headers only',
      target_type: ['web_url'], baseline_group: 'recon', steps: [0, 1].map(index => ({
        step_id: 'observe-' + index, name: index ? 'Repeat observation' : 'Read response headers', tool_id: 'curl',
        args_template: ['-I', '<target>'], inputs: [], outputs: [], score: 0,
      })) }) };
  },
} });
// Keep analysis, generation, version freezing, API access and report projection
// real. Tool execution is an isolated fixture, never a request to the target.
await mock.module('../src/services/executionEngine.js', { namedExports: {
  executeRun: async runId => {
    executionCalls++;
    const db = getDb(), run = db.prepare('SELECT * FROM execution_runs WHERE run_id=?').get(runId);
    assert.equal(run.engine_type, 'mechanical');
    assert.ok(JSON.parse(run.plan_data)._task_plan);
    const steps = db.prepare('SELECT * FROM playbook_steps WHERE playbook_id=? ORDER BY step_index').all(run.playbook_id);
    for (const step of steps) {
      db.prepare('INSERT INTO execution_steps(run_id,step_index,tool_id,args,success,exit_code,notes) VALUES(?,?,?,?,?,?,?)')
        .run(runId, step.step_index, step.tool_id, step.args_template, executionFailure ? 0 : 1,
          executionFailure ? 1 : 0, 'fixture response headers');
      db.prepare('INSERT INTO evidence_records(run_id,step_index,tool_id,target,evidence_type,evidence_data) VALUES(?,?,?,?,?,?)')
        .run(runId, step.step_index, step.tool_id, run.target, 'fixture_observation', JSON.stringify({ fixture: true }));
    }
    db.prepare('UPDATE execution_runs SET status=?,stop_reason=?,updated_at=datetime(\'now\') WHERE run_id=?')
      .run(executionFailure ? 'FAILED' : 'COMPLETED', executionFailure ? 'fixture tool failed' : null, runId);
    return { ok: !executionFailure, error: executionFailure ? 'fixture tool failed' : null };
  },
} });
const { default: pipelineRoutes } = await import('../src/routes/pipelines.js');
const { runPipeline, resumePipelineAfterApproval } = await import('../src/services/pipelineEngine.js');

async function fixture(t) {
  scanState = 'COMPLETED'; modelFailure = null; executionFailure = false; modelCalls = executionCalls = 0;
  const db = getDb(':memory:');
  await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
  for (const [username, role] of [['owner', 'user'], ['other', 'user'], ['reviewer', 'admin']])
    db.prepare('INSERT INTO users(username,password,role,is_active) VALUES(?,?,?,1)').run(username, 'fixture', role);
  const app = express(); app.use(express.json());
  app.use((req, res, next) => { const sub = req.headers['x-fixture-user'] || 'owner'; req.user = { sub, role: sub === 'reviewer' ? 'admin' : 'user' }; next(); });
  app.use('/tasks', pipelineRoutes(db));
  app.use((error, req, res, next) => res.status(error.status || 500).json({ status: 'error', error: { message: error.message } }));
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); closeDb(); });
  const request = async (path, body, user = 'owner') => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/tasks${path}`, {
      method: body === undefined ? 'GET' : 'POST', headers: { 'content-type': 'application/json', 'x-fixture-user': user },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    return { status: response.status, body: await response.json() };
  };
  const create = async (config = {}) => {
    const created = await request('', { target: 'http://workflow.invalid/', config: {
      task_mode: 'assessment', workflow_mode: 'intelligent', authorization_confirmed: true,
      authorization_scope: 'Fixture only', auto_execute: true, ...config,
    } });
    assert.equal(created.status, 201, JSON.stringify(created.body));
    return created.body.data.pipeline_id;
  };
  return { db, request, create };
}

for (const failed of [false, true]) test(`intelligent test automatically prepares review, executes frozen version and reports (${failed ? 'failed' : 'completed'} tool)`, async t => {
  const { db, request, create } = await fixture(t); executionFailure = failed;
  const id = await create({ require_approval: false });
  assert.equal((await runPipeline(id)).status, 'awaiting_approval');
  const plan = (await request(`/${id}/plan`)).body.data;
  assert.equal(plan.state, 'submitted'); assert.equal(plan.content.steps.length, 2);
  assert.deepEqual(plan.history.map(row => row.action), ['submit', 'create']);
  assert.match(plan.history[0].note, /系统.*自动/);
  assert.equal(modelCalls, 2); assert.equal(executionCalls, 0);
  assert.equal((await request(`/${id}/approve`, {}, 'reviewer')).status, 409);
  assert.equal((await request(`/${id}/plan/approve`, { revision: plan.revision })).status, 403);
  assert.equal((await request(`/${id}/plan`, undefined, 'other')).status, 403);
  assert.equal((await request(`/${id}/plan/approve`, { revision: plan.revision - 1 }, 'reviewer')).status, 409);
  const source = plan.content.source_playbook_id;
  db.prepare("UPDATE playbook_steps SET name='changed template' WHERE playbook_id=?").run(source);
  assert.equal((await request(`/${id}/plan/approve`, { revision: plan.revision }, 'reviewer')).status, 202);
  for (let i = 0; i < 100 && !executionCalls; i++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(executionCalls, 1);
  const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(id);
  assert.equal(pipeline.status, failed ? 'failed' : 'completed', pipeline.error_message);
  assert.notEqual(pipeline.generated_playbook_id, source);
  assert.equal(db.prepare('SELECT name FROM playbook_steps WHERE playbook_id=? ORDER BY step_index').get(pipeline.generated_playbook_id).name, 'Read response headers');
  assert.equal((await request(`/${id}/plan/approve`, { revision: plan.revision }, 'reviewer')).status, 409);
  assert.equal((await runPipeline(id)).ok, false); assert.equal(executionCalls, 1);
  const results = (await request(`/${id}/results`)).body.data;
  assert.equal(results.execution.run.run_id, pipeline.run_id);
  assert.equal(results.execution.evidence.length, 2);
  assert.ok(results.findings.every(row => row.state === 'unreviewed'));
  const reportBody = { run_id: pipeline.run_id, source_fingerprint: results.source_fingerprint };
  const report = await request(`/${id}/results/reports`, reportBody);
  assert.equal(report.status, 201, JSON.stringify(report.body));
  const again = await request(`/${id}/results/reports`, reportBody);
  assert.equal(again.body.data.report.report_id, report.body.data.report.report_id);
});

for (const failure of ['analysis', 'generation', 'FAILED', 'CANCELLED']) test(`intelligent preparation stops without execution on ${failure}`, async t => {
  const { db, create } = await fixture(t);
  if (['FAILED', 'CANCELLED'].includes(failure)) scanState = failure; else modelFailure = failure;
  const id = await create(); const result = await runPipeline(id);
  assert.equal(result.status, failure === 'CANCELLED' ? 'cancelled' : failure === 'generation' ? 'awaiting_approval' : 'failed');
  // Generation can legitimately fall back to a matching template; it must still
  // produce a submitted review and never run a tool before confirmation.
  if (failure === 'generation') assert.equal((db.prepare('SELECT state FROM task_plans WHERE pipeline_id=?').get(id)).state, 'submitted');
  else assert.equal(db.prepare('SELECT count(*) n FROM task_plans').get().n, 0);
  assert.equal(executionCalls, 0); assert.equal(db.prepare('SELECT count(*) n FROM execution_runs').get().n, 0);
});

test('intelligent mode rejects incompatible tasks and cannot resume without a reviewed plan', async t => {
  const { db, request, create } = await fixture(t);
  assert.equal((await request('', { target: 'http://workflow.invalid/', config: { workflow_mode: 'intelligent', task_mode: 'discovery' } })).status, 400);
  const id = await create();
  db.prepare("UPDATE pipelines SET status='awaiting_approval' WHERE pipeline_id=?").run(id);
  assert.equal((await resumePipelineAfterApproval(id)).ok, false);
  assert.equal(executionCalls, 0);
});

test('failed automatic submission rolls back the plan; generation with no matching template fails visibly', async t => {
  const { db, create } = await fixture(t);
  const unauthorized = await create({ authorization_confirmed: false });
  assert.equal((await runPipeline(unauthorized)).status, 'failed');
  assert.equal(db.prepare('SELECT count(*) n FROM task_plans').get().n, 0);
  assert.match(db.prepare('SELECT error_message FROM pipelines WHERE pipeline_id=?').get(unauthorized).error_message, /授权/);
  modelFailure = 'generation';
  db.prepare('DELETE FROM playbook_steps').run(); db.prepare('DELETE FROM playbooks').run();
  const noTemplate = await create();
  assert.equal((await runPipeline(noTemplate)).status, 'failed');
  assert.equal(db.prepare('SELECT count(*) n FROM task_plans').get().n, 0);
  assert.equal(executionCalls, 0);
});


for (const failed of [false, true]) test(`original workflow reviews a task plan and preserves ${failed ? 'failed' : 'completed'} execution evidence`, async t => {
  const { db, request, create } = await fixture(t); executionFailure = failed;
  const id = await create({ workflow_mode: undefined, require_approval: true });
  assert.equal((await runPipeline(id)).status, 'awaiting_approval');
  const paused = db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(id);
  assert.ok(paused.scan_task_id); assert.ok(paused.generated_playbook_id);
  assert.equal(modelCalls, 2); assert.equal(executionCalls, 0);
  assert.equal((await request(`/${id}/plan`)).body.data, null);
  const draft = await request(`/${id}/plan`, { playbook_id: paused.generated_playbook_id });
  assert.equal(draft.status, 200, JSON.stringify(draft.body));
  const submitted = await request(`/${id}/plan/submit`, { revision: draft.body.data.revision });
  assert.equal(submitted.status, 200, JSON.stringify(submitted.body));
  const revision = submitted.body.data.revision;
  assert.equal((await request(`/${id}/plan/approve`, { revision })).status, 403);
  assert.equal((await request(`/${id}/plan/approve`, { revision: revision - 1 }, 'reviewer')).status, 409);
  assert.equal((await request(`/${id}/plan/approve`, { revision }, 'reviewer')).status, 202);
  for (let i = 0; i < 100 && !executionCalls; i++) await new Promise(resolve => setTimeout(resolve, 5));
  assert.equal(executionCalls, 1);
  const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(id);
  assert.equal(pipeline.status, failed ? 'failed' : 'completed', pipeline.error_message);
  assert.equal(pipeline.scan_task_id, paused.scan_task_id);
  assert.notEqual(pipeline.generated_playbook_id, paused.generated_playbook_id);
  assert.equal((await request(`/${id}/plan/approve`, { revision }, 'reviewer')).status, 409);
  const results = (await request(`/${id}/results`)).body.data;
  assert.equal(results.execution.run.run_id, pipeline.run_id);
  assert.equal(results.execution.evidence.length, 2);
  const body = { run_id: pipeline.run_id, source_fingerprint: results.source_fingerprint };
  const report = await request(`/${id}/results/reports`, body);
  assert.equal(report.status, 201, JSON.stringify(report.body));
  assert.equal((await request(`/${id}/results/reports`, body)).body.data.report.report_id, report.body.data.report.report_id);
});


test('malformed HTTP authority is rejected before a task or scanner is created',async t=>{
 const {db,request}=await fixture(t);
 for(const target of ['http://127.0.0.1;8080','http://127.0.0.1,8080','http://bad_host.invalid:8080']) {
  assert.equal((await request('',{target,config:{task_mode:'assessment'}})).status,400);
 }
 assert.equal(db.prepare('SELECT count(*) n FROM pipelines').get().n,0);
 assert.equal(db.prepare('SELECT count(*) n FROM scan_tasks').get().n,0);
});
