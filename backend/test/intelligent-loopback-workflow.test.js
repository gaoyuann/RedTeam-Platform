import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import express from 'express';
import { fileURLToPath } from 'node:url';
import { getDb, closeDb } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';

// Only the model answer and container selection are controlled. The scanner,
// HTTP probes, curl process, compiler, preflight, executor and reports are real.
await mock.module('../src/tools/containerEngine.js', { namedExports: {
  getEngine: async () => 'host', detectEngine: async () => 'host', resetCache: () => {},
} });
let modelCalls = 0;
await mock.module('../src/services/llmClient.js', { namedExports: {
  callLlm: async messages => {
    modelCalls++;
    let input;
    try { input = JSON.parse(messages.at(-1).content); } catch {}
    if (input?.candidates) {
      if (input.history.length) return { ok: true, content: JSON.stringify({ action: 'finish', reason: '本地观察样例完成' }) };
      const candidate = input.candidates.find(item => item.scan_type === 'app_discovery');
      assert.ok(candidate);
      return { ok: true, content: JSON.stringify({ action: 'execute_check', check_id: candidate.check_id,
        evidence_id: candidate.source_record_id, reason: '读取已声明的本地 HTTP 入口' }) };
    }
    if (messages.at(-1).content.includes('Available tools:')) return { ok: true, content: JSON.stringify({
      name: 'Loopback response observation', description: 'Only observe response headers; no vulnerability claimed',
      target_type: ['any'], baseline_group: 'recon', steps: [0, 1].map(index => ({
        step_id: 'observe_' + index, name: 'Observe actual headers ' + index, tool_id: 'curl',
        args_template: ['--head', '<target>'], inputs: [], outputs: [], score: 0,
      })),
    }) };
    return { ok: true, content: JSON.stringify({ tech_stack: [{ name: 'HTTP' }], attack_surface: [{ name: 'loopback fixture' }],
      risk_assessment: [], recommended_strategy: [{ action: 'Observe response only', tools: ['curl'] }] }) };
  },
  callLlmReact: async () => { throw Error('Reviewed execution must not enter dynamic ReAct'); },
} });
const { default: pipelineRoutes } = await import('../src/routes/pipelines.js');

async function listen(t, server) {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  return 'http://127.0.0.1:' + server.address().port;
}
async function until(check) {
  for (let i = 0; i < 400; i++) {
    const result = await check();
    if (result) return result;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  assert.fail('Real local task did not reach its expected state');
}

for (const workflow of ['original', 'intelligent']) test(`${workflow}: API creation -> actual scan -> review -> real curl -> evidence -> report and export`, async t => {
  modelCalls = 0;
  const db = getDb(':memory:'); t.after(closeDb);
  await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
  db.prepare("INSERT INTO users(username,password,role,is_active) VALUES('loopback-owner','fixture','admin',1)").run();
  const methods = [];
  const target = await listen(t, http.createServer((req, res) => {
    methods.push(req.method); res.writeHead(200, { 'content-type': 'text/html', 'x-fixture': 'loopback-only' });
    res.end('<html><title>Local workflow fixture</title></html>');
  })) + '/';
  const app = express(); app.use(express.json());
  app.use((req, res, next) => { req.user = { sub: 'loopback-owner', role: 'admin' }; next(); });
  app.use('/tasks', pipelineRoutes(db));
  app.use((error, req, res, next) => res.status(error.status || 500).json({ status: 'error', error: { message: error.message } }));
  const endpoint = await listen(t, http.createServer(app));
  const request = async (path, body) => {
    const response = await fetch(endpoint + '/tasks' + path, {
      method: body === undefined ? 'GET' : 'POST', headers: { 'content-type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const result = await response.json();
    assert.ok(response.ok, JSON.stringify(result));
    return result.data;
  };
  const task = await request('', { target, request_id: 'loopback-full-task', config: {
    task_mode: 'assessment', ...(workflow === 'intelligent' ? { workflow_mode: 'intelligent' } : {}), authorization_confirmed: true,
    authorization_scope: target, task_scope: { includes: [target], excludes: [], execution_location: 'scanner', discovery_budget: 0 },
  } });
  await request('/' + task.pipeline_id + '/start', {});
  const row = () => db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(task.pipeline_id);
  await until(() => row().status !== 'running');
  assert.equal(row().status, 'awaiting_approval', row().error_message);
  assert.equal(methods.filter(method => method === 'HEAD').length, 0);
  const scans = db.prepare('SELECT * FROM scan_tasks WHERE pipeline_id=? ORDER BY id').all(task.pipeline_id);
  assert.equal(scans[0].scan_type, 'react_scan');
  assert.ok(scans.some(scan => scan.scan_type === 'app_discovery'));
  let plan = await request('/' + task.pipeline_id + '/plan');
  if (workflow === 'original') {
    assert.equal(plan, null);
    const draft = await request('/' + task.pipeline_id + '/plan', { playbook_id: row().generated_playbook_id });
    plan = await request('/' + task.pipeline_id + '/plan/submit', { revision: draft.revision });
  }
  assert.equal(plan.state, 'submitted');
  assert.equal(plan.content.steps.length, 2);
  await request('/' + task.pipeline_id + '/plan/approve', { revision: plan.revision });
  await until(() => !['running', 'awaiting_approval'].includes(row().status));
  assert.equal(row().status, 'completed', row().error_message);
  assert.equal(methods.filter(method => method === 'HEAD').length, 2);
  const results = await request('/' + task.pipeline_id + '/results');
  assert.equal(results.execution.run.status, 'COMPLETED');
  assert.equal(results.execution.steps.length, 2);
  assert.ok(results.execution.evidence.length >= 2);
  assert.ok(results.execution.steps.every(step => step.state === 'SUCCEEDED' || step.success === true || step.success === 1), JSON.stringify(results.execution.steps));
  const report = await request('/' + task.pipeline_id + '/results/reports', {
    run_id: row().run_id, source_fingerprint: results.source_fingerprint,
  });
  assert.ok(report.report.report_id);
  const exported = await fetch(endpoint + '/tasks/' + task.pipeline_id + '/results/reports/' + report.report.report_id + '/export?format=json');
  assert.equal(exported.status, 200);
  assert.ok((await exported.text()).includes(task.pipeline_id));
  assert.equal(modelCalls, 4);
});
