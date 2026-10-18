import test, { after, mock } from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import express from 'express';
import schema from '../src/db/migrations/001_create_tables.js';
import payloadSchema from '../src/db/migrations/002_add_payload_tables.js';
import findingLinksSchema from '../src/db/migrations/032_finding_payload_links.js';
import { refreshPayloadIndex, getPayloadById, getPayloadList } from '../src/services/payloadLoader.js';
import { compilePlaybook } from '../src/services/playbookCompiler.js';
import { validateExecutionScope } from '../src/services/executionScope.js';
import { findingPayloadSummary, matchPayloads } from '../src/services/findingPayloads.js';

let generated = { name: { zh: '测试验证载荷' }, tool_id: 'nuclei', args: ['-u', '<target>', '-tags', 'sqli'],
  prerequisites: [{ zh: '目标存在 SQL 注入迹象' }] };
let modelCalls = 0;
await mock.module('../src/services/llmClient.js', { namedExports: {
  callLlm: async () => { modelCalls++; return { ok: true, content: JSON.stringify(generated) }; },
} });
const { default: payloadRoutes } = await import('../src/routes/payloads.js');
const { validateGeneratedPayload } = await import('../src/services/payloadGenerator.js');

const db = new Database(':memory:');
db.pragma('foreign_keys = ON');
schema(db);
payloadSchema(db);
findingLinksSchema(db);
db.prepare("INSERT INTO users(username,password,role) VALUES ('alice','x','user'),('bob','x','user'),('admin','x','admin')").run();
db.prepare("INSERT INTO scan_tasks(scan_task_id,target,scan_type,created_by) VALUES ('scan-a','http://fixture.invalid','vuln_scan','alice')").run();
const findingId = Number(db.prepare(`INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool)
  VALUES ('scan-a','sql_injection',?,'high','sqlmap')`).run(JSON.stringify({
    title: 'SQL injection in id', parameter: 'id', url: 'http://fixture.invalid/items',
  })).lastInsertRowid);
const app = express();
app.use(express.json());
app.use((req, _res, next) => { req.user = { sub: req.headers['x-test-user'] || 'alice',
  role: req.headers['x-test-user'] === 'admin' ? 'admin' : 'user' }; next(); });
app.use('/api/payloads', payloadRoutes(db));
const server = app.listen(0);
const base = `http://127.0.0.1:${server.address().port}`;
async function request(path, body, user = 'alice', method = 'POST') {
  const response = await fetch(base + path, { method, headers: { 'content-type': 'application/json', 'x-test-user': user },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  return { code: response.status, body: await response.json() };
}

test('a finding generates once, saves a usable payload, and reuses it on the next request', async () => {
  const first = await request('/api/payloads/resolve', { finding_id: findingId });
  assert.equal(first.code, 200);
  assert.equal(first.body.data.state, 'generated');
  assert.ok(first.body.data.reference_payloads.some(item => item.id.startsWith('sqli-')));
  const payload = first.body.data.payload;
  assert.equal(payload.import_status, 'accepted');
  assert.equal(payload.consumption.type, 'tool_args');
  assert.equal(payload.validation.runtime_verified, false);
  assert.match(first.body.data.catalog_version, /^sha256:/);
  assert.equal(db.prepare('SELECT payload_id FROM finding_payload_links WHERE scan_result_id=? AND active=1').get(findingId).payload_id, payload.id);
  assert.equal(modelCalls, 1);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM finding_payload_links WHERE scan_result_id=?').get(findingId).n, 1);
  refreshPayloadIndex();
  getPayloadList(); // A static-only lookup must not hide accepted DB payloads later.
  assert.equal(getPayloadById(payload.id, db)?.id, payload.id);
  const compiled = compilePlaybook({ db, target: 'http://fixture.invalid', steps: [{
    tool_id: 'nuclei', payload_id: payload.id, args_template: '[]', name: 'verify',
  }] });
  assert.equal(compiled.ok, true);
  assert.deepEqual(compiled.compiledSteps[0].resolved_args, ['-u', 'http://fixture.invalid', '-tags', 'sqli']);
  const wrongTool = compilePlaybook({ db, target: 'http://fixture.invalid', steps: [{
    tool_id: 'nmap', payload_id: payload.id, args_template: '[]', name: 'wrong',
  }] });
  assert.equal(wrongTool.ok, false);
  const second = await request('/api/payloads/resolve', { finding_id: findingId });
  assert.equal(second.body.data.state, 'existing');
  assert.equal(second.body.data.payload.id, payload.id);
  assert.equal(modelCalls, 1);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM finding_payload_links WHERE scan_result_id=?').get(findingId).n, 1);
  assert.equal(findingPayloadSummary(db, db.prepare('SELECT * FROM scan_results WHERE id=?').get(findingId)).status, 'linked');
  const unrelatedId = Number(db.prepare(`INSERT INTO scan_results(scan_task_id,result_type,result_data,severity)
    VALUES ('scan-a','sql_injection',?,'high')`).run(JSON.stringify({
      title: 'SQL injection in id', parameter: 'id', url: 'http://fixture.invalid/other',
    })).lastInsertRowid);
  assert.equal(matchPayloads(db, db.prepare('SELECT * FROM scan_results WHERE id=?').get(unrelatedId))
    .some(candidate => candidate.payload_id === payload.id), false);

  db.prepare("INSERT INTO execution_runs(run_id,status,user_sub,target) VALUES ('alice-run','COMPLETED','alice','http://fixture.invalid'),('bob-run','COMPLETED','bob','http://fixture.invalid')").run();
  const insertEvidence = db.prepare(`INSERT INTO evidence_records(run_id,step_index,tool_id,evidence_type,evidence_data,recorded_at)
    VALUES (?,0,'nuclei','tool',?,'2026-10-18T00:00:00Z')`);
  insertEvidence.run('alice-run', JSON.stringify({ payload_id: payload.id, success: true }));
  insertEvidence.run('bob-run', JSON.stringify({ payload_id: payload.id, success: false }));
  const ownHistory = await request(`/api/payloads/${payload.id}`, undefined, 'alice', 'GET');
  assert.deepEqual(ownHistory.body.data.verification_history.map(row => row.run_id), ['alice-run']);
  const adminHistory = await request(`/api/payloads/${payload.id}`, undefined, 'admin', 'GET');
  assert.deepEqual(adminHistory.body.data.verification_history.map(row => row.run_id), ['bob-run', 'alice-run']);
});

test('ownership, finding type, and invalid model output fail without saving', async () => {
  assert.equal((await request('/api/payloads/resolve', { finding_id: findingId }, 'bob')).code, 403);
  assert.equal((await request('/api/payloads/resolve', { finding_id: 99999 })).code, 404);
  const infoId = Number(db.prepare(`INSERT INTO scan_results(scan_task_id,result_type,result_data,severity)
    VALUES ('scan-a','http_probe','{"title":"web"}','info')`).run().lastInsertRowid);
  assert.equal((await request('/api/payloads/resolve', { finding_id: infoId })).code, 400);
  const otherId = Number(db.prepare(`INSERT INTO scan_results(scan_task_id,result_type,result_data,severity)
    VALUES ('scan-a','vulnerability','{"title":"Other issue"}','high')`).run().lastInsertRowid);
  generated = { name: { zh: 'bad' }, tool_id: 'python3', args: ['-c', 'print(1)'] };
  const bad = await request('/api/payloads/resolve', { finding_id: otherId });
  assert.equal(bad.code, 422);
  assert.match(bad.body.error.message, /校验失败/);
  assert.equal(db.prepare('SELECT COUNT(*) n FROM generated_payloads').get().n, 1);
});

test('bounded HTTP request payloads compile and reject other origins', () => {
  const requestPayload = { name: { zh: '有界 HTTP 验证' }, tool_id: 'target-request',
    args: [JSON.stringify({ url: '<target>/items?id=1', method: 'GET' })] };
  assert.deepEqual(validateGeneratedPayload(requestPayload), []);
  assert.ok(validateGeneratedPayload({ ...requestPayload,
    args: [JSON.stringify({ url: 'http://elsewhere.invalid', method: 'GET' })] }).length);
  assert.ok(validateGeneratedPayload({ ...requestPayload,
    args: [JSON.stringify({ url: '<target>', method: 'DELETE' })] }).length);
  const tcp = { ...requestPayload, args: [JSON.stringify({ url: '<target>', exchanges: [{ send: 'PING\\r\\n' }] })] };
  assert.deepEqual(validateGeneratedPayload(tcp, 'intranet', 'tcp://fixture.invalid:1234'), []);
  assert.ok(validateGeneratedPayload({ ...tcp, tool_id: 'nmap' }, 'intranet', 'tcp://fixture.invalid:1234').length);
  const payloadId = 'ai_http_fixture';
  db.prepare(`INSERT INTO generated_payloads(payload_id,name,payload_type,payload_data,import_status)
    VALUES (?,?,'web',?,'accepted')`).run(payloadId, 'HTTP', JSON.stringify({
    id: payloadId, name: { zh: 'HTTP' }, consumption: { type: 'tool_args', tool_id: 'target-request',
      args_template: requestPayload.args },
  }));
  refreshPayloadIndex();
  const compiled = compilePlaybook({ db, target: 'http://fixture.invalid', steps: [{
    tool_id: 'target-request', payload_id: payloadId, args_template: '[]', name: 'http',
  }] });
  assert.equal(compiled.ok, true);
  assert.equal(validateExecutionScope({ target: 'http://fixture.invalid', toolId: 'target-request',
    args: compiled.compiledSteps[0].resolved_args }).allowed, true);
});

test('legacy review remains admin-only and revoked payloads leave the index', async () => {
  const id = db.prepare('SELECT payload_id FROM generated_payloads LIMIT 1').get().payload_id;
  assert.equal((await request(`/api/payloads/${id}/review`, { status: 'rejected' }, 'alice', 'PUT')).code, 403);
  assert.equal((await request(`/api/payloads/${id}/review`, { status: 'rejected' }, 'admin', 'PUT')).code, 200);
  assert.equal(getPayloadById(id, db), null);
});

after(() => { server.close(); db.close(); refreshPayloadIndex(); });
