import test from 'node:test';
import assert from 'node:assert/strict';
import Database from 'better-sqlite3';
import express from 'express';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import { runMigrations } from '../src/db/migrate.js';
import migrateClassification from '../src/db/migrations/040_finding_classifications.js';
import resultRoutes from '../src/routes/taskResults.js';
import { findingClassification } from '../src/services/findingClassificationStore.js';

function classification(id, categories = ['tampering-deception']) {
  return { finding_id: id, categories, reason: '扫描证据描述了未授权修改测试记录的候选风险',
    confidence: 'medium', missing_conditions: ['需要对照账号与权限基准'] };
}

async function fixture(t, count = 2) {
  const db = new Database(':memory:'); db.pragma('foreign_keys=ON');
  await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
  migrateClassification(db); // Repeated application is harmless.
  db.exec(`INSERT INTO users(username,password,role,is_active) VALUES
    ('class_alice','fixture','user',1),('class_bob','fixture','user',1),('class_admin','fixture','admin',1);
    INSERT INTO pipelines(pipeline_id,target,status,created_by,scan_task_id,config) VALUES
    ('class-p','http://classification.invalid','completed','class_alice','class-s','{}'),
    ('class-other','http://other.invalid','completed','class_bob','class-other-s','{}');
    INSERT INTO scan_tasks(scan_task_id,target,scan_type,status,created_by,pipeline_id) VALUES
    ('class-s','http://classification.invalid','vuln_scan','COMPLETED','class_alice','class-p'),
    ('class-other-s','http://other.invalid','vuln_scan','COMPLETED','class_bob','class-other');`);
  const insert = db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool) VALUES(?,?,?,'high','fixture')");
  const ids = Array.from({ length: count }, (_, index) => Number(insert.run('class-s', 'vulnerability',
    JSON.stringify({ title: 'Candidate ' + index, description: '未授权修改测试记录', token: 'fixture-secret-value' })).lastInsertRowid));
  const otherId = Number(insert.run('class-other-s', 'vulnerability', '{"title":"Other task"}').lastInsertRowid);
  const infoId = Number(insert.run('class-s', 'open_port', '{"port":443}').lastInsertRowid);
  let calls = 0;
  const contexts = [];
  const state = { behavior: items => ({ ok: true, content: JSON.stringify({ classifications: items.map(item => classification(item.finding_id)) }) }) };
  const app = express(); app.use(express.json());
  app.use((req, _res, next) => {
    const sub = req.headers['x-fixture-user'] || 'class_alice';
    req.user = { sub, role: sub === 'class_admin' ? 'admin' : 'user' }; next();
  });
  app.use('/api/pipelines/:id/results', resultRoutes(db, { llm: async (messages, options) => {
    ++calls; assert.equal(options.json, true); assert.ok(options.timeoutMs <= 60000);
    assert.match(messages[0].content, /不可信数据/);
    assert.ok(!messages[1].content.includes('fixture-secret-value'));
    const items = JSON.parse(messages[1].content).untrusted_findings; contexts.push(items);
    return state.behavior(items);
  } }));
  app.use((error, _req, res, _next) => res.status(error.status || 500).json({ status: 'error', error: { message: error.message } }));
  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); });
  async function request(path = '/classifications', body, expected = 200, user = 'class_alice', pipeline = 'class-p') {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/pipelines/${pipeline}/results${path}`, {
      method: body === undefined ? 'GET' : 'POST', headers: { 'content-type': 'application/json', 'x-fixture-user': user },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
    const value = await response.json(); assert.equal(response.status, expected, JSON.stringify(value));
    return value;
  }
  return { db, ids, otherId, infoId, state, request, contexts, calls: () => calls };
}

test('classification persists multiple scenarios and unknowns, is cached, and remains independent of verification', async t => {
  const f = await fixture(t);
  f.state.behavior = items => ({ ok: true, content: JSON.stringify({ classifications: items.map((item, index) =>
    classification(item.finding_id, index ? [] : ['data-exfiltration', 'tampering-deception'])) }) });
  const result = (await f.request('/classifications', { finding_ids: f.ids })).data;
  assert.equal(result.generated_count, 2); assert.equal(result.cached_count, 0);
  assert.deepEqual(result.items[0].classification.categories, ['data-exfiltration', 'tampering-deception']);
  assert.equal(result.items[1].classification.state, 'unknown');
  assert.ok(result.items[1].classification.reason);
  assert.equal((await f.request('/classifications', { finding_ids: f.ids })).data.cached_count, 2);
  assert.equal(f.calls(), 1);
  await f.request('/classifications', { finding_ids: f.ids, force: true }); assert.equal(f.calls(), 2);
  const page = (await f.request('?view=scans&category=vulnerability')).data;
  assert.equal(page.scan_records[0].classification.state, 'classified');
  assert.equal(page.scan_records[1].classification.state, 'unknown');
  const details = (await f.request('/records/' + f.ids[0])).data;
  assert.equal(details.record.classification.categories.length, 2);
  assert.equal(f.db.prepare('SELECT count(*) n FROM finding_verifications').get().n, 0);
  assert.equal(f.db.prepare('SELECT count(*) n FROM execution_runs').get().n, 0);
  assert.equal(f.db.prepare('SELECT count(*) n FROM finding_payload_links').get().n, 0);
  assert.equal(f.db.prepare('SELECT count(*) n FROM scan_results').get().n, 4);
  assert.deepEqual(f.db.pragma('foreign_key_check'), []);
});

test('classification enforces ownership, IDs, candidate types and source visibility before calling the model', async t => {
  const f = await fixture(t);
  for (const body of [{}, { finding_ids: [] }, { finding_ids: [f.ids[0], f.ids[0]] }, { finding_ids: [0] },
    { finding_ids: [String(f.ids[0])] }, { finding_ids: f.ids, force: 'true' },
    { finding_ids: f.ids, target: 'http://injected.invalid' }, { finding_ids: Array.from({ length: 31 }, (_, i) => i + 1) }])
    await f.request('/classifications', body, 400);
  await f.request('/classifications', { finding_ids: [f.otherId] }, 404);
  await f.request('/classifications', { finding_ids: [999999] }, 404);
  await f.request('/classifications', { finding_ids: [f.infoId] }, 400);
  await f.request('/classifications', { finding_ids: f.ids }, 403, 'class_bob');
  await f.request('/classifications', { finding_ids: f.ids }, 401, 'missing-user');
  await f.request('/classifications', { finding_ids: f.ids }, 404, 'class_alice', 'missing-task');
  f.db.prepare("UPDATE scan_results SET result_type='source_finding' WHERE id=?").run(f.ids[0]);
  f.db.exec("UPDATE scan_tasks SET scan_type='source_scan',status='RUNNING' WHERE scan_task_id='class-s'");
  await f.request('/classifications', { finding_ids: [f.ids[0]] }, 404);
  f.db.exec("UPDATE scan_tasks SET status='COMPLETED' WHERE scan_task_id='class-s'");
  assert.equal(f.calls(), 0);
  await f.request('/classifications', { finding_ids: f.ids }, 200, 'class_admin');
  assert.equal(f.calls(), 1);
});

test('invalid, incomplete and failed model responses preserve the last valid classification', async t => {
  const f = await fixture(t);
  await f.request('/classifications', { finding_ids: f.ids });
  const original = f.db.prepare('SELECT * FROM finding_classifications ORDER BY finding_id').all();
  const valid = f.ids.map(id => classification(id));
  const replies = [
    { ok: false, error: 'LLM API 401: secret-provider-response' },
    { ok: true, content: 'bad JSON' },
    { ok: true, content: JSON.stringify({ classifications: valid }), finishReason: 'length' },
    ...[valid.slice(0, 1), [valid[0], valid[0]], [valid[0], classification(f.otherId)],
      [valid[0], { ...valid[1], categories: ['invented'] }], [valid[0], { ...valid[1], reason: '' }],
      [valid[0], { ...valid[1], categories: ['device-control', 'device-control'] }],
      [valid[0], { ...valid[1], confidence: '100%' }], [valid[0], { ...valid[1], missing_conditions: [null] }]]
      .map(classifications => ({ ok: true, content: JSON.stringify({ classifications }) })),
  ];
  for (const reply of replies) {
    f.state.behavior = () => reply;
    const response = await f.request('/classifications', { finding_ids: f.ids, force: true }, reply.ok ? 422 : 502);
    assert.ok(!JSON.stringify(response).includes('secret-provider-response'));
    assert.deepEqual(f.db.prepare('SELECT * FROM finding_classifications ORDER BY finding_id').all(), original);
  }
});

test('classification batches all inputs and commits none if a later batch fails', async t => {
  const f = await fixture(t, 30);
  for (const id of f.ids) f.db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify({
    title: 'Candidate ' + id, description: 'Evidence '.repeat(1000) }), id);
  let batch = 0;
  f.state.behavior = items => {
    assert.ok(items.length <= 10);
    assert.ok(items.every(item => item.evidence.length <= 6000 && item.evidence_truncated));
    assert.ok(JSON.stringify(items).length < 18000);
    if (++batch === 3) return { ok: true, content: '{"classifications":[]}' };
    return { ok: true, content: JSON.stringify({ classifications: items.map(item => classification(item.finding_id)) }) };
  };
  await f.request('/classifications', { finding_ids: f.ids }, 422);
  assert.equal(f.db.prepare('SELECT count(*) n FROM finding_classifications').get().n, 0);
  f.state.behavior = items => ({ ok: true, content: JSON.stringify({ classifications: items.map(item => classification(item.finding_id)) }) });
  const result = (await f.request('/classifications', { finding_ids: f.ids })).data;
  assert.equal(result.generated_count, 30);
  assert.ok(result.items.every(item => item.classification.evidence_truncated));
  assert.equal(new Set(f.contexts.slice(3).flat().map(item => item.finding_id)).size, 30);
});

test('changed evidence becomes stale and races, concurrent requests and revoked access cannot save a new result', async t => {
  const f = await fixture(t);
  const id = f.ids[0];
  await f.request('/classifications', { finding_ids: [id] });
  f.db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run('{"title":"New source facts"}', id);
  assert.equal((await f.request('?view=scans')).data.scan_records.find(row => row.id === id).classification.state, 'stale');
  await f.request('/classifications', { finding_ids: [id] }); assert.equal(f.calls(), 2);
  const previous = f.db.prepare('SELECT * FROM finding_classifications WHERE finding_id=?').get(id);
  let started, release;
  let entered = new Promise(resolve => { started = resolve; });
  let gate = new Promise(resolve => { release = resolve; });
  f.state.behavior = async items => { started(); await gate;
    return { ok: true, content: JSON.stringify({ classifications: items.map(item => classification(item.finding_id)) }) }; };
  const pending = f.request('/classifications', { finding_ids: [id], force: true }, 409);
  await entered;
  await f.request('/classifications', { finding_ids: [f.ids[1]] }, 409);
  f.db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run('{"title":"Changed during model call"}', id);
  release(); await pending;
  assert.deepEqual(f.db.prepare('SELECT * FROM finding_classifications WHERE finding_id=?').get(id), previous);
  entered = new Promise(resolve => { started = resolve; }); gate = new Promise(resolve => { release = resolve; });
  const revoked = f.request('/classifications', { finding_ids: [id], force: true }, 401);
  await entered; f.db.exec("UPDATE users SET is_active=0 WHERE username='class_alice'"); release(); await revoked;
  assert.deepEqual(f.db.prepare('SELECT * FROM finding_classifications WHERE finding_id=?').get(id), previous);
  f.db.exec("UPDATE users SET is_active=1 WHERE username='class_alice'");
  f.state.behavior = items => ({ ok: true, content: JSON.stringify({ classifications: items.map(item => classification(item.finding_id, [])) }) });
  await f.request('/classifications', { finding_ids: [id] });
  assert.equal((await f.request('?view=scans')).data.scan_records.find(row => row.id === id).classification.state, 'unknown');
});

test('old databases remain readable and classification records follow source deletion', async t => {
  const f = await fixture(t);
  await f.request('/classifications', { finding_ids: f.ids });
  f.db.prepare('DELETE FROM scan_results WHERE id=?').run(f.ids[0]);
  assert.equal(f.db.prepare('SELECT count(*) n FROM finding_classifications').get().n, 1);
  f.db.exec('DROP TABLE finding_classifications');
  const page = (await f.request('?view=scans&category=vulnerability')).data;
  assert.equal(page.scan_records[0].classification.state, 'unavailable');
  await f.request('/classifications', { finding_ids: [f.ids[1]] }, 503);
  migrateClassification(f.db);
  const row = f.db.prepare('SELECT * FROM scan_results WHERE id=?').get(f.ids[1]);
  assert.equal(findingClassification(f.db, 'class-p', row).state, 'unclassified');
  await f.request('/classifications', { finding_ids: [f.ids[1]] });
  assert.deepEqual(f.db.pragma('foreign_key_check'), []);
});
