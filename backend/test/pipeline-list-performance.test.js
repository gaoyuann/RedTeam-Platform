import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import Database from 'better-sqlite3';
import schema from '../src/db/migrations/001_create_tables.js';
import pipelineSchema from '../src/db/migrations/013_add_pipeline_tables.js';
import pipelineRoutes from '../src/routes/pipelines.js';

test('compact task lists omit large results while preserving scope, filters and legacy responses', async t => {
  const db = new Database(':memory:');
  schema(db);
  pipelineSchema(db);
  for (const username of ['alice', 'bob'])
    db.prepare("INSERT INTO users (username, password, role) VALUES (?, 'fixture', 'user')").run(username);
  const insert = db.prepare(`INSERT INTO pipelines
    (pipeline_id, target, status, created_by, config, analysis_result, result, created_at)
    VALUES (?, 'fixture.invalid', ?, ?, ?, ?, ?, ?)`);
  const largeResult = JSON.stringify({ evidence: 'x'.repeat(512 * 1024) });
  insert.run('alice-old', 'completed', 'alice', '{"task_name":"Old task","test_type":"web"}', largeResult, largeResult, '2026-10-20');
  insert.run('alice-new', 'running', 'alice', 'legacy-invalid-json', largeResult, largeResult, '2026-10-22');
  insert.run('bob-task', 'running', 'bob', '{}', largeResult, largeResult, '2026-10-21');
  const app = express();
  app.use((req, _res, next) => {
    req.user = { sub: 'alice', role: req.headers['x-test-role'] === 'admin' ? 'admin' : 'user' };
    next();
  });
  app.use('/api/pipelines', pipelineRoutes(db));
  const server = app.listen(0, '127.0.0.1');
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    db.close();
  });
  await new Promise(resolve => server.once('listening', resolve));
  const request = async (query = '', role = 'user') => {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/pipelines${query}`, {
      headers: { 'x-test-role': role },
    });
    assert.equal(response.status, 200);
    return response.json();
  };

  const before = db.prepare('SELECT * FROM pipelines ORDER BY id').all();
  const legacy = await request();
  const compact = await request('?view=list');
  assert.deepEqual(compact.data.map(row => row.pipeline_id), ['alice-new', 'alice-old']);
  assert.equal(compact.meta.total, 2);
  for (const row of compact.data) {
    const original = legacy.data.find(entry => entry.pipeline_id === row.pipeline_id);
    for (const [key, value] of Object.entries(row)) assert.equal(value, original[key]);
    for (const key of ['analysis_result', 'result', 'error_message']) assert.equal(Object.hasOwn(row, key), false);
  }
  assert.equal(compact.data[0].config, 'legacy-invalid-json');
  assert.equal(legacy.data[0].analysis_result, largeResult);
  assert.equal(legacy.data[0].result, largeResult);
  assert.ok(Buffer.byteLength(JSON.stringify(compact)) < Buffer.byteLength(JSON.stringify(legacy)) / 100);
  assert.deepEqual((await request('?view=list&status=running')).data.map(row => row.pipeline_id), ['alice-new']);
  assert.equal((await request('?view=list&status=failed')).meta.total, 0);
  assert.equal((await request('?view=list', 'admin')).meta.total, 3);
  assert.deepEqual(await request(), legacy, 'repeated list reads leave legacy responses unchanged');
  assert.deepEqual(db.prepare('SELECT * FROM pipelines ORDER BY id').all(), before);
  t.diagnostic(`fixture JSON bytes: legacy=${Buffer.byteLength(JSON.stringify(legacy))}, compact=${Buffer.byteLength(JSON.stringify(compact))}`);
});
