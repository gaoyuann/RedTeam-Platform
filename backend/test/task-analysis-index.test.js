import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import BetterSqlite3 from 'better-sqlite3';
import schema from '../src/db/migrations/001_create_tables.js';
import pipelineTables from '../src/db/migrations/013_add_pipeline_tables.js';
import approvalStatus from '../src/db/migrations/015_add_pipeline_approval_status.js';
import { taskAnalysisIndex } from '../src/services/taskAnalysisIndex.js';

const db = new BetterSqlite3(':memory:');
db.pragma('foreign_keys = ON');
schema(db);
pipelineTables(db);
approvalStatus(db);
after(() => db.close());

for (const [username, role] of [['alice', 'user'], ['bob', 'user'], ['admin', 'admin']]) {
  db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run(username, 'fixture', role);
}

function addTask(identifier, owner, analysis, output = null, target = `${identifier}.invalid`) {
  db.prepare(`INSERT INTO pipelines
      (pipeline_id, target, created_by, status, config, analysis_result, updated_at)
      VALUES (?, ?, ?, 'completed', ?, ?, ?)`)
    .run(identifier, target, owner, JSON.stringify({ task_name: `任务 ${identifier}` }),
      typeof analysis === 'string' ? analysis : JSON.stringify(analysis), '2026-10-10T08:00:00Z');
  if (output !== null) db.prepare(`INSERT INTO pipeline_steps
      (pipeline_id, step_order, step_type, status, output_data) VALUES (?, 0, 'analyze', 'completed', ?)`)
    .run(identifier, JSON.stringify(output));
}

addTask('structured', 'alice', {
  risk_assessment: [{ level: 'high', detail: 'sensitive candidate text' }],
  tech_stack: { detected: 'fixture stack' }, attack_surface: [], recommended_strategy: [],
}, { model: 'fixture' });
addTask('fallback', 'alice', { risk_assessment: [{ level: 'medium' }] }, { fallback: true });
addTask('empty', 'alice', {});
addTask('foreign', 'bob', { risk_assessment: [{ level: 'critical' }] });
addTask('malformed', 'alice', 'not-json');

test('task analysis index scopes owners and exposes counts instead of candidate content', () => {
  const result = taskAnalysisIndex(db, { username: 'alice', role: 'user' }, {});
  assert.equal(result.schema_version, 1);
  assert.equal(result.total, 4);
  assert.ok(result.records.every(record => record.owner === 'alice'));
  const structured = result.records.find(record => record.pipeline_id === 'structured');
  assert.deepEqual(structured.analysis.counts, {
    risk_assessment: 1, tech_stack: 1, attack_surface: 0, recommended_strategy: 0,
  });
  assert.equal(structured.analysis.source, 'structured');
  assert.equal(structured.analysis.total_entries, 2);
  assert.doesNotMatch(JSON.stringify(result), /sensitive candidate text|fixture stack|model/);
});

test('admin, state filters, literal search and pagination remain deterministic', () => {
  assert.equal(taskAnalysisIndex(db, { username: 'admin', role: 'admin' }, {}).total, 5);
  const available = taskAnalysisIndex(db, { username: 'alice', role: 'user' }, { state: 'available' });
  assert.deepEqual(available.records.map(record => record.pipeline_id).sort(), ['fallback', 'structured']);
  assert.equal(available.records.find(record => record.pipeline_id === 'fallback').analysis.source, 'fallback');
  const pending = taskAnalysisIndex(db, { username: 'alice', role: 'user' }, { state: 'pending' });
  assert.deepEqual(pending.records.map(record => record.pipeline_id).sort(), ['empty', 'malformed']);
  assert.equal(taskAnalysisIndex(db, { username: 'alice', role: 'user' }, { search: 'STRUC' }).records[0].pipeline_id, 'structured');
  const page = taskAnalysisIndex(db, { username: 'alice', role: 'user' }, { limit: '1', offset: '1' });
  assert.equal(page.records.length, 1);
  assert.equal(page.total, 4);
  assert.equal(page.offset, 1);
});

test('malformed stored JSON is empty and invalid index queries are rejected', () => {
  const malformed = taskAnalysisIndex(db, { username: 'alice', role: 'user' }, { search: 'malformed' }).records[0];
  assert.equal(malformed.task_name, '任务 malformed');
  assert.equal(malformed.analysis.available, false);
  assert.equal(malformed.analysis.total_entries, 0);
  for (const query of [
    { limit: '0' }, { limit: '101' }, { limit: '1.5' }, { offset: '-1' },
    { offset: '9007199254740992' }, { state: 'other' }, { search: ['array'] }, { search: 'x'.repeat(121) },
  ]) assert.throws(() => taskAnalysisIndex(db, { username: 'alice', role: 'user' }, query), /筛选参数无效/);
});

test('unconfirmed sources stay unknown and display metadata hides common credentials', () => {
  db.transaction(() => {
    addTask('sensitive-%_task', 'alice', { tech_stack: 'reference' }, null,
      'https://name:fixture-password@fixture.invalid/?token=fixture-token');
    db.prepare("UPDATE pipelines SET config=? WHERE pipeline_id='sensitive-%_task'")
      .run(JSON.stringify({ task_name: 'password=fixture-title-secret' }));
    const result = taskAnalysisIndex(db, { username: 'alice', role: 'user' }, { search: '%_' });
    assert.equal(result.records.length, 1);
    assert.equal(result.records[0].analysis.source, 'unknown');
    assert.doesNotMatch(JSON.stringify(result), /fixture-password|fixture-token|fixture-title-secret/);
    assert.equal(taskAnalysisIndex(db, { username: 'alice', role: 'user' }, { search: 'fixture-token' }).total, 0);
    db.prepare("DELETE FROM pipelines WHERE pipeline_id='sensitive-%_task'").run();
  })();
});

test('large index pages preserve identity and leave stored tasks unchanged', () => {
  db.transaction(() => {
    for (let index = 0; index < 105; index++) addTask(`bulk-${String(index).padStart(3, '0')}`, 'alice', {});
    const before = db.prepare('SELECT * FROM pipelines ORDER BY pipeline_id').all();
    const pages = [0, 50, 100].map(offset => taskAnalysisIndex(db,
      { username: 'alice', role: 'user' }, { search: 'bulk-', limit: '50', offset: String(offset) }));
    assert.deepEqual(pages.map(page => page.records.length), [50, 50, 5]);
    assert.ok(pages.every(page => page.total === 105));
    assert.equal(new Set(pages.flatMap(page => page.records.map(record => record.pipeline_id))).size, 105);
    assert.deepEqual(db.prepare('SELECT * FROM pipelines ORDER BY pipeline_id').all(), before);
    db.prepare("DELETE FROM pipelines WHERE pipeline_id LIKE 'bulk-%'").run();
  })();
});
