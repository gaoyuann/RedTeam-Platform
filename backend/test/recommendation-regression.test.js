import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import BetterSqlite3 from 'better-sqlite3';
import createTables from '../src/db/migrations/001_create_tables.js';
import repairDirectoryEnumeration from '../src/db/migrations/028_fix_recon_dir_enum.js';
import { renderCommand } from '../src/services/commandTemplateRenderer.js';
import { normalizeToolArgs } from '../src/tools/toolContracts.js';
import { captureTopologyOrigin, readTopologyOrigin, isLoopbackAddress } from '../src/services/topologyOrigin.js';

const definition = JSON.parse(readFileSync(new URL('../../data/playbooks/recon_dir_enum.json', import.meta.url), 'utf8'));
const legacyArguments = [
  ['-u', '<target>', '-w', 'config/wordlists/course_web_dirs.txt', '-t', '10', '-q', '-fw'],
  ['-u', '<target>', '-w', 'config/wordlists/course_web_dirs.txt', '-s', '403', '-t', '10', '-q', '-fw'],
];

function createFixture() {
  const database = new BetterSqlite3(':memory:');
  database.pragma('foreign_keys = ON');
  createTables(database);
  database.prepare('INSERT INTO playbooks (playbook_id, name, metadata) VALUES (?, ?, ?)')
    .run(definition.id, 'legacy fixture', JSON.stringify({ disableAutoInsert: true }));
  const insertStep = database.prepare(`INSERT INTO playbook_steps
    (playbook_id, step_index, step_id, name, tool_id, args_template, description)
    VALUES (?, ?, ?, ?, ?, ?, ?)`);
  definition.steps.forEach((step, index) => {
    insertStep.run(definition.id, index, step.id, 'legacy fixture', step.toolId, JSON.stringify(legacyArguments[index]), 'legacy fixture');
  });
  return database;
}

test('legacy Gobuster repair is idempotent and leaves execution history unchanged', () => {
  const database = createFixture();
  try {
    database.prepare(`INSERT INTO execution_runs (run_id, playbook_id, target, status, score_data, final_summary)
      VALUES (?, ?, ?, ?, ?, ?)`).run('failed-pikachu-fixture', definition.id, 'http://fixture.invalid:8765',
      'COMPLETED', JSON.stringify({ earned: 0 }), 'historical failure');
    const history = database.prepare('SELECT * FROM execution_runs').all();
    const playbook = database.prepare('SELECT * FROM playbooks').all();
    repairDirectoryEnumeration(database);
    const repaired = database.prepare('SELECT * FROM playbook_steps ORDER BY step_index').all();
    repaired.forEach((step, index) => {
      assert.deepEqual(JSON.parse(step.args_template), definition.steps[index].argsTemplate);
      assert.equal(step.name, definition.steps[index].name);
      assert.equal(step.description, definition.steps[index].description);
    });
    repairDirectoryEnumeration(database);
    assert.deepEqual(database.prepare('SELECT * FROM playbook_steps ORDER BY step_index').all(), repaired);
    assert.deepEqual(database.prepare('SELECT * FROM execution_runs').all(), history);
    assert.deepEqual(database.prepare('SELECT * FROM playbooks').all(), playbook);
  } finally {
    database.close();
  }
});

test('Gobuster migration preserves custom templates and steps assigned to other tools', () => {
  const database = createFixture();
  try {
    database.prepare('UPDATE playbook_steps SET args_template = ? WHERE step_index = 0')
      .run(JSON.stringify(['dir', '-u', '<target>', '-w', '/custom/dictionary.txt']));
    database.prepare("UPDATE playbook_steps SET tool_id = 'curl' WHERE step_index = 1").run();
    const original = database.prepare('SELECT * FROM playbook_steps ORDER BY step_index').all();
    repairDirectoryEnumeration(database);
    assert.deepEqual(database.prepare('SELECT * FROM playbook_steps ORDER BY step_index').all(), original);
    database.prepare('DELETE FROM playbook_steps').run();
    assert.doesNotThrow(() => repairDirectoryEnumeration(database));
  } finally {
    database.close();
  }
});

test('directory templates retain the explicit empty blacklist through command preparation', () => {
  for (const step of definition.steps) {
    const result = renderCommand(step.argsTemplate, { target_url: 'http://fixture.invalid:8765' });
    const prepared = normalizeToolArgs(step.toolId, result.rendered, {
      projectRoot: process.cwd(), engine: 'docker', target: 'http://fixture.invalid:8765',
    });
    assert.deepEqual(result.unresolvedTokens, []);
    assert.equal(prepared[0], 'dir');
    assert.equal(prepared[prepared.indexOf('-u') + 1], 'http://fixture.invalid:8765');
    assert.equal(prepared[prepared.indexOf('-w') + 1], '/usr/share/wordlists/course_web_dirs.txt');
    assert.ok(!prepared.includes('-fw'));
    if (prepared.includes('-s')) {
      assert.ok(prepared.includes('-b'));
      assert.equal(prepared[prepared.indexOf('-b') + 1], '');
    }
  }
});

test('topology origin is derived from the socket, not forwarded headers or client data', () => {
  const origin = captureTopologyOrigin({
    socket: { remoteAddress: '::ffff:192.0.2.112', localAddress: '::ffff:192.0.2.103' },
    headers: { 'x-forwarded-for': '198.51.100.1', 'x-real-ip': '198.51.100.2' },
    body: { topology_origin: { sourceAddress: '198.51.100.3' } },
  });
  assert.equal(origin.sourceAddress, '192.0.2.112');
  assert.equal(origin.serverAddress, '192.0.2.103');
  assert.equal(origin.transport, 'http-request');
  assert.ok(Number.isFinite(Date.parse(origin.capturedAt)));
  assert.deepEqual(readTopologyOrigin(JSON.stringify({ topology_origin: origin })), origin);
});

test('historical topology with no trustworthy origin remains unknown', () => {
  assert.equal(readTopologyOrigin('{invalid'), null);
  assert.equal(readTopologyOrigin({}), null);
  assert.equal(readTopologyOrigin({ topology_origin: { sourceAddress: '192.0.2.112' } }), null);
  const invalid = readTopologyOrigin({ topology_origin: {
    transport: 'http-request', sourceAddress: 'not-an-ip', serverAddress: 'also-invalid',
  } });
  assert.equal(invalid.sourceAddress, '');
  assert.equal(invalid.serverAddress, '');
  assert.equal(isLoopbackAddress('::ffff:127.0.0.1'), true);
  assert.equal(isLoopbackAddress('::1'), true);
  assert.equal(isLoopbackAddress('192.0.2.112'), false);
});
