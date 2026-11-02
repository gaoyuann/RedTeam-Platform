import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { exec, execFile, spawn as spawnLocal } from 'node:child_process';
import { EventEmitter } from 'node:events';
import { existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { getDb, closeDb } from '../src/db/connection.js';
import { runMigrations } from '../src/db/migrate.js';

let engine = 'docker', calls = [], decisions = [], onSpawn;
await mock.module('../src/tools/containerEngine.js', { namedExports: { getEngine: async () => engine } });
await mock.module('../src/services/preflightGate.js', { namedExports: {
  runPreflightChecks: async () => ({ passed: true, checks: [{
    name: 'target_class_compatibility', passed: true,
    target_profile: { target_class: 'web_url', host: 'fixture.invalid', port: 80, scheme: 'http' },
  }] }),
} });
await mock.module('../src/services/reactEngine.js', { namedExports: {
  determineEngineType: () => 'mechanical',
  reactDecide: async () => ({ thought: 'fixture', ...(decisions.shift() || { action: 'continue' }) }),
} });
// Exercise the real runner's argv and result handling without Docker or a target.
// Simulate the /tmp bind mount using harmless local shell fixtures only.
await mock.module('child_process', { namedExports: { exec, execFile, spawn: (bin, args, options) => {
  assert.ok(['docker', 'podman'].includes(bin));
  if (args[0] === 'rm') {
    const child = new EventEmitter();
    child.kill = () => true;
    queueMicrotask(() => child.emit('close', 0));
    return child;
  }
  const mount = args.find(arg => arg.endsWith(':/tmp'));
  assert.ok(mount, 'each tool container must mount the run temporary directory');
  const directory = mount.slice(0, -':/tmp'.length);
  assert.equal(statSync(directory).mode & 0o777, 0o700);
  assert.ok(args.includes('--rm'));
  assert.ok(args.some(arg => arg.endsWith(':/tmp/redteam-output')));
  const imageIndex = args.findIndex(arg => /^rt-system/.test(arg));
  assert.ok(imageIndex > 0);
  assert.equal(args[imageIndex + 1], 'sh');
  const toolArgs = args.slice(imageIndex + 2);
  calls.push({ directory, args: toolArgs, container: args[args.indexOf('--name') + 1] });
  const child = spawnLocal('sh', toolArgs.map(arg => arg.replaceAll('/tmp/', directory + '/')), options);
  onSpawn?.();
  return child;
} } });

const { executeRun, requestAbort } = await import('../src/services/executionEngine.js');

async function fixture(t, scripts, { optional = false, type = 'mechanical' } = {}) {
  calls = []; decisions = []; onSpawn = undefined; engine = 'docker';
  const db = getDb(':memory:');
  await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
  db.prepare("INSERT INTO playbooks(playbook_id,name,disable_auto_insert) VALUES ('session-fixture','Session fixture',1)").run();
  for (const [index, script] of scripts.entries()) {
    db.prepare(`INSERT INTO playbook_steps(playbook_id,step_index,step_id,name,tool_id,args_template,optional,expected_mitre)
      VALUES ('session-fixture',?,?,?,'system-tools',?,?,'[]')`)
      .run(index, 'step-' + index, 'Fixture ' + index, JSON.stringify(['-c', script]), optional ? 1 : 0);
  }
  const addRun = id => db.prepare(`INSERT INTO execution_runs(run_id,playbook_id,target,status,engine_type)
    VALUES (?,'session-fixture','http://fixture.invalid/','PENDING',?)`).run(id, type);
  addRun('first');
  const original = db.prepare('SELECT * FROM playbook_steps ORDER BY step_index').all();
  t.after(() => {
    try {
      assert.deepEqual(db.prepare('SELECT * FROM playbook_steps ORDER BY step_index').all(), original);
      for (const { directory } of calls) assert.equal(existsSync(directory), false, 'temporary session must be removed');
    } finally { closeDb(); }
  });
  return { db, addRun };
}

test('disposable containers retain legacy /tmp artifacts across steps and isolate concurrent runs', async t => {
  const { db, addRun } = await fixture(t, [
    'test ! -e /tmp/dvwa_jar.txt && echo fixture-$$ > /tmp/dvwa_jar.txt && cat /tmp/dvwa_jar.txt',
    'cat /tmp/dvwa_jar.txt',
  ]);
  addRun('second');
  const results = await Promise.all([executeRun('first'), executeRun('second')]);
  for (const result of results) {
    assert.equal(result.status, 'COMPLETED');
    assert.equal(result.completed, 2);
    assert.equal(result.failed, 0);
  }
  assert.equal(new Set(calls.map(call => call.container)).size, 4);
  const dirs = new Set(calls.map(call => call.directory));
  assert.equal(dirs.size, 2);
  for (const dir of dirs) assert.equal(calls.filter(call => call.directory === dir).length, 2);
  assert.equal(db.prepare('SELECT count(*) n FROM execution_attempts WHERE success=1').get().n, 4);
  const values = [];
  for (const id of ['first', 'second']) {
    const outputs = db.prepare('SELECT stdout FROM execution_attempts WHERE run_id=? ORDER BY step_index').all(id);
    assert.equal(outputs[1].stdout, outputs[0].stdout, 'consumer reads the cookie created by its producer');
    values.push(outputs[0].stdout);
  }
  assert.notEqual(values[0], values[1], 'concurrent producers create different fixture sessions');
  assert.equal((await executeRun('first')).ok, false, 'completed runs cannot replay');
});

test('Podman steps share the run mount and a fresh run cannot inherit an old cookie', async t => {
  const { addRun } = await fixture(t, [
    'test ! -e /tmp/dvwa_jar.txt && echo fresh > /tmp/dvwa_jar.txt',
    'test "$(cat /tmp/dvwa_jar.txt)" = fresh',
  ]);
  engine = 'podman';
  assert.equal((await executeRun('first')).completed, 2);
  const firstDir = calls[0].directory;
  addRun('second');
  assert.equal((await executeRun('second')).completed, 2);
  assert.notEqual(calls[2].directory, firstDir);
});

test('ReAct retry retains run artifacts and immutable source steps', async t => {
  const { db } = await fixture(t, [
    'if test -e /tmp/retry; then echo recovered; else echo created > /tmp/retry; echo "VERIFY_FAILED: retry fixture"; fi',
    'test -e /tmp/retry && echo next-step',
  ], { type: 'react' });
  decisions = [{ action: 'adjust' }];
  const result = await executeRun('first');
  assert.equal(result.completed, 2);
  assert.equal(result.failed, 0);
  assert.equal(calls.length, 3);
  assert.equal(new Set(calls.map(call => call.directory)).size, 1);
  assert.deepEqual(db.prepare('SELECT success FROM execution_attempts ORDER BY id').all().map(row => row.success), [0, 1, 1]);
});

test('business failures persist in attempts and evidence even with exit zero', async t => {
  const { db } = await fixture(t, [
    'echo "DVWA ready (session: fixture, login_ok: 0)"',
    'echo "UPLOAD_RESULT: check server response above"',
    'curl() { echo "<title>404 Not Found</title>"; }; curl http://fixture.invalid/missing',
    'echo "FILE_TAMPER_FAILED: fixture"',
    'echo "VERIFY_FAILED: fixture"',
  ], { optional: true });
  const result = await executeRun('first');
  assert.equal(result.status, 'COMPLETED', 'completion status remains distinct from scoring');
  assert.equal(result.completed, 0);
  assert.equal(result.failed, 5);
  assert.equal(db.prepare('SELECT count(*) n FROM execution_attempts WHERE success=0 AND exit_code=0').get().n, 5);
  for (const row of db.prepare('SELECT evidence_data,mitre_hits FROM evidence_records').all()) {
    const evidence = JSON.parse(row.evidence_data);
    assert.equal(evidence.success, false);
    assert.ok(evidence.error);
    assert.deepEqual(JSON.parse(row.mitre_hits), []);
  }
});

test('required business failure stops later steps and still removes session files', async t => {
  const { db } = await fixture(t, ['echo fixture > /tmp/dvwa_jar.txt; echo "VERIFY_FAILED: fixture"', 'echo must-not-run']);
  const result = await executeRun('first');
  assert.equal(result.failed, 1);
  assert.equal(calls.length, 1);
  const summary = JSON.parse(db.prepare("SELECT final_summary FROM execution_runs WHERE run_id='first'").get().final_summary);
  assert.equal(summary.unexecuted, 1);
  assert.equal(summary.hasNonOptionalFailure, true);
});

test('manual abort stops the child, retains abort status and removes temporary session', async t => {
  await fixture(t, ['exec sleep 30', 'echo must-not-run']);
  onSpawn = () => { onSpawn = undefined; setImmediate(() => requestAbort('first')); };
  const result = await executeRun('first');
  assert.equal(result.status, 'ABORTED');
  assert.equal(calls.length, 1);
});

test('run deadline stops later steps and removes the shared temporary directory', async t => {
  const { db } = await fixture(t, ['exec sleep 30', 'echo must-not-run']);
  const previous = process.env.RUN_TIMEOUT_MS;
  process.env.RUN_TIMEOUT_MS = '60000';
  t.after(() => {
    if (previous === undefined) delete process.env.RUN_TIMEOUT_MS;
    else process.env.RUN_TIMEOUT_MS = previous;
  });
  t.mock.timers.enable({ apis: ['setTimeout'] });
  onSpawn = () => { onSpawn = undefined; setImmediate(() => t.mock.timers.tick(60000)); };
  const result = await executeRun('first');
  assert.equal(result.status, 'FAILED');
  assert.match(result.error, /超时/);
  assert.equal(calls.length, 1);
  assert.equal(JSON.parse(db.prepare("SELECT final_summary FROM execution_runs WHERE run_id='first'").get().final_summary).timeoutAbort, true);
});

test('executor exception removes session directory and reports a runtime failure', async t => {
  await fixture(t, ['echo fixture > /tmp/dvwa_jar.txt'], { type: 'react' });
  decisions.push({ get action() { throw new Error('fixture decision failure'); } });
  const result = await executeRun('first');
  assert.equal(result.status, 'FAILED');
  assert.equal(result.error, 'fixture decision failure');
});
