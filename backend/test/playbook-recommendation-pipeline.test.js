import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import { getDb, closeDb } from '../src/db/connection.js';
import schema from '../src/db/migrations/001_create_tables.js';
import importPlaybooks from '../src/db/migrations/003_import_playbooks.js';
import pipelineSchema from '../src/db/migrations/013_add_pipeline_tables.js';
import scanProfile from '../src/db/migrations/020_scan_target_profile.js';
import targetClassMigration from '../src/db/migrations/011_add_target_class.js';
import approvalMigration from '../src/db/migrations/015_add_pipeline_approval_status.js';

let includeInjection = false;
let executionCalls = 0;
await mock.module('../src/services/scanExecutor.js', { namedExports: {
  executeScan: async identifier => {
    const db = getDb();
    const task = db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(identifier);
    const findings = task.scan_type === 'port_scan'
      ? [['open_port', { port: 80 }, 'nmap']]
      : task.scan_type === 'app_discovery'
        ? [['http_probe', { url: task.target, status_code: 200, title: 'SQL Injections' }, 'httpx']]
        : [['web_vuln', { finding: 'Missing X-Frame-Options header' }, 'nikto'],
          ['web_vuln', { finding: 'Directory indexing found.' }, 'nikto']];
    if (task.scan_type === 'web_scan' && includeInjection) findings.push(['sql_injection', {}, 'sqlmap']);
    for (const [type, data, tool] of findings) {
      db.prepare('INSERT INTO scan_results (scan_task_id,result_type,result_data,severity,source_tool) VALUES (?,?,?,?,?)')
        .run(identifier, type, JSON.stringify(data), 'medium', tool);
    }
    db.prepare("UPDATE scan_tasks SET status='COMPLETED', started_at=?, completed_at=? WHERE scan_task_id=?")
      .run(new Date().toISOString(), new Date().toISOString(), identifier);
    return { status: 'COMPLETED' };
  },
  requestScanAbort: () => {},
} });
await mock.module('../src/services/scanAnalyzer.js', { namedExports: {
  analyzeScanResults: async () => ({ ok: true, data: { tech_stack: [], attack_surface: [], risk_assessment: [] } }),
} });
await mock.module('../src/services/playbookGenerator.js', { namedExports: {
  generatePlaybook: async () => ({ ok: false, error: 'fixture: generation unavailable' }),
} });
await mock.module('../src/services/executionEngine.js', { namedExports: {
  executeRun: async identifier => {
    executionCalls++;
    getDb().prepare("UPDATE execution_runs SET status='COMPLETED' WHERE run_id=?").run(identifier);
    return { ok: true };
  },
} });
const { runPipeline } = await import('../src/services/pipelineEngine.js');
const { default: pipelineRoutes } = await import('../src/routes/pipelines.js');

function createDatabase() {
  const db = getDb(':memory:');
  schema(db);
  importPlaybooks(db);
  pipelineSchema(db);
  approvalMigration(db);
  targetClassMigration(db);
  scanProfile(db);
  db.exec('ALTER TABLE execution_runs ADD COLUMN scan_task_id TEXT');
  db.prepare("INSERT INTO users (username,password,role) VALUES ('alice','test','user')").run();
  return db;
}

async function runFixture(identifier, target, injection) {
  includeInjection = injection;
  executionCalls = 0;
  const db = createDatabase();
  db.prepare('INSERT INTO pipelines (pipeline_id,target,status,config,created_by) VALUES (?,?,?,?,?)')
    .run(identifier, target, 'created', JSON.stringify({ require_approval: false }), 'alice');
  const result = await runPipeline(identifier);
  const generationStep = db.prepare("SELECT output_data FROM pipeline_steps WHERE pipeline_id=? AND step_type='generate'").get(identifier);
  assert.ok(generationStep, JSON.stringify({ result, steps: db.prepare('SELECT * FROM pipeline_steps').all() }));
  const generation = JSON.parse(generationStep.output_data);
  return { db, result, generation };
}

test('configuration-only pipeline retains candidates and pauses instead of treating a scanner as an attack route', async () => {
  try {
    const { db, result, generation } = await runFixture('configuration', 'http://example.test/', false);
    assert.equal(result.status, 'awaiting_approval');
    assert.equal(executionCalls, 0);
    assert.ok(generation.recommendations.length > 1);
    assert.equal(generation.ai_generation_error, 'fixture: generation unavailable');
    assert.ok(generation.recommendations.every(candidate => !candidate.automatic_eligible));
    assert.ok(!generation.recommendations.some(candidate => candidate.playbook_id === 'http_flood_dos'));
    assert.equal(generation.selected_recommendation.playbook_id, generation.playbook_id);
    assert.ok(generation.recommendations.every(candidate => candidate.match_evidence.every(signal => signal.scan_task_id)));
    const nikto = generation.recommendations.find(candidate => candidate.playbook_id === 'web_server_scan_nikto');
    assert.equal(nikto.match_status, 'already_checked');
    assert.equal(db.prepare("SELECT status FROM pipelines WHERE pipeline_id='configuration'").get().status, 'awaiting_approval');
  } finally { closeDb(); }
});

test('SQL signal at a homepage requires input and approval endpoint refuses silent execution', async () => {
  let server;
  try {
    const { db, result, generation } = await runFixture('missing-entry', 'http://example.test/', true);
    assert.equal(result.status, 'awaiting_approval');
    assert.equal(generation.playbook_id, 'web_sqli_verify');
    assert.equal(generation.selected_recommendation.match_status, 'needs_input');
    const app = express();
    app.use(express.json());
    app.use((req, res, next) => { req.user = { sub: 'alice', role: 'user' }; next(); });
    app.use('/api/pipelines', pipelineRoutes(db));
    server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/pipelines/missing-entry/approve`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}',
    });
    assert.equal(response.status, 409);
    assert.match((await response.json()).error.message, /具体带参数/);
    assert.equal(executionCalls, 0);
    assert.equal(db.prepare("SELECT status FROM pipelines WHERE pipeline_id='missing-entry'").get().status, 'awaiting_approval');
  } finally {
    if (server) {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
    closeDb();
  }
});

test('SQL indication with selected parameter entry remains eligible for normal pipeline execution', async () => {
  try {
    const { result, generation } = await runFixture('selected-entry', 'http://example.test/Less-1/?id=1', true);
    assert.equal(result.status, 'completed');
    assert.equal(generation.playbook_id, 'web_sqli_verify');
    assert.equal(generation.selected_recommendation.automatic_eligible, true);
    assert.equal(executionCalls, 1);
  } finally { closeDb(); }
});
