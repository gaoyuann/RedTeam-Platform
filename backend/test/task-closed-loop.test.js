import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { fileURLToPath } from 'node:url';
import express from 'express';
import BetterSqlite3 from 'better-sqlite3';
import { runMigrations } from '../src/db/migrate.js';
import pipelineRoutes from '../src/routes/pipelines.js';
import taskPlanRoutes from '../src/routes/taskPlans.js';
import { authenticate } from '../src/middleware/auth.js';
import { rbacGuard } from '../src/middleware/rbac.js';
import { generateAccessToken } from '../src/middleware/jwtUtils.js';
import errorHandler from '../src/middleware/errorHandler.js';
import { readTopologyOrigin } from '../src/services/topologyOrigin.js';

const db = new BetterSqlite3(':memory:');
db.pragma('foreign_keys = ON');
const app = express();
app.use(express.json());
const resumed = [];
app.use('/api/pipelines/:id/plan', authenticate, rbacGuard('pipelines'), taskPlanRoutes(db, async () => pipelineId => {
  const plan = db.prepare('SELECT approved_playbook_id FROM task_plans WHERE pipeline_id = ?').get(pipelineId);
  insertExecutionFixture(plan.approved_playbook_id);
  db.prepare("UPDATE pipelines SET status = 'completed', run_id = 'run-closed-loop' WHERE pipeline_id = ?").run(pipelineId);
  db.prepare("UPDATE pipeline_steps SET status = 'completed', output_data = ? WHERE pipeline_id = ? AND step_type = 'execute'")
    .run(JSON.stringify({ run_id: 'run-closed-loop', playbook_id: plan.approved_playbook_id, fixture: true }), pipelineId);
  resumed.push(pipelineId);
  return { ok: true };
}));
app.use('/api/pipelines', authenticate, rbacGuard('pipelines'), pipelineRoutes(db));
app.use(errorHandler);
const server = http.createServer(app);
const tokens = {};

before(async () => {
  await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
  for (const [username, role] of [['alice', 'user'], ['bob', 'user'], ['admin', 'admin']]) {
    db.prepare('INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)').run(username, 'fixture', role);
    tokens[username] = generateAccessToken({ username, role });
  }
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
});

test('task creation and config updates retain only server-observed topology origin', async () => {
  const created = await request('POST', '/api/pipelines', 'alice', {
    target: 'http://topology-fixture.invalid:8765',
    config: { task_name: 'origin fixture', topology_origin: {
      transport: 'http-request', sourceAddress: '192.0.2.199', serverAddress: '192.0.2.198',
    } },
  });
  assert.equal(created.response.status, 201);
  const identifier = created.data.data.pipeline_id;
  try {
    const origin = readTopologyOrigin(db.prepare('SELECT config FROM pipelines WHERE pipeline_id = ?').get(identifier).config);
    assert.equal(origin.sourceAddress, '127.0.0.1');
    assert.equal(origin.serverAddress, '127.0.0.1');
    assert.ok(origin.capturedAt);
    const updated = await request('PUT', `/api/pipelines/${identifier}`, 'alice', {
      config: { task_name: 'updated fixture', topology_origin: {
        transport: 'http-request', sourceAddress: '192.0.2.177',
      } },
    });
    assert.equal(updated.response.status, 200);
    const config = JSON.parse(db.prepare('SELECT config FROM pipelines WHERE pipeline_id = ?').get(identifier).config);
    assert.deepEqual(readTopologyOrigin(config), origin);
    assert.equal(config.task_name, 'updated fixture');
  } finally {
    db.prepare('DELETE FROM pipelines WHERE pipeline_id = ?').run(identifier);
  }
});

after(async () => {
  await new Promise(resolve => server.close(resolve));
  db.close();
});

async function request(method, path, actor, body) {
  const response = await fetch(`http://127.0.0.1:${server.address().port}${path}`, {
    method,
    headers: { authorization: `Bearer ${tokens[actor]}`, 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text; }
  return { response, data };
}

function insertFixturePlaybook() {
  db.prepare(`INSERT INTO playbooks (playbook_id, name, description, target_type, roles_allowed, metadata)
    VALUES ('fixture-plan', '隔离验证预案', '仅用于自动化闭环验证', 'web', 'admin,user', '{}')`).run();
  db.prepare(`INSERT INTO playbook_steps
    (playbook_id, step_index, step_id, name, tool_id, args_template, description, optional)
    VALUES ('fixture-plan', 0, 'fixture-step', '读取隔离页面', 'fixture-tool', ?, '不连接外部目标', 0)`)
    .run(JSON.stringify(['fixture.invalid']));
}

function insertPipelineSteps(pipelineId) {
  const steps = [
    ['scan', 'completed', { scan_task_id: 'scan-closed-loop' }],
    ['analyze', 'completed', { analysis: 'fixture candidate' }],
    ['generate', 'completed', { playbook_id: 'fixture-plan' }],
    ['execute', 'pending', { fixture: true }],
  ];
  const insert = db.prepare(`INSERT INTO pipeline_steps
    (pipeline_id, step_order, step_type, status, input_data, output_data, completed_at)
    VALUES (?, ?, ?, ?, ?, ?, '2026-10-10T08:00:00Z')`);
  steps.forEach(([type, status, output], order) => insert.run(
    pipelineId, order, type, status, JSON.stringify({ fixture: true }), JSON.stringify(output)));
}

function insertExecutionFixture(playbookId) {
  db.prepare(`INSERT INTO execution_runs
    (run_id, playbook_id, status, user_sub, user_role, target, engine_type, preflight_status,
     preflight_data, score_data, final_summary, created_at, updated_at)
    VALUES ('run-closed-loop', ?, 'COMPLETED', 'alice', 'user',
      'fixture.invalid', 'fixture', 'PASSED', '[]', ?, ?, '2026-10-10T08:00:00Z', '2026-10-10T08:01:00Z')`)
    .run(playbookId, JSON.stringify({ ok: true, runId: 'run-closed-loop', percent: 80, earned: 80, total: 100 }),
      JSON.stringify({ result: 'fixture completed' }));
  const attempt = db.prepare(`INSERT INTO execution_attempts
    (run_id, step_index, tool_id, source, args, success, exit_code, stdout, stderr, execution_mode, duration_ms,
     started_at, completed_at)
    VALUES ('run-closed-loop', 0, 'fixture-tool', 'playbook', ?, 1, 0, ?, '', 'fixture', 42,
      '2026-10-10T08:00:10Z', '2026-10-10T08:00:11Z')`)
    .run(JSON.stringify(['fixture.invalid']), 'candidate=not-a-confirmed-vulnerability');
  db.prepare(`INSERT INTO execution_steps
    (run_id, step_index, tool_id, source, success, exit_code, args, notes, attempt_id, executed_at)
    VALUES ('run-closed-loop', 0, 'fixture-tool', 'playbook', 1, 0, ?, '工具结果待人工复核', ?, '2026-10-10T08:00:11Z')`)
    .run(JSON.stringify(['fixture.invalid']), attempt.lastInsertRowid);
  db.prepare(`INSERT INTO evidence_records
    (run_id, step_index, tool_id, evidence_type, evidence_data, raw_stdout, raw_stderr, target, recorded_at, attempt_id)
    VALUES ('run-closed-loop', 0, 'fixture-tool', 'response', ?, ?, '', 'fixture.invalid', '2026-10-10T08:00:11Z', ?)`)
    .run(JSON.stringify({ status_code: 200, note: 'fixture evidence' }), 'response body is not a vulnerability verdict', attempt.lastInsertRowid);
}

test('isolated task closes the loop without crossing owner, target, or evidence boundaries', async context => {
  insertFixturePlaybook();

  const created = await request('POST', '/api/pipelines', 'alice', {
    target: 'fixture.invalid',
    created_by: 'bob',
    config: {
      task_name: '闭环隔离任务',
      auto_execute: true,
      authorization_confirmed: true,
      authorization_scope: '仅限 fixture.invalid 的课堂授权',
      creation_mode: 'quick',
    },
  });
  assert.equal(created.response.status, 201);
  const pipelineId = created.data.data.pipeline_id;
  assert.equal(created.data.data.created_by, 'alice');

  db.prepare(`INSERT INTO scan_tasks
    (scan_task_id, target, scan_type, status, created_by, created_at, completed_at)
    VALUES ('scan-closed-loop', 'fixture.invalid', 'fixture', 'COMPLETED', 'alice',
      '2026-10-10T08:00:00Z', '2026-10-10T08:00:02Z')`).run();
  db.prepare(`INSERT INTO scan_results
    (scan_task_id, result_type, result_data, severity, source_tool, captured_at)
    VALUES ('scan-closed-loop', 'vulnerability', ?, 'medium', 'fixture-scanner', '2026-10-10T08:00:02Z')`)
    .run(JSON.stringify({ name: '扫描候选', host: 'fixture.invalid' }));
  db.prepare(`UPDATE pipelines SET status = 'awaiting_approval', scan_task_id = 'scan-closed-loop',
    analysis_result = ?, generated_playbook_id = 'fixture-plan' WHERE pipeline_id = ?`)
    .run(JSON.stringify({ risk_assessment: [{ name: 'AI 候选', level: 'medium' }] }), pipelineId);
  insertPipelineSteps(pipelineId);

  let result = await request('GET', `/api/pipelines/${pipelineId}`, 'alice');
  assert.equal(result.response.status, 200);
  assert.equal(result.data.data.target, 'fixture.invalid');
  assert.equal(result.data.data.steps.length, 4);
  result = await request('GET', `/api/pipelines/${pipelineId}/steps`, 'alice');
  assert.equal(result.response.status, 200);
  assert.deepEqual(result.data.data.map(step => step.step_type), ['scan', 'analyze', 'generate', 'execute']);

  result = await request('GET', `/api/pipelines/${pipelineId}`, 'bob');
  assert.equal(result.response.status, 403);
  result = await request('GET', `/api/pipelines/${pipelineId}/steps`, 'bob');
  assert.equal(result.response.status, 403);

  result = await request('POST', `/api/pipelines/${pipelineId}/plan`, 'alice', { playbook_id: 'fixture-plan' });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.data.state, 'draft');
  assert.equal(result.data.data.content.target, 'fixture.invalid');
  assert.equal(result.data.data.content.authorization_scope, '仅限 fixture.invalid 的课堂授权');
  const draftRevision = result.data.data.revision;

  result = await request('POST', `/api/pipelines/${pipelineId}/plan/submit`, 'alice', { revision: draftRevision });
  assert.equal(result.response.status, 200);
  assert.equal(result.data.data.state, 'submitted');
  const submittedRevision = result.data.data.revision;
  result = await request('POST', `/api/pipelines/${pipelineId}/plan/submit`, 'alice', { revision: draftRevision });
  assert.equal(result.response.status, 409);

  result = await request('POST', `/api/pipelines/${pipelineId}/plan/approve`, 'alice', { revision: submittedRevision });
  assert.equal(result.response.status, 403);
  assert.equal(resumed.length, 0);
  result = await request('POST', `/api/pipelines/${pipelineId}/plan/approve`, 'admin', {
    revision: submittedRevision, note: '隔离 fixture 通过预案审阅',
  });
  assert.equal(result.response.status, 202);
  const approved = result.data.data;
  assert.equal(approved.state, 'approved');
  assert.equal(approved.revision, submittedRevision + 1);
  const approvedPlaybookId = approved.approved_playbook_id;
  assert.deepEqual(resumed, [pipelineId]);

  result = await request('GET', `/api/pipelines/${pipelineId}/execution`, 'alice');
  assert.equal(result.response.status, 200);
  assert.equal(result.data.data.run.run_id, 'run-closed-loop');
  assert.equal(result.data.data.run.playbook_id, approvedPlaybookId);
  assert.equal(result.data.data.run.approved_snapshot, true);
  assert.equal(result.data.data.steps[0].state, 'SUCCEEDED');
  assert.equal(result.data.data.evidence[0].source_state, 'linked');

  result = await request('GET', `/api/pipelines/${pipelineId}/results`, 'alice');
  assert.equal(result.response.status, 200);
  const snapshot = result.data.data;
  assert.equal(snapshot.pipeline_id, pipelineId);
  assert.equal(snapshot.owner, 'alice');
  assert.equal(snapshot.target, 'fixture.invalid');
  assert.equal(snapshot.trace.plan.source_state, 'verified');
  assert.equal(snapshot.trace.plan.content_revision, submittedRevision);
  assert.equal(snapshot.trace.plan.approval_revision, approved.revision);
  assert.equal(snapshot.findings[0].state, 'unreviewed');
  assert.match(snapshot.assessment.notice, /不等于漏洞成立/);
  assert.equal(snapshot.execution.evidence[0].source_state, 'linked');

  result = await request('POST', `/api/pipelines/${pipelineId}/results/reports`, 'alice', {
    run_id: snapshot.execution.run.run_id,
    source_fingerprint: snapshot.source_fingerprint,
    title: '闭环隔离报告',
  });
  assert.equal(result.response.status, 201);
  const reportId = result.data.data.report.report_id;
  result = await request('GET', `/api/pipelines/${pipelineId}/results/reports/${reportId}`, 'alice');
  assert.equal(result.response.status, 200);
  assert.equal(result.data.data.report.kind, 'trace_snapshot');
  assert.equal(result.data.data.report.content.provenance.pipeline_id, pipelineId);
  assert.equal(result.data.data.report.content.provenance.owner, 'alice');
  assert.match(JSON.stringify(result.data), /候选/);

  const reportFingerprint = result.data.data.report.source_fingerprint;
  assert.equal(result.data.data.report.review, undefined);

  result = await request('GET', `/api/pipelines/${pipelineId}/results/reports/${reportId}/export?format=html`, 'alice');
  assert.equal(result.response.status, 200);
  assert.match(result.response.headers.get('content-type'), /text\/html/);
  assert.match(result.data, /来源链/);
  assert.match(result.data, /不等于漏洞成立/);

  result = await request('GET', `/api/pipelines/${pipelineId}/logs`, 'alice');
  assert.equal(result.response.status, 200);
  assert.ok(result.data.data.some(row => row.message.includes('预案')));

  const auditTypes = db.prepare('SELECT type FROM audit_log WHERE execution_id = ? ORDER BY id').all(pipelineId).map(row => row.type);
  assert.deepEqual(auditTypes, ['pipeline_create', 'task_plan_create', 'task_plan_submit', 'task_plan_approve']);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE type = 'task_report_generate' AND target = 'fixture.invalid'").get());

  await context.test('quick and full creation share identity and authorization contracts', async () => {
    const full = await request('POST', '/api/pipelines', 'alice', {
      target: 'fixture.invalid', created_by: 'bob',
      config: { task_name: '完整隔离任务', creation_mode: 'full', authorization_confirmed: true,
        authorization_scope: '同一目标的独立授权任务', require_approval: true, unknown_key: 'discard' },
    });
    assert.equal(full.response.status, 201);
    assert.notEqual(full.data.data.pipeline_id, pipelineId);
    assert.equal(full.data.data.created_by, 'alice');
    assert.equal(full.data.data.status, created.data.data.status);
    assert.equal(full.data.data.config.authorization_confirmed, true);
    assert.equal(full.data.data.config.creation_mode, 'full');
    assert.equal(full.data.data.config.unknown_key, undefined);
    const otherId = full.data.data.pipeline_id;
    const otherResults = await request('GET', `/api/pipelines/${otherId}/results`, 'alice');
    assert.equal(otherResults.response.status, 200);
    assert.equal(otherResults.data.data.execution.run, null);
    assert.deepEqual(otherResults.data.data.reports, []);
    const otherReport = await request('GET', `/api/pipelines/${otherId}/results/reports/${reportId}`, 'alice');
    assert.equal(otherReport.response.status, 409);
  });

  await context.test('foreign actors cannot read or mutate any task stage', async () => {
    const beforeAudit = db.prepare('SELECT COUNT(*) AS count FROM audit_log').get().count;
    const beforePlan = db.prepare('SELECT * FROM task_plans WHERE pipeline_id = ?').get(pipelineId);
    for (const [method, suffix, body] of [
      ['GET', '', undefined], ['GET', '/steps', undefined], ['GET', '/logs', undefined],
      ['GET', '/plan', undefined], ['GET', '/execution', undefined], ['GET', '/results', undefined],
      ['GET', '/report', undefined], ['GET', `/results/reports/${reportId}`, undefined],
      ['GET', `/results/reports/${reportId}/export?format=json`, undefined],
      ['PUT', '', { config: { task_name: 'foreign' } }], ['DELETE', '', undefined],
      ['POST', '/start', {}], ['POST', '/cancel', {}], ['POST', '/approve', {}],
      ['POST', '/assistant', { message: 'fixture question' }],
      ['POST', '/plan/approve', { revision: approved.revision }],
      ['POST', '/results/reports', { run_id: 'run-closed-loop', source_fingerprint: reportFingerprint }],
    ]) {
      const denied = await request(method, `/api/pipelines/${pipelineId}${suffix}`, 'bob', body);
      assert.equal(denied.response.status, 403, `${method} ${suffix}`);
      assert.doesNotMatch(JSON.stringify(denied.data), /fixture evidence|闭环隔离报告|AI 候选/);
    }
    const foreignList = await request('GET', '/api/pipelines', 'bob');
    assert.ok(foreignList.data.data.every(row => row.created_by === 'bob'));
    const foreignIndex = await request('GET', '/api/pipelines/analysis-index', 'bob');
    assert.equal(foreignIndex.data.data.total, 0);
    const adminSteps = await request('GET', `/api/pipelines/${pipelineId}/steps`, 'admin');
    assert.equal(adminSteps.response.status, 200);
    assert.equal(adminSteps.data.data.length, 4);
    const missing = await request('GET', '/api/pipelines/missing/steps', 'alice');
    assert.equal(missing.response.status, 404);
    const unauthenticated = await request('GET', `/api/pipelines/${pipelineId}/steps`, 'missing');
    assert.equal(unauthenticated.response.status, 401);
    assert.equal(db.prepare('SELECT COUNT(*) AS count FROM audit_log').get().count, beforeAudit);
    assert.deepEqual(db.prepare('SELECT * FROM task_plans WHERE pipeline_id = ?').get(pipelineId), beforePlan);
    assert.deepEqual(resumed, [pipelineId]);
  });

  await context.test('owner and target mismatches never become task evidence', async () => {
    for (const [identifier, owner, target] of [
      ['foreign-scan', 'bob', 'fixture.invalid'], ['other-target-scan', 'alice', 'other.invalid'],
    ]) {
      db.prepare(`INSERT INTO scan_tasks (scan_task_id, target, scan_type, status, created_by)
        VALUES (?, ?, 'fixture', 'COMPLETED', ?)`).run(identifier, target, owner);
      db.prepare(`INSERT INTO scan_results (scan_task_id, result_type, result_data, source_tool)
        VALUES (?, 'vulnerability', ?, 'fixture')`).run(identifier, JSON.stringify({ name: identifier, host: target }));
    }
    db.prepare('UPDATE pipelines SET scan_task_id = ? WHERE pipeline_id = ?')
      .run('scan-closed-loop,foreign-scan,other-target-scan,missing,scan-closed-loop', pipelineId);
    const scoped = await request('GET', `/api/pipelines/${pipelineId}/results`, 'alice');
    assert.equal(scoped.response.status, 200);
    assert.deepEqual(scoped.data.data.trace.scan_sources.map(row => row.scan_task_id), ['scan-closed-loop']);
    assert.doesNotMatch(JSON.stringify(scoped.data.data.findings), /foreign-scan|other-target-scan/);
    for (const [owner, target] of [['bob', 'fixture.invalid'], ['alice', 'other.invalid']]) {
      db.prepare("UPDATE execution_runs SET user_sub = ?, target = ? WHERE run_id = 'run-closed-loop'").run(owner, target);
      for (const stage of ['execution', 'results']) {
        const mismatch = await request('GET', `/api/pipelines/${pipelineId}/${stage}`, 'alice');
        assert.equal(mismatch.response.status, 409);
        assert.doesNotMatch(JSON.stringify(mismatch.data), /fixture evidence/);
      }
    }
    db.prepare("UPDATE execution_runs SET user_sub = 'alice', target = 'fixture.invalid' WHERE run_id = 'run-closed-loop'").run();
    db.prepare("UPDATE pipelines SET scan_task_id = 'scan-closed-loop' WHERE pipeline_id = ?").run(pipelineId);
  });

  await context.test('reports are generated directly and the removed review endpoint is unavailable', async () => {
    const document = await request('GET', `/api/pipelines/${pipelineId}/results/reports/${reportId}`, 'alice');
    assert.equal(document.response.status, 200);
    assert.equal(document.data.data.report.review, undefined);
    assert.equal(document.data.data.report.status, 'draft');
    assert.ok(document.data.data.report.content.results.findings.every(row => row.state === 'unreviewed'));
    const removed = await request('POST', `/api/pipelines/${pipelineId}/results/reports/${reportId}/review`, 'admin', { action: 'approve' });
    assert.equal(removed.response.status, 404);
  });

  await context.test('stale source fingerprints cannot overwrite frozen reports', async () => {
    const beforeContent = db.prepare('SELECT content FROM test_reports WHERE report_id = ?').get(reportId).content;
    const reused = await request('POST', `/api/pipelines/${pipelineId}/results/reports`, 'alice', {
      run_id: 'run-closed-loop', source_fingerprint: reportFingerprint,
    });
    assert.equal(reused.response.status, 200);
    assert.equal(reused.data.data.reused, true);
    assert.equal(reused.data.data.report.report_id, reportId);
    db.prepare("UPDATE execution_attempts SET stdout = 'late fixture evidence' WHERE run_id = 'run-closed-loop'").run();
    const stale = await request('POST', `/api/pipelines/${pipelineId}/results/reports`, 'alice', {
      run_id: 'run-closed-loop', source_fingerprint: reportFingerprint,
    });
    assert.equal(stale.response.status, 409);
    const current = await request('GET', `/api/pipelines/${pipelineId}/results`, 'alice');
    assert.notEqual(current.data.data.source_fingerprint, reportFingerprint);
    const fresh = await request('POST', `/api/pipelines/${pipelineId}/results/reports`, 'alice', {
      run_id: 'run-closed-loop', source_fingerprint: current.data.data.source_fingerprint,
    });
    assert.equal(fresh.response.status, 201);
    assert.notEqual(fresh.data.data.report.report_id, reportId);
    assert.equal(db.prepare('SELECT content FROM test_reports WHERE report_id = ?').get(reportId).content, beforeContent);
    const jsonExport = await request('GET', `/api/pipelines/${pipelineId}/results/reports/${reportId}/export?format=json`, 'alice');
    assert.equal(jsonExport.response.status, 200);
    assert.equal(jsonExport.response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal(jsonExport.data.report.review, undefined);
    assert.equal(jsonExport.data.report.source_fingerprint, reportFingerprint);
    const unsupported = await request('GET', `/api/pipelines/${pipelineId}/results/reports/${reportId}/export?format=pdf`, 'alice');
    assert.equal(unsupported.response.status, 400);
  });
  await context.test('full scan report appendix keeps over 200 records and stable source IDs',async()=>{
    const insert=db.prepare("INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool) VALUES ('scan-closed-loop','vulnerability',?,'high','fixture')");
    for(let i=0;i<230;i++) insert.run(JSON.stringify({finding:'full-appendix-'+i}));
    const snapshot=await request('GET',`/api/pipelines/${pipelineId}/results`,'alice');
    assert.equal(snapshot.response.status,200);
    assert.equal(snapshot.data.data.scan_records.length,100,'API page remains bounded');
    assert.ok(snapshot.data.data.scan_summary.record_count>=230);
    const created=await request('POST',`/api/pipelines/${pipelineId}/results/reports`,'alice',{
      run_id:'run-closed-loop',source_fingerprint:snapshot.data.data.source_fingerprint});
    assert.equal(created.response.status,201);
    const id=created.data.data.report.report_id;
    const report=await request('GET',`/api/pipelines/${pipelineId}/results/reports/${id}/export?format=json`,'alice');
    assert.equal(report.response.status,200);
    const records=report.data.report.content.results.scan_records;
    assert.equal(records.length,snapshot.data.data.scan_summary.record_count);
    assert.ok(records.some(row=>row.result_data.includes('full-appendix-229')));
    assert.equal(new Set(records.map(row=>row.id)).size,records.length);
    assert.equal(report.data.report.content.results.scan_summary.deduplicated,false);
  });
  assert.deepEqual(db.pragma('foreign_key_check'), []);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM task_report_reviews WHERE report_id = ?").get(reportId).count, 0);
  assert.ok(db.prepare("SELECT 1 FROM audit_log WHERE type = 'task_report_export' AND execution_id = ?").get(reportId));
});
