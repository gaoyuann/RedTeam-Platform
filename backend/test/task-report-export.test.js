import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import Database from 'better-sqlite3';
import express from 'express';
import JSZip from 'jszip';
import { PDFDocument, PDFName, PDFRawStream, decodePDFRawStream } from 'pdf-lib';
import fontkit from '@pdf-lib/fontkit';
import { runMigrations } from '../src/db/migrate.js';
import { syncInstances } from '../src/services/findingInstances.js';
import { buildVerificationContract } from '../src/services/findingVerificationResult.js';
import { createTaskReport, readTaskReport, taskResultsSnapshot } from '../src/services/taskResults.js';
import { buildTaskReportSections, exportTaskReport, MAX_TASK_REPORT_EXPORT_BYTES } from '../src/services/taskReportExport.js';
import { buildTaskAttackReportData } from '../src/services/taskAttackReport.js';
import { parseCppcheck } from '../src/services/sourceToolParsers.js';
import taskRoutes from '../src/routes/taskResults.js';
import reportRoutes from '../src/routes/reports.js';

const actor = { sub: 'report-alice', role: 'user' };
const mime = {
  json: 'application/json', html: 'text/html', pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
};
const reportHeadings = ['本次攻击测试概况', '逐漏洞攻击效果表', '攻击测试结论'];
const attackHeaders = ['漏洞及位置', '实施操作', '预期效果', '实际效果与证据', '结果'];
const resultLabels = { achieved: '达到预期效果', not_achieved: '未达到预期效果',
  inconclusive: '证据不足', not_performed: '未开展适用攻击测试', pending: '进行中' };

async function fixture({ legacy = false, withRun = false, records = 1 } = {}) {
  const db = new Database(':memory:');
  db.pragma('foreign_keys = ON');
  await runMigrations(db, fileURLToPath(new URL('../src/db/migrations/', import.meta.url)));
  for (const [name, role] of [['report-alice', 'user'], ['report-bob', 'user'], ['report-admin', 'admin']]) {
    db.prepare("INSERT INTO users(username,password,role) VALUES (?,'fixture',?)").run(name, role);
  }
  db.prepare(`INSERT INTO pipelines(pipeline_id,target,status,created_by,config)
    VALUES ('report-task','http://192.0.2.10/','completed','report-alice',?)`)
    .run(JSON.stringify({ task_name: '中文报告隔离测试', task_scope: { includes: ['http://192.0.2.10/'], excludes: [], execution_location: 'scanner' } }));
  db.prepare(`INSERT INTO scan_tasks(scan_task_id,scan_type,target,status,created_by,pipeline_id)
    VALUES ('report-scan','web_scan','http://192.0.2.10/','COMPLETED','report-alice','report-task')`).run();
  const insert = db.prepare(`INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool)
    VALUES ('report-scan','web_vuln',?,'high','fixture-scanner')`);
  for (let index = 0; index < records; index++) {
    insert.run(JSON.stringify({ name: '中文扫描记录-' + index, url: 'http://192.0.2.10/item/' + index,
      method: 'GET', rule_id: 'fixture-' + index,
      description: index === records - 1 ? '长中文内容需要完整换行并在跨页后保留。'.repeat(35) + '末条中文哨兵' : '保存时的扫描内容' }));
  }
  if (withRun || legacy) {
    db.prepare(`INSERT INTO execution_runs(run_id,target,user_sub,status,score_data)
      VALUES ('report-run','http://192.0.2.10/','report-alice','COMPLETED',?)`)
      .run(JSON.stringify({ ok: true, runId: 'report-run', percent: 73, earned: 73, total: 100 }));
    db.prepare("UPDATE pipelines SET run_id='report-run' WHERE pipeline_id='report-task'").run();
    const attempt = db.prepare(`INSERT INTO execution_attempts(run_id,step_index,tool_id,success,exit_code,stdout)
      VALUES ('report-run',0,'fixture-tool',1,0,'保存时的工具输出')`).run();
    db.prepare(`INSERT INTO execution_steps(run_id,step_index,tool_id,success,exit_code,attempt_id)
      VALUES ('report-run',0,'fixture-tool',1,0,?)`).run(attempt.lastInsertRowid);
    db.prepare(`INSERT INTO evidence_records(run_id,step_index,tool_id,evidence_type,evidence_data,raw_stdout,target,attempt_id,mitre_hits,recommendations)
      VALUES ('report-run',0,'fixture-tool','response','{}','保存时的证据','http://192.0.2.10/',?,?,?)`)
      .run(attempt.lastInsertRowid, JSON.stringify([{ id: 'T1190', name: '保存时的标签' }]), JSON.stringify(['保存时的修复建议']));
  }
  const pipeline = db.prepare("SELECT * FROM pipelines WHERE pipeline_id='report-task'").get();
  syncInstances(db, pipeline);
  const snapshot = taskResultsSnapshot(db, pipeline);
  let reportId;
  if (legacy) {
    const { statistics, instances, coverage_checks, baseline, verification_attempts, reports, ...results } = snapshot;
    const content = { schema_version: 1, type: 'task_result_report', notice: '历史冻结快照',
      provenance: { pipeline_id: pipeline.pipeline_id, owner: pipeline.created_by, target: pipeline.target,
        run_id: pipeline.run_id, source_fingerprint: snapshot.source_fingerprint }, results };
    reportId = 'legacy-task-report';
    db.prepare(`INSERT INTO test_reports(report_id,title,run_id,template,status,content,generated_by)
      VALUES (?,'历史中文报告','report-run','task_trace_v1','draft',?,'report-alice')`).run(reportId, JSON.stringify(content));
  } else {
    reportId = createTaskReport(db, pipeline, actor, { run_id: pipeline.run_id || null,
      source_fingerprint: snapshot.source_fingerprint }).report.report_id;
  }
  const document = readTaskReport(db, pipeline, reportId);
  const stored = () => db.prepare('SELECT content FROM test_reports WHERE report_id=?').get(reportId).content;
  let server;
  return { db, pipeline, reportId, document, stored,
    async start() {
      const app = express();
      app.use(express.json());
      app.use((req, res, next) => {
        const sub = req.headers['x-actor'] || actor.sub;
        req.user = { sub, role: db.prepare('SELECT role FROM users WHERE username=?').get(sub)?.role || 'user' };
        next();
      });
      app.use('/api/pipelines/:id/results', taskRoutes(db));
      app.use('/api/reports', reportRoutes(db));
      app.use((error, req, res, next) => res.status(error.status || 500).json({ status: 'error', error: { message: error.message } }));
      server = app.listen(0, '127.0.0.1');
      await new Promise(resolve => server.once('listening', resolve));
      return 'http://127.0.0.1:' + server.address().port;
    },
    async close() {
      if (server) await new Promise(resolve => server.close(resolve));
      db.close();
    },
  };
}

async function docxXml(buffer) {
  const zip = await JSZip.loadAsync(buffer);
  assert.ok(zip.file('[Content_Types].xml'));
  return zip.file('word/document.xml').async('string');
}

function briefSections(document) {
  const sections = buildTaskReportSections(document);
  assert.deepEqual(sections.map(section => section.title), reportHeadings);
  assert.deepEqual(sections[1].headers, attackHeaders);
  assert.ok(sections[1].rows.every(row => row.length === 5));
  assert.deepEqual(document.presentation, { schema_version: 1, title: '任务攻击测试结果报告', sections });
  return sections;
}

function changeFrozen(f, change) {
  const content = JSON.parse(f.stored());
  change(content.results);
  f.db.prepare('UPDATE test_reports SET content=? WHERE report_id=?').run(JSON.stringify(content), f.reportId);
  return readTaskReport(f.db, f.pipeline, f.reportId);
}

function attackView({ finding = 1, id = 'saved-attempt-1', target = 'http://192.0.2.10/saved-entry',
  status = 'achieved', sourceValid = true, createdAt = '2026-10-19T00:00:00Z' } = {}) {
  const contract = buildVerificationContract({ target, steps: [{ step_id: 'check', step_index: 0,
    tool_id: 'target-request', name: '检查保存入口的安全响应头', consumption: 'none' }],
    assessment_rule: { id: 'f08-web-headers-v1', version: 1, kind: 'headers', step_id: 'check',
      target, attribute: 'nosniff', limitations: '仅证明保存入口的指定响应头配置' } }, finding);
  const started = status !== 'not_performed';
  return { id, finding_id: finding, run_id: 'saved-verification-run-' + id, revision: 3,
    state: 'completed', stop_confirmed: true, started, source_valid: sourceValid,
    created_at: createdAt, completed_at: createdAt,
    conclusion: status === 'achieved' ? 'confirmed' : status === 'not_achieved' ? 'not_verified' : 'pending',
    result: { schema_version: 1, status, reason: status === 'achieved' ? '响应缺少指定防护响应头'
      : status === 'not_achieved' ? '响应包含指定防护响应头' : '预检阻止适用操作',
    reason_code: status === 'achieved' ? 'criteria_met' : status === 'not_achieved' ? 'negative_criteria_met' : 'not_started',
    object: contract.object, objective: contract.objective, criterion: contract.criterion,
    evidence_ids: started ? [12] : [],
    operations: contract.operations.map(operation => ({ ...operation, started, evidence_ids: started ? [12] : [] })),
    observed_facts: started ? [{ evidence_id: 12, url: target, method: 'GET', status_code: 200, complete: true }] : [],
    checks: [], unverified: [contract.limitations], limitations: contract.limitations },
    human_opinions: [{ conclusion: 'false_positive', reviewed_by: 'saved-reviewer', note: '独立人工意见保留', evidence_ids: [], created_at: createdAt }] };
}

function setSavedAttacks(f, views, { legacy = false, instances } = {}) {
  return changeFrozen(f, results => {
    if (legacy) {
      results.findings = views.map((view, index) => ({ ...results.findings[index % results.findings.length],
        id: 'scan:' + view.finding_id, verification: { ...view, attempt_id: view.id, id: 'aggregate-' + view.id } }));
    } else results.verification_attempts = views;
    if (instances) results.instances = instances;
  });
}

// Read the embedded Unicode map and page text, so assertions cover the PDF bytes
// consumed by Office rather than only the intermediate section model.
function pdfText(pdf) {
  const streams = [...pdf.context.enumerateIndirectObjects()]
    .map(([, value]) => value).filter(value => value instanceof PDFRawStream)
    .map(value => Buffer.from(decodePDFRawStream(value).decode()).toString('latin1'));
  const unicode = new Map();
  for (const stream of streams.filter(value => value.includes('begincmap'))) {
    for (const block of stream.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
      for (const [, code, mapped] of block[1].matchAll(/<([\da-f]+)>\s*<([\da-f]+)>/gi)) {
        unicode.set(code.toUpperCase(), String.fromCharCode(...mapped.match(/.{4}/g).map(value => parseInt(value, 16))));
      }
    }
  }
  assert.ok(unicode.size > 0, 'PDF includes a Chinese Unicode character map');
  return streams.filter(value => !value.includes('begincmap')).flatMap(stream =>
    [...stream.matchAll(/<([\da-f]+)>\s*Tj/gi)].map(([, encoded]) =>
      encoded.match(/.{4}/g).map(code => unicode.get(code.toUpperCase()) || '').join(''))).join('');
}

async function assertFile(buffer, format) {
  if (format === 'docx') {
    assert.equal(buffer.subarray(0, 2).toString(), 'PK');
    return docxXml(buffer);
  }
  if (format === 'pdf') {
    assert.equal(buffer.subarray(0, 5).toString(), '%PDF-');
    const pdf = await PDFDocument.load(buffer);
    assert.ok(pdf.getPageCount() > 0);
    return pdfText(pdf);
  }
  const text = buffer.toString('utf8');
  if (format === 'json') assert.equal(JSON.parse(text).report.kind, 'trace_snapshot');
  else assert.match(text, /<!DOCTYPE html>/i);
  return text;
}

test('v1 and v2 exports use only saved report fields, with no F09 backfill', async context => {
  for (const legacy of [false, true]) await context.test(legacy ? 'historical v1' : 'current v2', async () => {
    const f = await fixture({ legacy, withRun: true });
    try {
      const document = setSavedAttacks(f, [attackView()], { legacy });
      const original = f.stored();
      const sections = briefSections(document);
      const data = buildTaskAttackReportData(document);
      assert.equal(data.rows.length, 1);
      if (legacy) {
        assert.equal(document.report.content.results.statistics, undefined);
        assert.equal(data.stats.vulnerability_instances, null);
      } else assert.equal(data.stats.vulnerability_instances, 1);
      f.db.prepare("UPDATE scan_results SET result_data='{}',severity='low'").run();
      f.db.prepare("UPDATE execution_runs SET score_data=?,final_summary=? WHERE run_id='report-run'")
        .run(JSON.stringify({ ok: true, runId: 'report-run', percent: 99 }), '后改执行结论');
      f.db.prepare("UPDATE execution_attempts SET stdout='后改工具结果'").run();
      f.db.prepare("UPDATE evidence_records SET recommendations='[\"后改建议\"]',raw_stdout='后改证据'").run();
      const frozen = readTaskReport(f.db, f.pipeline, f.reportId);
      assert.deepEqual(buildTaskReportSections(frozen), sections);
      assert.deepEqual(frozen.presentation, document.presentation);
      for (const format of ['json', 'html', 'docx', 'pdf']) {
        const exported = await exportTaskReport(frozen, format);
        assert.ok(Buffer.isBuffer(exported.buffer));
        assert.ok(exported.contentType.startsWith(mime[format]));
        assert.equal(exported.filename, 'report_' + f.reportId + '.' + format);
        const content = await assertFile(exported.buffer, format);
        if (format === 'json') {
          const saved = JSON.parse(content).report.content.results;
          assert.equal(saved.assessment.teaching_score.percent, 73);
          assert.match(JSON.stringify(saved.execution.evidence), /保存时的修复建议|T1190/);
          assert.deepEqual(saved, document.report.content.results);
        } else {
          for (const heading of reportHeadings) assert.ok(content.includes(heading));
          assert.match(content, /saved-entry/);
          assert.match(content, /达到预期效果/);
          assert.doesNotMatch(content, /教学得分|MITRE|T1190|保存时的修复建议|扫描全量记录附录|完整展示快照/);
        }
        assert.doesNotMatch(content, /后改建议|后改证据|后改执行结论|后改工具结果/);
      }
      assert.equal(f.stored(), original);
    } finally { await f.close(); }
  });
});

test('v1 and v2 brief reports retain saved attack facts while JSON preserves the full contract', async context => {
  for (const legacy of [true, false]) {
    for (const status of ['achieved', 'not_performed']) await context.test(`v${legacy ? 1 : 2} ${status}`, async () => {
      const f = await fixture({ legacy, withRun: true });
      try {
        const target = 'http://192.0.2.10/saved-entry';
        const view = attackView({ id: 'verification-attempt-42', target, status });
        const { result } = view;
        const savedDocument = setSavedAttacks(f, [view], { legacy });
        const original = f.stored();
        f.db.prepare('UPDATE scan_results SET result_data=?').run(JSON.stringify({ target: 'http://192.0.2.10/current-data-entry' }));
        const document = readTaskReport(f.db, f.pipeline, f.reportId);
        assert.notEqual(document.target, target, 'the saved verification entry differs from the overall task target');
        const sections = briefSections(document);
        const data = buildTaskAttackReportData(document);
        assert.equal(data.rows.length, 1);
        assert.equal(data.rows[0].latest_attempt_id, view.id);
        assert.equal(data.rows[0].target, target);
        assert.equal(data.rows[0].objective_id, result.objective.id);
        assert.equal(data.rows[0].status, status);
        assert.deepEqual(document.presentation, savedDocument.presentation);
        const json = JSON.parse((await exportTaskReport(document, 'json')).buffer);
        const savedView = legacy ? json.report.content.results.findings[0].verification
          : json.report.content.results.verification_attempts[0];
        const originalView = legacy ? savedDocument.report.content.results.findings[0].verification
          : savedDocument.report.content.results.verification_attempts[0];
        assert.deepEqual(savedView.result, originalView.result);
        assert.deepEqual(savedView.result.object, result.object);
        assert.deepEqual(savedView.result.objective, result.objective);
        assert.deepEqual(savedView.result.criterion, result.criterion);
        if (legacy) {
          assert.notEqual(savedView.id, savedView.attempt_id);
          assert.equal(savedView.attempt_id, view.id);
        } else assert.equal(savedView.id, view.id);
        if (status === 'not_performed') {
          const savedResult = legacy ? document.report.content.results.findings[0].verification.result
            : document.report.content.results.verification_attempts[0].result;
          assert.deepEqual(savedResult.observed_facts, []);
          assert.equal(data.stats.started_attempts, legacy ? null : 0);
          assert.match(sections[1].rows[0][1], /未启动/);
        }
        const conclusion = sections[2].paragraphs.join('\n');
        assert.ok(conclusion.includes(target), 'the conclusion names the saved attack entry');
        assert.ok(conclusion.includes(result.reason), 'the conclusion describes the proven effect or the unperformed reason');
        for (const format of ['docx', 'pdf', 'html']) {
          const exported = await exportTaskReport(document, format);
          const text = await assertFile(exported.buffer, format);
          for (const heading of reportHeadings) assert.ok(text.includes(heading));
          assert.ok(text.includes(target));
          assert.ok(text.includes(view.id));
          assert.ok(text.includes(result.objective.label));
          assert.ok(text.includes(resultLabels[status]));
          assert.ok(text.includes(result.reason));
          assert.doesNotMatch(text, /required_evidence|same_entry|observed_facts|reason_code|source_fingerprint|复核人：saved-reviewer/);
          assert.doesNotMatch(text, /current-data-entry/);
        }
        assert.equal(sections[1].rows.length, 1);
        assert.equal(f.stored(), original);
      } finally { await f.close(); }
    });
  }
});

test('missing historical verification fields remain unrecorded instead of borrowing plan or live data', async context => {
  for (const legacy of [true, false]) await context.test(`v${legacy ? 1 : 2}`, async () => {
    const f = await fixture({ legacy, withRun: true });
    try {
      const view = { id: 'saved-missing-fields-attempt', finding_id: 7,
        state: 'completed', result: { schema_version: 1, status: 'not_performed', reason: '历史结果未记录对象和判据', observed_facts: [] },
        plan: { verification_contract: { object: { finding_id: 99, target: 'http://192.0.2.10/plan-only-target' },
          objective: { id: 'plan-only-objective', label: '不应补入报告的方案目标', category: 'effect' },
          criterion: { id: 'plan-only-criterion', version: 99 } } } };
      setSavedAttacks(f, [view], { legacy });
      const original = f.stored();
      f.db.prepare('UPDATE scan_results SET result_data=?').run(JSON.stringify({ target: 'http://192.0.2.10/current-target',
        objective: 'current-objective', criterion: { id: 'current-criterion', version: 88 } }));
      const document = readTaskReport(f.db, f.pipeline, f.reportId);
      const sections = briefSections(document);
      const data = buildTaskAttackReportData(document);
      assert.equal(data.rows.length, 1);
      assert.equal(data.rows[0].latest_attempt_id, view.id);
      assert.equal(data.rows[0].objective_id, null);
      assert.equal(data.rows[0].target, null);
      assert.match(sections[1].rows[0][2], /未记录|未知/);
      for (const format of ['docx', 'pdf', 'html']) {
        const text = await assertFile((await exportTaskReport(document, format)).buffer, format);
        assert.match(text, /未记录|未知/);
        assert.doesNotMatch(text, /plan-only|不应补入报告的方案目标|current-target|current-objective|current-criterion/);
      }
      assert.equal(f.stored(), original);
    } finally { await f.close(); }
  });
});

test('pure-scan brief reports stay short and JSON retains all 235 records and the long last record', async () => {
  const f = await fixture({ records: 235 });
  try {
    const original = f.stored();
    assert.equal(f.document.report.content.results.execution.run, null);
    assert.equal(f.document.report.content.results.scan_records.length, 235);
    const sections = briefSections(f.document);
    assert.equal(sections[1].rows.length, 0);
    const json = JSON.parse((await exportTaskReport(f.document, 'json')).buffer);
    assert.equal(json.report.content.results.scan_records.length, 235);
    assert.match(json.report.content.results.scan_records.at(-1).result_data, /中文扫描记录-234/);
    assert.match(json.report.content.results.scan_records.at(-1).result_data, /长中文内容需要完整换行并在跨页后保留。/);
    assert.match(json.report.content.results.scan_records.at(-1).result_data, /末条中文哨兵/);
    for (const format of ['docx', 'pdf', 'html']) {
      const file = await exportTaskReport(f.document, format);
      const text = await assertFile(file.buffer, format);
      assert.match(text, /235/);
      assert.match(text, /未保存逐漏洞攻击记录|未开展.*攻击/);
      assert.doesNotMatch(text, /中文扫描记录-234|末条中文哨兵|扫描全量记录|长中文内容需要/);
    }
    const pdf = await PDFDocument.load((await exportTaskReport(f.document, 'pdf')).buffer);
    assert.ok(pdf.getPageCount() <= 2, 'a pure-scan overview does not expand into a scan appendix');
    for (const page of pdf.getPages()) assert.ok(page.node.Resources()?.lookup(PDFName.of('Font')), 'every page has an embedded text font');
    assert.equal(f.stored(), original);
  } finally { await f.close(); }
});

test('retries of a mapped vulnerability and objective show only the latest saved effect', async () => {
  const f = await fixture({ records: 2 });
  try {
    const first = attackView({ finding: 1, id: 'earlier-success' });
    const last = attackView({ finding: 2, id: 'latest-negative', status: 'not_achieved', createdAt: '2026-10-20T00:00:00Z' });
    const document = setSavedAttacks(f, [first, last], { instances: [{
      ...f.document.report.content.results.instances[0], instance_id: 'merged-vulnerability', record_ids: [1, 2],
    }] });
    const data = buildTaskAttackReportData(document);
    assert.equal(data.rows.length, 1);
    assert.deepEqual(data.rows[0].finding_ids, ['1', '2']);
    assert.deepEqual(data.rows[0].attempt_ids, ['earlier-success', 'latest-negative']);
    assert.equal(data.rows[0].latest_attempt_id, 'latest-negative');
    assert.equal(data.rows[0].attempt_count, 2);
    assert.equal(data.rows[0].status, 'not_achieved');
    assert.equal(data.stats.started_instances, 1);
    assert.equal(data.stats.started_attempts, 2);
    assert.equal(data.stats.effect_targets, 1);
    assert.equal(data.stats.latest_results.achieved, 0);
    assert.equal(data.stats.latest_results.not_achieved, 1);
    const sections = briefSections(document);
    assert.equal(sections[1].rows[0][4], resultLabels.not_achieved);
    assert.match(sections[1].rows[0][3], /响应包含指定防护响应头/);
    assert.doesNotMatch(sections[1].rows[0][3], /响应缺少指定防护响应头/);
  } finally { await f.close(); }
});

test('historical full scan verification survives the 150-candidate preview and is not duplicated', async () => {
  const f = await fixture({ legacy: true, records: 151 });
  try {
    const view = attackView({ finding: 151, id: 'beyond-preview', status: 'inconclusive' });
    const verification = { ...view, id: 'verification-151', attempt_id: view.id };
    const document = changeFrozen(f, results => {
      assert.equal(results.findings.length, 150);
      results.scan_records[150].verification = verification;
      results.scan_records[0].verification = { ...attackView(), id: 'aggregate-1', attempt_id: 'saved-attempt-1' };
      results.findings[0].verification = results.scan_records[0].verification;
    });
    const before = f.stored();
    const data = buildTaskAttackReportData(document);
    assert.equal(data.rows.length, 2);
    assert.deepEqual(data.rows.map(row => row.latest_attempt_id), ['saved-attempt-1', 'beyond-preview']);
    assert.equal(data.stats.started_attempts, 2);
    for (const format of ['html', 'docx', 'pdf', 'json']) {
      const output = await assertFile((await exportTaskReport(document, format)).buffer, format);
      assert.ok(output.includes('beyond-preview'));
      assert.ok(output.includes('中文扫描记录-150'));
      assert.doesNotMatch(output, /未保存逐漏洞攻击记录/);
    }
    assert.equal(f.stored(), before);
  } finally { await f.close(); }
});

test('full v2 attempt history takes precedence over duplicate saved scan summaries', async () => {
  const f = await fixture();
  try {
    const current = attackView({ status: 'not_achieved' });
    const document = changeFrozen(f, results => {
      results.verification_attempts = [current];
      const stale = { ...attackView(), id: 'verification-1', attempt_id: current.id };
      results.scan_records[0].verification = stale;
      results.findings[0].verification = stale;
    });
    const data = buildTaskAttackReportData(document);
    assert.equal(data.rows.length, 1);
    assert.equal(data.rows[0].status, 'not_achieved');
    assert.equal(data.stats.started_attempts, 1);
  } finally { await f.close(); }
});

test('placeholder and missing objective identities never merge different operations', async () => {
  const f = await fixture();
  try {
    const views = ['读取测试文件', '写入测试文件'].map((name, index) => {
      const view = attackView({ id: 'unknown-objective-' + index, status: 'inconclusive' });
      const contract = buildVerificationContract({ target: view.result.object.target,
        steps: [{ step_id: 'step', tool_id: 'fixture-payload', name, consumption: 'independent' }] }, 1);
      assert.equal(contract.objective.id, 'unavailable_effect');
      view.result.objective = contract.objective;
      view.result.criterion = null;
      view.result.operations = contract.operations.map(operation => ({ ...operation, started: true }));
      return view;
    });
    for (const missing of [false, true]) {
      const inputs = structuredClone(views);
      if (missing) for (const view of inputs) view.result.objective.id = null;
      const document = setSavedAttacks(f, inputs);
      const data = buildTaskAttackReportData(document);
      assert.equal(data.rows.length, 2);
      assert.equal(data.stats.started_instances, 1);
      assert.equal(data.stats.started_attempts, 2);
      for (const format of ['html', 'docx', 'pdf']) {
        const output = await assertFile((await exportTaskReport(document, format)).buffer, format);
        assert.ok(output.includes('读取测试文件'));
        assert.ok(output.includes('写入测试文件'));
      }
    }
  } finally { await f.close(); }
});

test('unknown historical applicability preserves executed operations without asserting zero attacks', async () => {
  const f = await fixture();
  try {
    const view = attackView({ status: 'inconclusive' });
    view.result.objective = { id: null, category: 'unknown', label: '历史验证目标未记录' };
    view.result.criterion = null;
    view.result.reason = '历史目标未明确，证据不足';
    const document = setSavedAttacks(f, [view]);
    const data = buildTaskAttackReportData(document);
    assert.equal(data.stats.started_instances, null);
    assert.equal(data.stats.started_attempts, null);
    assert.equal(data.stats.counts_complete, false);
    assert.equal(data.rows[0].status, 'inconclusive');
    assert.match(data.rows[0].operation, /已执行/);
    assert.match(data.rows[0].operation, /次数未知/);
    assert.match(data.limitations.join('\n'), /适用性未知/);
    for (const format of ['html', 'docx', 'pdf']) {
      const output = await assertFile((await exportTaskReport(document, format)).buffer, format);
      assert.doesNotMatch(output, /实际启动适用攻击\s*0\s*次/);
      assert.ok(output.includes('适用攻击启动次数未知'));
    }
  } finally { await f.close(); }
});

test('inconclusive reports distinguish observed evidence from missing judgement evidence', async () => {
  const f = await fixture();
  try {
    const view = attackView({ status: 'inconclusive' });
    view.result.evidence_ids = [];
    view.result.operations[0].evidence_ids = [42, 42, 43];
    view.result.observed_facts[0].evidence_id = 42;
    const document = setSavedAttacks(f, [view]);
    const actual = buildTaskAttackReportData(document).rows[0].actual;
    assert.match(actual, /判定证据：未记录/);
    assert.match(actual, /观察\/操作证据：42, 43/);
    assert.doesNotMatch(actual, /42, 42/);
    for (const format of ['html', 'docx', 'pdf']) {
      const output = await assertFile((await exportTaskReport(document, format)).buffer, format);
      assert.ok(output.includes('判定证据：未记录'));
      assert.ok(output.includes('观察/操作证据：42, 43'));
      assert.ok(output.includes('证据不足'));
    }
  } finally { await f.close(); }
});

test('scan parser names and instance rule fallback survive outside the candidate preview', async () => {
  const f = await fixture({ records: 151 });
  try {
    const cppcheck = parseCppcheck('<results><errors><error id="bufferAccessOutOfBounds" severity="error" msg="Array index out of bounds"><location file="main.c" line="42"/></error></errors></results>')[0];
    for (const [record, identity, expected] of [
      [cppcheck, null, 'Array index out of bounds'],
      [{ result_type: 'web_vuln', result_data: { info: { name: 'Nested Nuclei finding' }, 'template-id': 'template-151' } }, null, 'Nested Nuclei finding'],
      [{ result_type: 'web_vuln', result_data: {} }, { rule: 'saved-instance-rule' }, 'saved-instance-rule'],
    ]) {
      const document = changeFrozen(f, results => {
        results.verification_attempts = [attackView({ finding: 151 })];
        results.scan_records[150] = { ...results.scan_records[150], ...record, result_data: JSON.stringify(record.result_data) };
        if (identity) results.instances.find(item => item.record_ids.includes(151)).identity = identity;
      });
      assert.equal(document.report.content.results.findings.length, 150);
      const data = buildTaskAttackReportData(document);
      assert.ok(data.rows[0].finding.includes(expected));
      for (const format of ['html', 'docx', 'pdf']) {
        const output = await assertFile((await exportTaskReport(document, format)).buffer, format);
        assert.ok(output.includes(expected), `${format}: ${expected}`);
      }
    }
  } finally { await f.close(); }
});

test('different vulnerability locations, entry points and objectives remain separate', async () => {
  const f = await fixture({ records: 2 });
  try {
    const entryA = 'http://192.0.2.10/entry-a', entryB = 'http://192.0.2.10/entry-b';
    const views = [attackView({ finding: 1, id: 'entry-a-headers', target: entryA }),
      attackView({ finding: 1, id: 'entry-b-headers', target: entryB }),
      attackView({ finding: 1, id: 'entry-a-other-goal', target: entryA }),
      attackView({ finding: 2, id: 'other-location-same-goal', target: entryA })];
    views[2].result.objective = { id: 'other-saved-goal', label: '另一个已保存攻击目标', category: 'effect' };
    const document = setSavedAttacks(f, views);
    const data = buildTaskAttackReportData(document);
    assert.equal(data.rows.length, 4);
    const firstInstance = document.report.content.results.instances.find(item => item.record_ids.includes(1)).instance_id;
    const secondInstance = document.report.content.results.instances.find(item => item.record_ids.includes(2)).instance_id;
    assert.equal(data.rows.filter(row => row.instance_id === firstInstance).length, 3);
    assert.equal(data.rows.filter(row => row.instance_id === secondInstance).length, 1);
    assert.equal(data.rows.filter(row => row.target === entryA && row.objective_id === 'f08-web-headers-v1').length, 2,
      'same target and objective do not merge distinct mapped vulnerabilities');
    assert.equal(data.stats.started_instances, 2);
    assert.equal(data.stats.started_attempts, 4);
    assert.equal(data.stats.effect_targets, 4);
    assert.equal(briefSections(document)[1].rows.length, 4);
  } finally { await f.close(); }
});

test('missing saved entry points cannot merge two attempts into an assumed common target', async () => {
  const f = await fixture();
  try {
    const views = [attackView({ id: 'unknown-entry-one' }), attackView({ id: 'unknown-entry-two', status: 'not_achieved' })];
    for (const view of views) delete view.result.object.target;
    const document = setSavedAttacks(f, views);
    const data = buildTaskAttackReportData(document);
    assert.equal(data.rows.length, 2, 'unknown entries remain separate even when instance and objective match');
    assert.deepEqual(data.rows.map(row => row.latest_attempt_id), ['unknown-entry-one', 'unknown-entry-two']);
    assert.ok(data.rows.every(row => row.target === null && row.attempt_count === 1));
    assert.equal(data.stats.latest_results.achieved, 1);
    assert.equal(data.stats.latest_results.not_achieved, 1);
    assert.equal(data.stats.counts_complete, false);
    assert.match(data.limitations.join('\n'), /入口.*未知|未记录.*入口|入口.*未记录|未保存.*入口/);
  } finally { await f.close(); }
});

test('untrusted sources, page access and tool success cannot become a successful attack', async context => {
  const cases = [
    ['source mismatch', view => { view.source_valid = false; }, 'inconclusive', null],
    ['accessibility only', view => { view.result.objective.category = 'accessibility'; }, 'not_performed', 0],
    ['not performed with HTTP observations', view => { view.result.status = 'not_performed'; }, 'not_performed', 0],
    ['tool success without effect result', view => { delete view.result; }, 'inconclusive', null],
  ];
  for (const [name, change, status, started] of cases) await context.test(name, async () => {
    const f = await fixture({ withRun: true });
    try {
      const view = attackView(); change(view);
      const document = setSavedAttacks(f, [view]);
      const data = buildTaskAttackReportData(document);
      assert.equal(document.report.content.results.execution.steps[0].state, 'SUCCEEDED');
      assert.equal(data.rows[0].status, status);
      assert.equal(data.stats.latest_results.achieved, 0);
      assert.equal(data.stats.started_attempts, started);
      if (started === null) assert.equal(data.stats.counts_complete, false);
      const table = briefSections(document)[1];
      assert.equal(table.rows[0][4], resultLabels[status]);
      if (view.result?.observed_facts.length) assert.match(table.rows[0][3], /HTTP 200/);
      assert.doesNotMatch(table.rows[0][3], /"status_code"|"observed_facts"|"complete"/);
    } finally { await f.close(); }
  });
});

test('operations with unknown startup remain explicitly unknown in the attack narrative', async () => {
  const f = await fixture();
  try {
    const view = attackView({ status: 'inconclusive' });
    view.started = null;
    view.result.operations[0].started = null;
    view.result.reason = '保存的证据无法证明工具实际启动';
    const document = setSavedAttacks(f, [view]);
    const sections = briefSections(document);
    const data = buildTaskAttackReportData(document);
    assert.match(sections[1].rows[0][1], /启动未知/);
    assert.doesNotMatch(sections[1].rows[0][1], /实际启动适用攻击\s*0\s*次/);
    assert.equal(sections[1].rows[0][4], resultLabels.inconclusive);
    assert.equal(data.stats.started_attempts, null);
    assert.equal(data.stats.started_instances, null);
    assert.equal(data.stats.counts_complete, false);
    assert.ok(sections[2].paragraphs.join('\n').includes(view.result.reason));
    const mixed = setSavedAttacks(f, [attackView({ id: 'known-start-first' }), view]);
    const mixedData = buildTaskAttackReportData(mixed);
    assert.equal(mixedData.rows.length, 1);
    assert.equal(mixedData.stats.started_attempts, 1);
    assert.equal(mixedData.stats.counts_complete, false);
    const mixedSections = briefSections(mixed);
    assert.match(mixedSections[1].rows[0][1], /至少\s*1\s*次|已核对启动\s*1\s*次.*启动未知/);
    const overview = mixedSections[0].paragraphs.join('\n');
    assert.match(overview, /可核对[^；\n]*(?:攻击尝试|攻击启动次数)：\s*1\s*次|至少\s*1\s*次/);
    assert.doesNotMatch(overview, /；实际启动适用攻击尝试：\s*1\s*次/);
  } finally { await f.close(); }
});

test('unmapped attacks stay record counts and incomplete historical associations stay unknown', async context => {
  await context.test('mapped and unmapped attacks have separate totals', async () => {
    const f = await fixture({ records: 3 });
    try {
      const instance = f.document.report.content.results.instances.find(item => item.record_ids.includes(1));
      const document = setSavedAttacks(f, [attackView({ finding: 1, id: 'mapped' }),
        attackView({ finding: 2, id: 'unmapped-two' }), attackView({ finding: 3, id: 'unmapped-three' })],
      { instances: [instance] });
      const data = buildTaskAttackReportData(document);
      assert.equal(data.rows.length, 3);
      assert.equal(data.stats.started_instances, 1);
      assert.equal(data.stats.started_attempts, 3);
      assert.equal(data.stats.unmapped_started_records, 2);
      assert.equal(data.stats.unmapped_started_attempts, 2);
      assert.equal(data.stats.counts_complete, false);
      assert.equal(data.rows.filter(row => row.instance_id === null).length, 2);
      assert.match(JSON.stringify(briefSections(document)), /未归并.*2/);
    } finally { await f.close(); }
  });
  await context.test('pure scan has known zero starts without fabricating attack rows', async () => {
    const f = await fixture();
    try {
      const data = buildTaskAttackReportData(f.document);
      assert.equal(data.rows.length, 0);
      assert.equal(data.stats.started_instances, 0);
      assert.equal(data.stats.started_attempts, 0);
      assert.equal(data.stats.counts_complete, true);
    } finally { await f.close(); }
  });
  await context.test('historical main Run success without a finding association remains unknown', async () => {
    const f = await fixture({ legacy: true });
    try {
      const data = buildTaskAttackReportData(f.document);
      assert.equal(data.rows.length, 0);
      assert.equal(data.stats.vulnerability_instances, null);
      assert.equal(data.stats.started_instances, null);
      assert.equal(data.stats.started_attempts, null);
      assert.equal(data.stats.counts_complete, false);
      assert.match(JSON.stringify(briefSections(f.document)), /未知/);
    } finally { await f.close(); }
  });
  await context.test('v1 verification aggregate never becomes an attempt ID', async () => {
    const f = await fixture({ legacy: true });
    try {
      const document = changeFrozen(f, results => {
        results.findings[0].verification = { id: 'aggregate-without-attempt', state: 'completed', conclusion: 'confirmed' };
      });
      const data = buildTaskAttackReportData(document);
      assert.equal(data.rows[0].latest_attempt_id, null);
      assert.equal(data.rows[0].attempt_count, 0);
      assert.deepEqual(data.rows[0].attempt_ids, []);
      assert.equal(data.rows[0].status, 'inconclusive');
      assert.equal(data.stats.started_attempts, null);
      assert.doesNotMatch(JSON.stringify(briefSections(document)), /aggregate-without-attempt/);
    } finally { await f.close(); }
  });
});

test('few attacks fit a short PDF and large attack tables keep their last row across pages', async context => {
  for (const count of [2, 3, 32]) await context.test(count + ' attacks', async () => {
    const f = await fixture({ records: count });
    try {
      const views = Array.from({ length: count }, (_, index) => attackView({ finding: index + 1,
        id: 'saved-attempt-' + index, target: 'http://192.0.2.10/attack-' + index, createdAt: '2026-10-18T08:00:00Z' }));
      setSavedAttacks(f, views);
      const document = changeFrozen(f, results => { results.baseline = {
        schema_version: 1, environment_id: 'saved-training-range', environment_version: '2026.1',
        assets_complete: false, vulnerabilities_complete: false, assets: [], vulnerabilities: [],
      }; });
      assert.equal(briefSections(document)[1].rows.length, count);
      const binary = await exportTaskReport(document, 'pdf');
      const pdf = await PDFDocument.load(binary.buffer);
      assert.ok(pdf.getPages().every(page => page.getWidth() > page.getHeight()), 'the final PDF uses landscape pages');
      if (count <= 3) assert.ok(pdf.getPageCount() <= 2, 'two or three attacks remain within two PDF pages');
      else assert.ok(pdf.getPageCount() > 1, 'the attack table is paginated');
      for (const format of ['docx', 'html', 'pdf']) {
        const file = format === 'pdf' ? binary : await exportTaskReport(document, format);
        const text = await assertFile(file.buffer, format);
        assert.ok(text.includes('saved-attempt-' + (count - 1)), `${format} retains the final attack`);
        assert.ok(text.includes('http://192.0.2.10/attack-' + (count - 1)));
        assert.ok(text.includes('saved-training-range'));
        assert.ok(text.includes('2026.1'));
        assert.ok(text.includes('2026-10-18T08:00:00Z'));
        for (const heading of reportHeadings) assert.ok(text.includes(heading));
        if (format === 'docx') {
          assert.match(text, /<w:tblHeader\b/);
          const page = text.match(/<w:pgSz\b[^>]*>/)?.[0];
          assert.ok(page);
          const width = Number(page.match(/\bw:w="(\d+)"/)?.[1]);
          const height = Number(page.match(/\bw:h="(\d+)"/)?.[1]);
          assert.ok(width > height, 'the final Word XML uses landscape page dimensions');
          const grids = [...text.matchAll(/<w:tblGrid>([\s\S]*?)<\/w:tblGrid>/g)];
          assert.equal(grids.length, 1);
          assert.equal([...grids[0][1].matchAll(/<w:gridCol\b/g)].length, 5);
        }
      }
    } finally { await f.close(); }
  });
});

test('both HTTP export entries support all formats and retain their independent defaults', async context => {
  for (const legacy of [false, true]) await context.test(legacy ? 'v1' : 'v2 without a main Run', async () => {
    const f = await fixture({ legacy });
    try {
      const original = f.stored(), root = await f.start();
      const paths = ['/api/pipelines/report-task/results/reports/' + f.reportId + '/export', '/api/reports/' + f.reportId + '/export'];
      f.db.prepare("UPDATE scan_results SET result_data=?").run(JSON.stringify({ name: '导出前修改的扫描记录' }));
      if (legacy) {
        f.db.prepare("UPDATE execution_runs SET score_data=? WHERE run_id='report-run'")
          .run(JSON.stringify({ ok: true, runId: 'report-run', percent: 99 }));
        f.db.prepare("UPDATE evidence_records SET recommendations='[\"导出前修改的建议\"]'").run();
      }
      let expectedAudits = 0;
      for (const entry of paths) {
        for (const format of ['json', 'html', 'pdf', 'docx']) {
          const response = await fetch(root + entry + '?format=' + format);
          assert.equal(response.status, 200, entry + ' ' + format);
          assert.ok(response.headers.get('content-type').startsWith(mime[format]));
          assert.equal(response.headers.get('content-disposition'), 'attachment; filename="report_' + f.reportId + '.' + format + '"');
          assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
          const content = await assertFile(Buffer.from(await response.arrayBuffer()), format);
          if (format === 'json') assert.match(content, /中文扫描记录-0/);
          else {
            for (const heading of reportHeadings) assert.ok(content.includes(heading));
            assert.doesNotMatch(content, /中文扫描记录-0|T1190|保存时的修复建议/);
          }
          assert.doesNotMatch(content, /导出前修改的扫描记录|导出前修改的建议/);
          expectedAudits++;
        }
        const response = await fetch(root + entry);
        assert.equal(response.status, 200);
        await assertFile(Buffer.from(await response.arrayBuffer()), entry.startsWith('/api/reports/') ? 'docx' : 'json');
        expectedAudits++;
        for (const format of ['docx', 'pdf']) {
          const admin = await fetch(root + entry + '?format=' + format, { headers: { 'x-actor': 'report-admin' } });
          assert.equal(admin.status, 200, 'administrator can export an owned report through ' + entry);
          await assertFile(Buffer.from(await admin.arrayBuffer()), format);
          expectedAudits++;
        }
      }
      const audits = f.db.prepare("SELECT reasons FROM audit_log WHERE type='task_report_export' AND execution_id=?").all(f.reportId);
      assert.equal(audits.length, expectedAudits);
      assert.ok(audits.every(row => JSON.parse(row.reasons).source_fingerprint === f.document.report.source_fingerprint));
      assert.equal(f.stored(), original);
    } finally { await f.close(); }
  });
});

test('denied actors, unsupported formats and corrupt snapshots produce no file and no export audit', async () => {
  const f = await fixture();
  try {
    const root = await f.start();
    const entries = ['/api/pipelines/report-task/results/reports/' + f.reportId + '/export', '/api/reports/' + f.reportId + '/export'];
    const before = f.db.prepare("SELECT COUNT(*) n FROM audit_log WHERE type='task_report_export'").get().n;
    f.db.prepare(`INSERT INTO pipelines(pipeline_id,target,status,created_by,config)
      VALUES ('wrong-report-task','http://192.0.2.10/','completed','report-alice','{}')`).run();
    for (const format of ['pdf', 'docx']) {
      const wrong = await fetch(root + '/api/pipelines/wrong-report-task/results/reports/' + f.reportId + '/export?format=' + format);
      assert.equal(wrong.status, 409, 'same owner and target do not authorize a report from another task');
      assert.equal(wrong.headers.get('content-disposition'), null);
    }
    for (const entry of entries) {
      for (const format of ['pdf', 'docx']) {
        const denied = await fetch(root + entry + '?format=' + format, { headers: { 'x-actor': 'report-bob' } });
        assert.equal(denied.status, 403);
        assert.equal(denied.headers.get('content-disposition'), null);
        assert.doesNotMatch(await denied.text(), /中文扫描记录|末条中文哨兵/);
      }
      const unsupported = await fetch(root + entry + '?format=xlsx');
      assert.equal(unsupported.status, 400);
      assert.equal(unsupported.headers.get('content-disposition'), null);
    }
    f.db.prepare("UPDATE test_reports SET content='{broken' WHERE report_id=?").run(f.reportId);
    for (const entry of entries) {
      const response = await fetch(root + entry + '?format=docx');
      assert.ok([403, 409].includes(response.status), 'broken provenance must be rejected');
      assert.equal(response.headers.get('content-disposition'), null);
    }
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM audit_log WHERE type='task_report_export'").get().n, before);
  } finally { await f.close(); }
});

test('PDF character codes resolve to real embedded CJK and Latin glyph outlines', async () => {
  const f = await fixture();
  try {
    const document = setSavedAttacks(f, [attackView()]);
    const { buffer } = await exportTaskReport(document, 'pdf');
    assert.ok(buffer.length <= MAX_TASK_REPORT_EXPORT_BYTES);
    const pdf = await PDFDocument.load(buffer);
    const resources = pdf.getPages()[0].node.Resources().lookup(PDFName.of('Font'));
    const font = resources.lookup(resources.keys()[0]);
    const descendant = font.lookup(PDFName.of('DescendantFonts')).lookup(0);
    assert.equal(descendant.get(PDFName.of('CIDToGIDMap')).toString(), '/Identity');
    const descriptor = descendant.lookup(PDFName.of('FontDescriptor'));
    const embeddedBytes = Buffer.from(decodePDFRawStream(descriptor.lookup(PDFName.of('FontFile2'))).decode());
    const embedded = fontkit.create(embeddedBytes);
    const original = fontkit.create(await readFile(new URL('../assets/fonts/NotoSansSC-Regular.ttf', import.meta.url)));
    const cmap = Buffer.from(decodePDFRawStream(font.lookup(PDFName.of('ToUnicode'))).decode()).toString();
    const ids = new Map();
    for (const block of cmap.matchAll(/beginbfchar([\s\S]*?)endbfchar/g)) {
      for (const [, code, unicode] of block[1].matchAll(/<([\da-f]+)>\s*<([\da-f]+)>/gi)) {
        if (unicode.length === 4) ids.set(String.fromCharCode(parseInt(unicode, 16)), parseInt(code, 16));
      }
    }
    // ToUnicode extraction alone passed for the broken subset: e.g. 任 had an
    // extractable code but zero drawing commands. Check the actual font program.
    for (const character of '任务攻击测试结果报告RedTeam012') {
      assert.ok(ids.has(character), `PDF contains ${character}`);
      const actual = embedded.getGlyph(ids.get(character)).path.commands;
      const expected = original.glyphForCodePoint(character.codePointAt(0)).path.commands;
      assert.ok(actual.length > 0, `${character} has a visible glyph outline`);
      assert.deepEqual(actual, expected, `${character} retains the original drawing outline`);
    }
  } finally { await f.close(); }
});

test('font, renderer and size failures are explicit and never produce a fake successful download', async () => {
  const f = await fixture();
  const temporary = await mkdtemp(path.join(tmpdir(), 'task-report-font-'));
  try {
    const original = f.stored();
    await assert.rejects(exportTaskReport(f.document, 'pdf', { fontPath: path.join(temporary, 'missing.ttf') }), { status: 500 });
    const invalid = path.join(temporary, 'invalid.ttf');
    await writeFile(invalid, 'invalid font fixture');
    await assert.rejects(exportTaskReport(f.document, 'pdf', { fontPath: invalid }), { status: 500 });
    await assert.rejects(exportTaskReport(f.document, 'xlsx'), { status: 400 });
    await assert.rejects(exportTaskReport({ ...f.document, report: { ...f.document.report, kind: 'legacy' } }, 'pdf'), { status: 409 });
    assert.equal(MAX_TASK_REPORT_EXPORT_BYTES, 16 * 1024 * 1024);
    for (const format of ['json', 'html', 'pdf', 'docx']) await assert.rejects(exportTaskReport(f.document, format, { maxBytes: 10 }), { status: 413 });
    const root = await f.start();
    const renderer = mock.method(PDFDocument, 'create', async () => { throw new Error('fixture renderer failure'); });
    try {
      for (const entry of ['/api/pipelines/report-task/results/reports/', '/api/reports/']) {
        const response = await fetch(root + entry + f.reportId + '/export?format=pdf');
        assert.equal(response.status, 500);
        assert.equal(response.headers.get('content-disposition'), null);
        assert.equal((await response.json()).error.message, '报告文件生成失败，请稍后重试');
      }
    } finally { renderer.mock.restore(); }
    assert.equal(f.db.prepare("SELECT COUNT(*) n FROM audit_log WHERE type='task_report_export'").get().n, 0);
    assert.equal(f.stored(), original);
  } finally { await f.close(); await rm(temporary, { recursive: true, force: true }); }
});
