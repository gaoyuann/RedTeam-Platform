import { createHash, randomUUID } from 'crypto';
import { isDeepStrictEqual } from 'node:util';
import { taskExecutionSnapshot, taskDisplayText, taskDisplayValue } from './taskExecution.js';
import { appendTaskLog } from './taskActivity.js';

function json(value, fallback = null) {
  try { return typeof value === 'string' ? JSON.parse(value) : value ?? fallback; } catch { return fallback; }
}

function fail(status, message) { throw Object.assign(new Error(message), { status }); }

function approvedSource(db, pipeline, run) {
  if (!run) return null;
  const playbook = db.prepare('SELECT name, metadata FROM playbooks WHERE playbook_id = ?').get(run.playbook_id);
  const metadata = json(playbook?.metadata, {})?.task_plan;
  const source = { playbook_id: run.playbook_id, source_state: 'incomplete', content_revision: null,
    approval_revision: null, approval_record_id: null, approved_by: null, approved_at: null };
  if (metadata?.pipeline_id !== pipeline.pipeline_id || !Number.isSafeInteger(metadata.revision) || metadata.revision < 1) return source;
  source.content_revision = metadata.revision;
  const approval = db.prepare("SELECT * FROM task_plan_history WHERE pipeline_id = ? AND action = 'approve' AND revision = ? AND actor = ? ORDER BY id DESC LIMIT 1")
    .get(pipeline.pipeline_id, metadata.revision + 1, metadata.approved_by || '');
  const content = json(approval?.snapshot);
  const steps = db.prepare('SELECT step_id, name, tool_id, args_template, optional FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index').all(run.playbook_id);
  const comparable = rows => rows.map(row => ({ step_id: row.step_id, name: row.name, tool_id: row.tool_id,
    args: json(row.args_template, []), optional: Boolean(row.optional) }));
  if (!approval || approval.actor_role !== 'admin' || content?.target !== pipeline.target || content?.name !== playbook.name
      || !Array.isArray(content.steps) || !isDeepStrictEqual(comparable(steps), comparable(content.steps))) return source;
  return { ...source, source_state: 'verified', approval_revision: approval.revision, approval_record_id: approval.id,
    approved_by: taskDisplayText(approval.actor), approved_at: approval.created_at };
}

function frozenContent(row, pipeline) {
  const content = json(row.content);
  if (row.template !== 'task_trace_v1' || content?.type !== 'task_result_report' || content.schema_version !== 1) return null;
  const provenance = content.provenance;
  if (provenance?.pipeline_id !== pipeline.pipeline_id || provenance.owner !== pipeline.created_by
      || provenance.target !== taskDisplayText(pipeline.target) || provenance.run_id !== row.run_id
      || content.results?.execution?.run?.run_id !== row.run_id || content.results.pipeline_id !== pipeline.pipeline_id
      || content.results.owner !== pipeline.created_by || content.results.target !== taskDisplayText(pipeline.target)
      || content.results.source_fingerprint !== provenance.source_fingerprint
      || !content.results.assessment || !Array.isArray(content.results.findings)
      || !Array.isArray(content.results.execution.steps) || !Array.isArray(content.results.execution.evidence)
      || !Array.isArray(content.results.execution.attempts)
      || !/^[a-f0-9]{64}$/.test(provenance.source_fingerprint || '')) return null;
  for (const key of ['findings', 'steps', 'evidence', 'attempts']) {
    const rows = key === 'findings' ? content.results.findings : content.results.execution[key];
    if (rows.length > 200 || rows.some(value => !value || typeof value !== 'object' || Array.isArray(value))) return null;
    if (key === 'findings' && rows.some(value => value.state !== 'unreviewed')) return null;
    if (['evidence', 'attempts'].includes(key) && rows.some(value => value.run_id !== row.run_id || !Number.isSafeInteger(value.id) || value.id < 1)) return null;
  }
  return taskDisplayValue(content, 0, 200);
}

function reportMetadata(db, row, pipeline) {
  const content = frozenContent(row, pipeline);
  return { report_id: row.report_id, run_id: row.run_id, title: taskDisplayText(row.title), status: row.status,
    generated_by: taskDisplayText(row.generated_by), created_at: row.created_at,
    kind: content ? 'trace_snapshot' : row.template === 'task_trace_v1' ? 'invalid' : 'legacy',
    source_fingerprint: content?.provenance.source_fingerprint || null };
}

function reportRows(db, pipeline) {
  return db.prepare(`SELECT report.* FROM test_reports AS report JOIN execution_runs AS run ON run.run_id = report.run_id
    WHERE run.user_sub = ? AND run.target = ? AND (report.scan_task_id IS NULL OR EXISTS (
      SELECT 1 FROM scan_tasks AS scan WHERE scan.scan_task_id = report.scan_task_id AND scan.created_by = run.user_sub AND scan.target = run.target)) AND (report.run_id = ? OR
      (report.template = 'task_trace_v1' AND CASE WHEN json_valid(report.content) THEN
        json_extract(report.content, '$.provenance.pipeline_id') END = ?)) ORDER BY report.id DESC LIMIT 50`)
    .all(pipeline.created_by, pipeline.target, pipeline.run_id || '', pipeline.pipeline_id);
}

export function taskResultsSnapshot(db, pipeline) {
  return db.transaction(() => {
    const execution = taskExecutionSnapshot(db, pipeline);
    if (!execution) fail(409, '任务关联执行记录的所有者或目标不匹配，请核对来源');
    const linkedIds = [...new Set((pipeline.scan_task_id || '').split(',').map(id => id.trim()).filter(Boolean))];
    const scans = linkedIds.length ? db.prepare(`SELECT * FROM scan_tasks
      WHERE scan_task_id IN (${linkedIds.map(() => '?').join(',')}) AND created_by = ? AND target = ? ORDER BY scan_task_id`)
      .all(...linkedIds, pipeline.created_by, pipeline.target) : [];
    const scanIds = scans.map(scan => scan.scan_task_id);
    const scanResults = scanIds.length ? db.prepare(`SELECT * FROM scan_results WHERE scan_task_id IN (${scanIds.map(() => '?').join(',')}) ORDER BY id`).all(...scanIds) : [];
    const run = execution.run ? db.prepare('SELECT * FROM execution_runs WHERE run_id = ?').get(execution.run.run_id) : null;
    const records = table => run ? db.prepare(`SELECT * FROM ${table} WHERE run_id = ? ORDER BY id`).all(run.run_id) : [];
    const plan = approvedSource(db, pipeline, run);
    const analysis = json(pipeline.analysis_result, {});
    const risks = analysis && typeof analysis === 'object' ? analysis.risk_assessment : null;
    const candidateItems = Array.isArray(risks) ? risks : risks ? [risks] : [];
    const candidates = candidateItems.filter(candidate => typeof candidate === 'string' ? Boolean(candidate.trim())
      : candidate && typeof candidate === 'object' && !Array.isArray(candidate) && Object.keys(candidate).length > 0);
    const riskTypes = new Set(['vulnerability', 'web_vuln', 'sql_injection', 'misconfiguration', 'auth_finding', 'credential']);
    const scanCandidates = scanResults.filter(row => {
      const data = json(row.result_data);
      return riskTypes.has(row.result_type) && data && typeof data === 'object' && !Array.isArray(data);
    });
    const findings = scanCandidates.slice(0, 150).map((row, index) => {
      const data = json(row.result_data);
      return { id: `scan:${index}`, category: 'scan_candidate',
        name: row.result_type === 'credential' ? '凭证相关候选（不展示凭证内容）'
          : taskDisplayText(data.name || data.finding || data.template || row.result_type),
        severity: taskDisplayText(row.severity || data.severity), state: 'unreviewed', source: 'structured_scan',
        sources: [{ scan_task_id: row.scan_task_id, result_id: row.id, tool: taskDisplayText(row.source_tool),
          result_type: row.result_type, captured_at: row.captured_at || '' }],
        detail: '结构化扫描候选，不自动认定漏洞成立。' };
    });
    findings.push(...candidates.slice(0, 50).map((candidate, index) => ({ id: `analysis:${index}`, category: 'analysis_candidate',
      name: taskDisplayText(typeof candidate === 'string' ? candidate : candidate?.name || candidate?.title || candidate?.category || '分析候选'),
      severity: taskDisplayText(candidate?.severity || candidate?.level || ''), state: 'unreviewed', source: 'task_analysis', sources: [],
      detail: taskDisplayText(JSON.stringify(taskDisplayValue(candidate), null, 2)) })));
    const score = json(run?.score_data);
    const cachedScore = score && score.ok === true && score.runId === run?.run_id && Number.isFinite(score.percent) && score.percent >= 0 && score.percent <= 100
      ? { percent: score.percent, earned: Number.isFinite(score.earned) ? score.earned : null,
        total: Number.isFinite(score.total) ? score.total : null, source: 'stored_teaching_score' } : null;
    const fingerprint = createHash('sha256').update(JSON.stringify({ pipeline, scans, scanResults, run,
      steps: records('execution_steps'), attempts: records('execution_attempts'), evidence: records('evidence_records'), plan,
      playbook: run ? db.prepare('SELECT * FROM playbooks WHERE playbook_id = ?').get(run.playbook_id) : null,
      definitions: run ? db.prepare('SELECT * FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index').all(run.playbook_id) : [] })).digest('hex');
    return { version: 1, pipeline_id: pipeline.pipeline_id, owner: pipeline.created_by, target: taskDisplayText(pipeline.target),
      pipeline_status: pipeline.status, task_name: taskDisplayText(json(pipeline.config, {})?.task_name || pipeline.pipeline_id),
      source_fingerprint: fingerprint, captured_at: new Date().toISOString(), execution, findings,
      finding_count: scanCandidates.length + candidates.length,
      assessment: { risk_level: '未评级（需人工复核证据）', teaching_score: cachedScore,
        notice: '扫描和 AI 发现均为候选；工具成功、规则命中、教学得分及 MITRE 标签不等于漏洞成立。失败、未记录和未执行项不代表安全。' },
      trace: { plan, scan_source_count: scans.length, scan_sources: scans.slice(0, 200).map(row => ({ scan_task_id: row.scan_task_id, target: taskDisplayText(row.target), status: row.status })),
        scan_result_ids: scanResults.filter(row => !['raw_output', 'scan_error'].includes(row.result_type)).slice(0, 200).map(row => row.id),
        evidence_ids: execution.evidence.map(row => row.id), attempt_ids: execution.attempts.map(row => row.id) },
      reports: reportRows(db, pipeline).map(row => reportMetadata(db, row, pipeline)),
      limits: { findings: 200, scan_candidates: 150, analysis_candidates: 50, reports: 50, records: 200, text: 2000 } };
  })();
}

export function createTaskReport(db, pipeline, actor, body) {
  if (!body || typeof body.run_id !== 'string' || !/^[a-f0-9]{64}$/.test(body.source_fingerprint || '')
      || body.title !== undefined && (typeof body.title !== 'string' || !body.title.trim() || body.title.length > 120)) fail(400, '报告参数或来源指纹无效');
  return db.transaction(() => {
    const snapshot = taskResultsSnapshot(db, pipeline);
    if (!snapshot.execution.run || snapshot.execution.run.run_id !== body.run_id || snapshot.source_fingerprint !== body.source_fingerprint)
      fail(409, '任务或来源已变化，请刷新结果后重新确认生成');
    if (!['COMPLETED', 'FAILED', 'ABORTED'].includes(snapshot.execution.run.status)) fail(409, '执行尚未结束，不能生成结果报告');
    const existing = db.prepare("SELECT * FROM test_reports WHERE run_id = ? AND template = 'task_trace_v1' ORDER BY id DESC").all(body.run_id)
      .find(row => frozenContent(row, pipeline)?.provenance.source_fingerprint === snapshot.source_fingerprint);
    if (existing) return { pipeline_id: pipeline.pipeline_id, run_id: body.run_id, report: reportMetadata(db, existing, pipeline), reused: true };
    const { reports, ...results } = snapshot;
    const content = taskDisplayValue({ schema_version: 1, type: 'task_result_report',
      provenance: { pipeline_id: pipeline.pipeline_id, owner: pipeline.created_by, target: snapshot.target,
        run_id: body.run_id, playbook_id: snapshot.execution.run.playbook_id, plan: snapshot.trace.plan,
        source_fingerprint: snapshot.source_fingerprint, captured_at: snapshot.captured_at },
      notice: '此报告是脱敏、限长的来源快照，不是完整原始证据、审批结论或风险评级；历史快照不随后续记录变化自动更新。', results }, 0, 200);
    const reportId = `task_rpt_${randomUUID()}`;
    const title = taskDisplayText(body.title?.trim() || `任务结果记录 - ${snapshot.task_name}`).slice(0, 120);
    const now = new Date().toISOString();
    db.prepare(`INSERT INTO test_reports (report_id, title, run_id, template, status, content, generated_by, created_at, updated_at)
      VALUES (?, ?, ?, 'task_trace_v1', 'draft', ?, ?, ?, ?)`).run(reportId, title, body.run_id, JSON.stringify(content), actor.sub, now, now);
    db.prepare(`INSERT INTO audit_log (type, execution_id, run_id, user_role, target, reasons, timestamp)
      VALUES ('task_report_generate', ?, ?, ?, ?, ?, ?)`).run(reportId, body.run_id, actor.role, pipeline.target,
        JSON.stringify({ pipeline_id: pipeline.pipeline_id, actor: actor.sub, source_fingerprint: snapshot.source_fingerprint }), now);
    appendTaskLog(db, pipeline.pipeline_id, `保存任务结果报告草稿 · ${reportId}`);
    return { pipeline_id: pipeline.pipeline_id, run_id: body.run_id,
      report: reportMetadata(db, db.prepare('SELECT * FROM test_reports WHERE report_id = ?').get(reportId), pipeline), reused: false };
  })();
}

export function readTaskReport(db, pipeline, reportId) {
  const row = db.prepare(`SELECT report.* FROM test_reports AS report JOIN execution_runs AS run ON run.run_id = report.run_id
    WHERE report.report_id = ? AND run.user_sub = ? AND run.target = ? AND (report.scan_task_id IS NULL OR EXISTS (
      SELECT 1 FROM scan_tasks AS scan WHERE scan.scan_task_id = report.scan_task_id AND scan.created_by = run.user_sub AND scan.target = run.target))`).get(reportId, pipeline.created_by, pipeline.target);
  if (!row) fail(404, '报告不存在或不属于此任务');
  const content = frozenContent(row, pipeline);
  if (!content && (row.run_id !== pipeline.run_id || row.template === 'task_trace_v1')) fail(409, '报告缺少有效任务来源，不能作为本任务追溯快照');
  return { pipeline_id: pipeline.pipeline_id, owner: pipeline.created_by, target: taskDisplayText(pipeline.target),
    report: { ...reportMetadata(db, row, pipeline),
      content: content || { schema_version: 0,
      notice: '旧报告只与当前 Run 关联，缺少完整任务及批准预案来源；原结论未重新验证，不支持追溯快照导出。',
      stored: taskDisplayValue(json(row.content, { notice: '原报告 JSON 不可解析' })) } } };
}

export function recordTaskReportExport(db, document, actor, format) {
  const report = document.report;
  db.prepare(`INSERT INTO audit_log (type, execution_id, run_id, user_role, target, reasons, timestamp)
    VALUES ('task_report_export', ?, ?, ?, ?, ?, ?)`).run(report.report_id, report.run_id, actor.role, document.target,
      JSON.stringify({ pipeline_id: document.pipeline_id, actor: actor.sub, format, source_fingerprint: report.source_fingerprint }), new Date().toISOString());
  appendTaskLog(db, document.pipeline_id, `请求导出已保存的报告快照 · ${report.report_id} · ${format.toUpperCase()}`);
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
}

export function taskReportHtml(document) {
  const report = document.report;
  const content = report.content;
  const results = content.results;
  const table = (title, headers, rows) => `<h2>${escapeHtml(title)}</h2><table><thead><tr>${headers.map(value => `<th>${escapeHtml(value)}</th>`).join('')}</tr></thead><tbody>${rows.map(row => `<tr>${row.map(value => `<td>${escapeHtml(value)}</td>`).join('')}</tr>`).join('')}</tbody></table>`;
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>${escapeHtml(report.title)}</title><style>body{font:15px sans-serif;max-width:1100px;margin:32px auto;padding:0 20px;color:#1e293b}table{border-collapse:collapse;width:100%;margin:16px 0}th,td{border:1px solid #dbe5f0;padding:8px;text-align:left}th{background:#eff6ff}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f8fafc;padding:16px}.notice{background:#fffbeb;padding:16px}</style></head><body>
    <h1>${escapeHtml(report.title)}</h1><p>报告 ${escapeHtml(report.report_id)} · ${escapeHtml(report.status)} · ${escapeHtml(report.generated_by)}</p>
    <p class="notice">${escapeHtml(content.notice)}<br>${escapeHtml(results.assessment.notice)}</p>
    <h2>来源链</h2><pre>${escapeHtml(JSON.stringify(content.provenance, null, 2))}</pre>
    <p>Run 状态：${escapeHtml(results.execution.run.status)} · 风险：${escapeHtml(results.assessment.risk_level)} · 教学得分：${escapeHtml(results.assessment.teaching_score?.percent ?? '未记录')}</p>
    ${table('发现候选（未复核）', ['类别', '名称', '风险标签', '来源'], results.findings.map(row => [row.category, row.name, row.severity, row.source]))}
    ${table('工具结果（不是漏洞验证结论）', ['步骤', '工具', '工具状态', '尝试编号', '退出码'], results.execution.steps.map(row => [row.step_index, row.tool_id, row.state, row.attempt_id, row.exit_code]))}
    ${table('证据来源', ['证据编号', 'Run', '步骤', '工具', '尝试编号', '来源校验', '采集时间'], results.execution.evidence.map(row => [row.id, row.run_id, row.step_index, row.tool_id, row.attempt_id, row.source_state, row.recorded_at]))}
    <h2>展示范围</h2><pre>${escapeHtml(JSON.stringify(results.limits, null, 2))}</pre>
    <details><summary>完整展示快照（已脱敏且限长，不是原始证据）</summary><pre>${escapeHtml(JSON.stringify(content, null, 2))}</pre></details></body></html>`;
}
