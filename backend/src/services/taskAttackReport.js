export const TASK_ATTACK_REPORT_TITLE = '任务攻击测试结果报告';

const rows = value => Array.isArray(value) ? value.filter(item => item && typeof item === 'object' && !Array.isArray(item)) : [];
const text = value => value === undefined || value === null || value === '' ? '未记录' : String(value);
const recorded = value => value !== undefined && value !== null && value !== '';
const counter = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
const summary = (value, limit = 160) => {
  const result = text(value).replace(/\s+/g, ' ').trim();
  return result.length > limit ? result.slice(0, limit) + '…（摘要，明细见 JSON）' : result;
};
const recordId = value => recorded(value) ? String(value).replace(/^scan:/, '') : null;
const statuses = {
  achieved: '达到预期效果', not_achieved: '未达到预期效果', inconclusive: '证据不足',
  not_performed: '未开展适用攻击测试', pending: '进行中',
};
const parse = value => { try { return typeof value === 'string' ? JSON.parse(value) : value; } catch { return null; } };

function sourceRecords(results) {
  const records = new Map();
  for (const item of rows(results.scan_records)) records.set(recordId(item.id), item);
  for (const finding of rows(results.findings)) {
    const key = recordId(finding.id);
    const saved = records.get(key) || {};
    records.set(key, { ...saved, finding });
  }
  return records;
}

function collectAttempts(results) {
  const full = Array.isArray(results.verification_attempts);
  const attempts = [], positions = new Map();
  const add = (entry, fallbackFinding, legacy) => {
    const attemptId = legacy ? entry.attempt_id : entry.attempt_id ?? entry.id;
    const item = { ...entry, attempt_id: recorded(attemptId) ? String(attemptId) : null,
      finding_id: recordId(entry.finding_id ?? fallbackFinding ?? entry.result?.object?.finding_id) };
    // A v1 verification aggregate ID is never an execution-attempt ID.
    const key = item.attempt_id ? `attempt:${item.attempt_id}` : `unstarted:${item.finding_id}`;
    if (!positions.has(key)) { positions.set(key, attempts.length); attempts.push(item); }
  };
  if (full) for (const item of rows(results.verification_attempts)) add(item, null, false);
  const covered = new Set(attempts.map(item => item.finding_id));
  for (const finding of [...rows(results.scan_records), ...rows(results.findings)]) {
    const verification = finding.verification;
    if (!verification || typeof verification !== 'object') continue;
    const id = recordId(finding.id);
    // Full v2 history wins. Only a saved summary without a launched attempt may
    // supplement it; never append a duplicate latest-attempt aggregate.
    if (full && (covered.has(id) || recorded(verification.attempt_id))) continue;
    add(verification, finding.id, true);
  }
  return { attempts, full };
}

function effect(entry) {
  const result = entry.result;
  const sameFinding = !recorded(result?.object?.finding_id) || !entry.finding_id
    || recordId(result.object.finding_id) === entry.finding_id;
  const valid = result?.schema_version === 1 && sameFinding && entry.source_valid !== false;
  const accessibility = result?.objective?.category === 'accessibility';
  const operations = rows(result?.operations);
  const launched = entry.started === true || operations.some(operation => operation.started === true) ? true
    : entry.started === false || operations.length && operations.every(operation => operation.started === false) ? false : null;
  const applicable = valid && !accessibility && result.status !== 'not_performed'
    && ['effect', 'configuration_exposure'].includes(result.objective?.category);
  const applicabilityUnknown = valid && !accessibility && result.status !== 'not_performed'
    && !['effect', 'configuration_exposure'].includes(result.objective?.category);
  const started = applicable && launched === true;
  let status = 'inconclusive', reason;
  if (!sameFinding || entry.source_valid === false) reason = '保存的验证来源无法可靠核对，未据此认定攻击效果。';
  else if (result?.schema_version !== 1) reason = '该历史记录未保存受支持的系统效果结果。';
  else if (accessibility) { status = 'not_performed'; reason = result.reason || '仅记录页面访问，未开展适用的效果验证。'; }
  else if (Object.hasOwn(statuses, result.status)) {
    status = result.status; reason = result.reason;
    if (['achieved', 'not_achieved'].includes(status) && (!started || !recorded(result.criterion?.id)
        || !Number.isSafeInteger(result.criterion?.version) || result.criterion.version < 1)) {
      status = 'inconclusive'; reason = '缺少适用判据或实际启动记录，不能确认达到或未达到预期效果。';
    }
  } else reason = '保存的系统效果状态未记录或不受支持。';
  return { status, started, valid, reason: text(reason), launched, applicable, applicabilityUnknown };
}

function savedTestPeriod(results) {
  const attempts = collectAttempts(results).attempts;
  const first = [results.execution?.run?.created_at, ...attempts.map(item => item.created_at)]
    .filter(item => typeof item === 'string' && Number.isFinite(Date.parse(item))).sort((a, b) => Date.parse(a) - Date.parse(b))[0];
  const last = [results.execution?.run?.updated_at, ...attempts.map(item => item.completed_at)]
    .filter(item => typeof item === 'string' && Number.isFinite(Date.parse(item))).sort((a, b) => Date.parse(b) - Date.parse(a))[0];
  if (first && last && Date.parse(last) < Date.parse(first)) return '未记录（保存的时间范围无法核对）';
  return first || last ? `${first || '起始未记录'} 至 ${last || '结束未记录'}` : '未记录';
}

function savedLocation(identity) {
  if (!identity || typeof identity !== 'object') return null;
  return identity.url || (identity.file ? `${identity.file}${recorded(identity.line) ? ':' + identity.line : ''}` : null)
    || (identity.host ? `${identity.host}${recorded(identity.port) ? ':' + identity.port : ''}` : null) || identity.target || null;
}

function describeFinding(group, recordMap) {
  const sources = group.finding_ids.map(id => recordMap.get(id)).filter(Boolean);
  const finding = sources.find(item => item.finding)?.finding;
  const scan = sources.find(item => item.result_data);
  const data = parse(scan?.result_data) || {};
  const name = [finding?.name, data.name, data.info?.name, data.finding, data.title, data.message,
    data.template, data['template-id'], data.rule, data.rule_id, group.instance?.identity?.rule,
    group.instance?.identity?.rule_id].find(item => typeof item === 'string' && item.trim()) || '保存的漏洞候选';
  const findingLocation = savedLocation(group.instance?.identity) || savedLocation(data);
  const location = group.target ? '实际测试入口：' + summary(group.target)
    : `发现位置：${summary(findingLocation)}；实际测试入口：未记录`;
  return `${summary(name, 100)}\n${location}\n${group.instance_id ? '漏洞实例：' + group.instance_id : '未归并发现记录：' + group.finding_ids.join(', ')}`;
}

function actualEffect(entry, projected) {
  const result = entry.result || {}, parts = [summary(projected.reason)];
  for (const observation of rows(result.observed_facts)) {
    const facts = [];
    if (recorded(observation.method)) facts.push(text(observation.method));
    if (recorded(observation.status_code)) facts.push('HTTP ' + observation.status_code);
    if (typeof observation.complete === 'boolean') facts.push(observation.complete ? '响应采集完整' : '响应采集不完整');
    if (facts.length) parts.push(facts.join('，') + '（仅为观察）');
  }
  for (const check of rows(result.checks)) parts.push(summary(`${text(check.label || check.id)}：${text(check.detail || check.status)}`, 110));
  // Bound the narrative, but keep the exact latest attempt and evidence references.
  const narrative = summary(parts.join('；'), 300);
  const evidenceIds = Array.isArray(result.evidence_ids) ? result.evidence_ids : Array.isArray(entry.evidence_ids) ? entry.evidence_ids : [];
  const references = values => [...new Set(values.filter(id => Number.isSafeInteger(id) && id > 0))];
  const judged = references(evidenceIds);
  const observed = references([...rows(result.observed_facts).map(item => item.evidence_id),
    ...rows(result.operations).flatMap(item => Array.isArray(item.evidence_ids) ? item.evidence_ids : [])]);
  return `${narrative}\n尝试：${text(entry.attempt_id)}；判定证据：${judged.length ? judged.join(', ') : '未记录'}`
    + (observed.length ? `；观察/操作证据：${observed.join(', ')}（不等于判定成立）` : '');
}

export function buildTaskAttackReportData(document) {
  const content = document?.report?.content;
  if (document?.report?.kind !== 'trace_snapshot' || ![1, 2].includes(content?.schema_version) || !content.results)
    throw Object.assign(new Error('报告缺少有效的任务攻击测试快照'), { status: 409 });
  const results = content.results, instances = rows(results.instances), records = sourceRecords(results);
  const mapped = new Map(), ambiguous = new Set();
  for (const instance of instances) for (const id of Array.isArray(instance.record_ids) ? instance.record_ids : []) {
    const key = recordId(id);
    if (mapped.has(key) && mapped.get(key).instance_id !== instance.instance_id) ambiguous.add(key);
    else if (recorded(instance.instance_id)) mapped.set(key, instance);
  }
  for (const key of ambiguous) mapped.delete(key);
  const { attempts, full } = collectAttempts(results);
  const groups = new Map(), limitations = [];
  const startedInstances = new Set(), startedUnmapped = new Set(), startedIds = new Set();
  let unmappedStartedAttempts = 0, uncertain = false;
  for (let index = 0; index < attempts.length; index++) {
    const entry = attempts[index], result = entry.result || {}, projected = effect(entry);
    const instance = mapped.get(entry.finding_id), target = recorded(result.object?.target) ? String(result.object.target) : null;
    const objectiveId = recorded(result.objective?.id) ? String(result.objective.id) : null;
    const reliableObjective = objectiveId && objectiveId !== 'unavailable_effect' ? objectiveId
      : !objectiveId && recorded(result.criterion?.id) ? String(result.criterion.id) : null;
    const objectiveKey = reliableObjective || `unknown:${entry.attempt_id || index}`;
    const subjectKey = instance ? `instance:${instance.instance_id}` : `record:${entry.finding_id || 'unknown-' + index}`;
    // A criterion version change is a retry of the same objective, rather than
    // another target. Distinct saved entry points and objectives remain distinct.
    const targetKey = target ?? `unknown-entry:${entry.attempt_id || index}`;
    const key = JSON.stringify([subjectKey, targetKey, objectiveKey]);
    if (!groups.has(key)) groups.set(key, { instance_id: instance?.instance_id || null, instance,
      finding_ids: [], target, objective_id: objectiveId, attempt_ids: [], attempt_count: 0, started_attempt_count: 0,
      startup_unknown: false });
    const group = groups.get(key);
    if (entry.finding_id && !group.finding_ids.includes(entry.finding_id)) group.finding_ids.push(entry.finding_id);
    if (entry.attempt_id) { group.attempt_count++; group.attempt_ids.push(entry.attempt_id); }
    if (projected.started) {
      group.started_attempt_count++;
      startedIds.add(entry.attempt_id || `unknown-${index}`);
      if (instance) startedInstances.add(instance.instance_id);
      else { startedUnmapped.add(entry.finding_id || `unknown-${index}`); unmappedStartedAttempts++; }
    }
    if (!projected.valid || projected.applicabilityUnknown || projected.applicable && projected.launched === null) group.startup_unknown = true;
    if (!projected.valid || !instance || !target || projected.started && !entry.attempt_id
        || projected.applicabilityUnknown || projected.applicable && projected.launched === null) uncertain = true;
    // The array is the saved chronological history. Its last result always wins;
    // an earlier success cannot override a later failure or unperformed attempt.
    Object.assign(group, { latest: entry, status: projected.status, latest_attempt_id: entry.attempt_id,
      criterion_id: recorded(result.criterion?.id) ? String(result.criterion.id) : null,
      criterion_version: result.criterion?.version ?? null, projected });
  }
  const attackRows = [...groups.values()].map(group => {
    const result = group.latest.result || {}, operations = rows(result.operations);
    const operationText = operations.map(item => {
      const state = item.started === true ? group.projected.valid ? '已执行' : '记录标为已执行（来源未核对）'
        : item.started === false ? '未启动' : '启动未知';
      return `${state}：${summary(item.name || item.tool_id || item.step_id, 90)}`;
    }).join('；');
    const operationKind = result.objective?.category === 'accessibility' ? '仅页面探测；' : '';
    const expected = `${summary(result.objective?.label)}\n目标：${text(group.objective_id)}；判据：${text(group.criterion_id)} / v${text(group.criterion_version)}`;
    const startup = group.startup_unknown ? group.started_attempt_count
      ? `已核对启动 ${group.started_attempt_count} 次，另有启动未知记录` : '适用攻击启动次数未知'
      : `实际启动适用攻击 ${group.started_attempt_count} 次`;
    return { ...group, finding: describeFinding(group, records),
      operation: `${operationKind}${summary(operationText || '操作未记录')}\n${startup}；保存尝试 ${group.attempt_count} 次`,
      expected, actual: actualEffect(group.latest, group.projected), result_label: statuses[group.status] };
  });
  const latestResults = { achieved: 0, not_achieved: 0, inconclusive: 0, not_performed: 0, pending: 0 };
  for (const group of attackRows) latestResults[group.status]++;
  const knownFull = full && !!results.statistics && !uncertain;
  if (!full) limitations.push('该历史报告未记录完整逐漏洞尝试历史；仅概述已保存的验证摘要，数量不代表完整测试历史。');
  if (!attempts.length) limitations.push('未保存逐漏洞攻击记录。');
  if (!attempts.length && results.execution?.run) limitations.push('主执行 Run 缺少逐漏洞攻击关联，实际攻击数量未知。');
  if (attempts.some(entry => !effect(entry).valid)) limitations.push('部分记录缺少有效系统结果或来源无法核对，未据此计入实际攻击或判定达成。');
  if (attempts.some(entry => !recorded(entry.result?.object?.target))) limitations.push('部分攻击记录的实际测试入口未记录，来源不完整，不能可靠合并为同一入口的重试。');
  if (attempts.some(entry => effect(entry).applicable && effect(entry).launched === null)) limitations.push('部分适用攻击记录的实际启动情况未知，未计入可核对启动次数。');
  if (attempts.some(entry => effect(entry).applicabilityUnknown)) limitations.push('部分已保存操作缺少明确验证目标，攻击适用性未知，不能据此报告确定的攻击总次数。');
  if (attempts.some(entry => entry.result?.objective?.id === 'unavailable_effect'
      || !recorded(entry.result?.objective?.id) && !recorded(entry.result?.criterion?.id)))
    limitations.push('部分尝试缺少可靠目标标识，逐条列示，不合并为同一目标的重试。');
  if (attempts.some(entry => !mapped.has(entry.finding_id))) limitations.push('未归并条目以发现记录为单位单独列示，不能计作已确认的漏洞实例总数。');
  const scannedRecords = counter(results.statistics?.findings?.records) ?? counter(results.scan_summary?.categories?.vulnerability)
    ?? (Array.isArray(results.scan_records) ? rows(results.scan_records).filter(item => item.category === 'vulnerability').length : null);
  const noLinkedRun = !attempts.length && !!results.execution?.run;
  const startedAttemptCount = startedIds.size || knownFull && !noLinkedRun ? startedIds.size : null;
  const startedInstanceCount = Array.isArray(results.instances) && (startedInstances.size || knownFull && !noLinkedRun) ? startedInstances.size : null;
  return { stats: { scanned_records: scannedRecords,
    vulnerability_instances: Array.isArray(results.instances) ? instances.length : counter(results.statistics?.findings?.instances),
    started_instances: startedInstanceCount, started_attempts: startedAttemptCount,
    unmapped_started_records: startedUnmapped.size, unmapped_started_attempts: unmappedStartedAttempts,
    effect_targets: attackRows.length, latest_results: latestResults, counts_complete: knownFull && !noLinkedRun },
  rows: attackRows, limitations };
}

export function buildTaskAttackReport(document) {
  const data = buildTaskAttackReportData(document), stats = data.stats, results = document.report.content.results;
  const count = (number, unit) => number === null ? '未知' : `${number} ${unit}`;
  const overview = [
    `任务：${summary(results.task_name || document.pipeline_id)}；目标：${summary(document.target)}`,
    ...(recorded(document.report.content.provenance?.task_no || results.task_no)
      ? [`任务ID：${text(document.report.content.provenance?.task_no || results.task_no)}`] : []),
    `报告：${text(document.report.report_id)}；保存时间：${text(document.report.created_at || document.report.content.provenance?.captured_at)}`,
    `测试时间：${savedTestPeriod(results)}；环境：${summary(results.baseline?.environment_id || results.statistics?.baseline?.environment_id)}；环境版本：${summary(results.baseline?.environment_version || results.statistics?.baseline?.environment_version)}。`,
    `扫描候选记录：${count(stats.scanned_records, '条')}；已归并漏洞实例：${count(stats.vulnerability_instances, '个')}。`,
  ];
  if (data.rows.length) {
    overview.push(`可核对实际开展攻击测试的漏洞实例：${count(stats.started_instances, '个')}；可核对适用攻击启动次数：${count(stats.started_attempts, '次')}。`);
    if (!stats.counts_complete) overview.push('数量仅表示已保存且可核对部分，不能作为完整总量。');
    if (stats.unmapped_started_records) overview.push(`另有未归并攻击发现记录 ${stats.unmapped_started_records} 条、实际启动 ${stats.unmapped_started_attempts} 次，未并入漏洞实例数。`);
  } else overview.push('未保存逐漏洞攻击记录；不能仅凭扫描结果或工具执行状态认定已开展攻击。');
  overview.push(`最新效果目标共 ${stats.effect_targets} 条（按漏洞或记录、测试入口和目标分别计数）：达到 ${stats.latest_results.achieved}，未达到 ${stats.latest_results.not_achieved}，证据不足 ${stats.latest_results.inconclusive}，未开展 ${stats.latest_results.not_performed}，进行中 ${stats.latest_results.pending}。`);
  const conclusions = [];
  const conclusionLabels = { achieved: '已证明的效果', not_achieved: '未达到的效果', inconclusive: '尚不能证明的效果',
    not_performed: '未开展的攻击测试', pending: '仍在进行的测试' };
  for (const [status, title] of Object.entries(conclusionLabels)) {
    const selected = data.rows.filter(item => item.status === status);
    if (!selected.length) continue;
    const examples = selected.slice(0, 2).map(item => {
      const objective = summary(item.latest.result?.objective?.label, 70), target = summary(item.target, 100);
      const reason = `；${status === 'achieved' ? '依据' : '原因'}：${summary(item.projected.reason, 100)}`;
      return `${objective}（入口：${target}${reason}）`;
    });
    conclusions.push(`${title}：${examples.join('；')}。${selected.length > examples.length ? `其余 ${selected.length - examples.length} 项见逐漏洞效果表。` : ''}`);
  }
  if (data.rows.length) conclusions.push('结论仅对应表中保存的具体目标；工具成功、HTTP 200 和历史成功记录均不能替代本次攻击效果。');
  else conclusions.push('本报告未保存可逐漏洞追溯的攻击效果，不能由扫描发现或主执行 Run 推断利用成功。');
  conclusions.push(...data.limitations, '本报告为简要结果摘要；完整已保存快照、尝试历史及其他资料可导出 JSON 查看。');
  return { schema_version: 1, title: TASK_ATTACK_REPORT_TITLE, sections: [
    { title: '本次攻击测试概况', paragraphs: overview },
    { title: '逐漏洞攻击效果表', headers: ['漏洞及位置', '实施操作', '预期效果', '实际效果与证据', '结果'],
      rows: data.rows.map(item => [item.finding, item.operation, item.expected, item.actual, item.result_label]),
      paragraphs: data.rows.length ? ['同一漏洞、入口和目标的重复尝试合并，展示最新结果；不同目标分别列示。'] : ['未保存逐漏洞攻击记录。'] },
    { title: '攻击测试结论', paragraphs: conclusions },
  ] };
}

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g,
  character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]);
export function taskAttackReportHtml(document) {
  const presentation = buildTaskAttackReport(document);
  const body = presentation.sections.map(section => `<section><h2>${escapeHtml(section.title)}</h2>`
    + (section.paragraphs || []).map(item => `<p>${escapeHtml(item)}</p>`).join('')
    + (section.headers && section.rows.length ? `<table><thead><tr>${section.headers.map(item => `<th>${escapeHtml(item)}</th>`).join('')}</tr></thead><tbody>${section.rows.map(row => `<tr>${row.map(item => `<td>${escapeHtml(item)}</td>`).join('')}</tr>`).join('')}</tbody></table>` : '') + '</section>').join('');
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>${escapeHtml(presentation.title)}</title><style>body{font:14px sans-serif;max-width:1200px;margin:28px auto;padding:0 20px;color:#1e293b}table{border-collapse:collapse;width:100%;table-layout:fixed}th,td{border:1px solid #cbd5e1;padding:8px;text-align:left;white-space:pre-wrap;overflow-wrap:anywhere;vertical-align:top}th{background:#eff6ff}th:nth-child(1){width:20%}th:nth-child(2){width:17%}th:nth-child(3){width:21%}th:nth-child(4){width:30%}th:nth-child(5){width:12%}thead{display:table-header-group}p{white-space:pre-wrap}</style></head><body><h1>${escapeHtml(presentation.title)}</h1>${body}</body></html>`;
}
