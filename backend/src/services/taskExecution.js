import {findingVerificationExecution} from './findingVerificationExecution.js';
import { sanitizeTaskLog } from './taskActivity.js';
import { summarizeRunResultCounts } from './runResultCounts.js';

function parse(value, fallback = null) {
  try { return typeof value === 'string' ? JSON.parse(value) : value ?? fallback; } catch { return fallback; }
}

function text(value) {
  return sanitizeTaskLog(String(value ?? '')
    .replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?(?:-----END [^-]*PRIVATE KEY-----|$)/g, '[私钥已隐藏]')
    .replace(/((?:--(?:password|passwd|token|secret|cookie|api-key)|-p|-l)(?:\s+|=))(?:"[^"]*"|'[^']*'|\S+)/gi, '$1[已隐藏]')
    .replace(/((?:username|login|token)["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s&,;]+)/gi, '$1[已隐藏]'));
}

function safeValue(value, depth = 0, arrayLimit = 50) {
  if (depth > 8) return '[深层内容已省略]';
  if (typeof value === 'string') return text(value);
  if (Array.isArray(value)) return value.slice(0, arrayLimit).map((entry, index) =>
    typeof value[index - 1] === 'string' && /^(?:--(?:password|passwd|token|secret|cookie|api-key)|-p|-l)$/i.test(value[index - 1])
      ? '[已隐藏]' : safeValue(entry, depth + 1, arrayLimit))
    .concat(value.length > arrayLimit ? ['[更多项已省略]'] : []);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 100).map(([key, entry]) =>
    [text(key), ['cookie_attributes_complete','login_form_present'].includes(key) && typeof entry==='boolean' ? entry : key==='cookie_attributes' && Array.isArray(entry) ? entry.slice(0,20).map(c=>({name:text(c?.name),httponly:c?.httponly===true,secure:c?.secure===true}))
      : key==='cookie_name' && typeof entry==='string' && /^[!#$%&'*+.^_`|~\w-]{1,128}$/.test(entry) ? entry : /password|passwd|secret|token|cookie|authorization|api.?key|credential|private.?key|username|login/i.test(key)
      ? '[已隐藏]' : safeValue(entry, depth + 1, arrayLimit)]));
  return value;
}

export { text as taskDisplayText, safeValue as taskDisplayValue };

function displayedJson(value) {
  const decoded = parse(value);
  return decoded === null ? text(value) : text(JSON.stringify(safeValue(decoded), null, 2));
}

function outcome(value) {
  return value === true || value === 1 ? 'SUCCEEDED' : value === false || value === 0 ? 'FAILED' : 'UNKNOWN';
}

export function taskExecutionSnapshot(db, pipeline) {
  return db.transaction(() => {
    const plan = db.prepare('SELECT state, revision, approved_playbook_id FROM task_plans WHERE pipeline_id = ?').get(pipeline.pipeline_id);
    const config = parse(pipeline.config, {}) || {};
    const snapshot = { version: 1, pipeline_id: pipeline.pipeline_id, task_no: pipeline.task_no || null, target: text(pipeline.target), owner: pipeline.created_by,
      pipeline_status: pipeline.status, plan: plan ? { state: plan.state, revision: plan.revision } : null,
      requires_approval: config.require_approval !== false, run: null, steps: [], attempts: [], evidence: [], preflight: [],
      limits: { records: 200, text: 2000 }, verification_runs:findingVerificationExecution(db,pipeline), captured_at: new Date().toISOString() };
    if (!pipeline.run_id) return snapshot;
    const run = db.prepare('SELECT * FROM execution_runs WHERE run_id = ? AND user_sub = ? AND target = ?')
      .get(pipeline.run_id, pipeline.created_by, pipeline.target);
    if (!run) return null;
    const playbook = db.prepare('SELECT name FROM playbooks WHERE playbook_id = ?').get(run.playbook_id);
    const planned = db.prepare('SELECT step_index, step_id, name, tool_id, args_template, optional FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index')
      .all(run.playbook_id);
    const results = db.prepare('SELECT * FROM execution_steps WHERE run_id = ? ORDER BY step_index, id').all(run.run_id);
    const sensitiveRecords = db.prepare('SELECT attempt_id, step_index, evidence_type FROM evidence_records WHERE run_id = ?').all(run.run_id)
      .filter(row => /credential|password|session|cookie/i.test(row.evidence_type || ''));
    const sensitiveAttempts = new Set(sensitiveRecords.filter(row => row.attempt_id).map(row => row.attempt_id));
    const sensitiveLegacySteps = new Set(sensitiveRecords.filter(row => !row.attempt_id).map(row => row.step_index));
    const hiddenOutput = '[凭证或会话输出已隐藏]';
    const latest = new Map(results.map(row => [row.step_index, row]));
    const knownIndices = [...new Set([...planned.map(row => row.step_index), ...latest.keys()])].sort((first, second) => first - second);
    const resultCounts = summarizeRunResultCounts(results, run.status, { knownStepCount: knownIndices.length });
    const finalSummary = parse(run.final_summary, {}) || {};
    snapshot.run = { run_id: run.run_id, playbook_id: run.playbook_id, playbook_name: text(playbook?.name || run.playbook_id),
      status: run.status, engine_type: text(run.engine_type), preflight_status: text(run.preflight_status),
      stop_reason: text(run.stop_reason || finalSummary.error || finalSummary.stopReason || ''),
      created_at: run.created_at, updated_at: run.updated_at,
      approved_snapshot: Boolean(plan?.state === 'approved' && plan.approved_playbook_id === run.playbook_id),
      counts: { steps: resultCounts.known, returned: resultCounts.returned,
        succeeded: resultCounts.succeeded, failed: resultCounts.failed, pending: resultCounts.pending,
        count_consistent: resultCounts.count_consistent, terminal_pending: resultCounts.terminal_pending,
        requires_attention: resultCounts.requires_attention, duplicate_records: resultCounts.duplicate_records,
        attempts: db.prepare('SELECT COUNT(*) AS count FROM execution_attempts WHERE run_id = ?').get(run.run_id).count,
        evidence: db.prepare('SELECT COUNT(*) AS count FROM evidence_records WHERE run_id = ?').get(run.run_id).count } };
    const checks = parse(run.preflight_data, []);
    snapshot.preflight = Array.isArray(checks) ? checks.slice(0, 50).map(check => ({ name: text(check?.name),
      state: check?.skipped === true ? 'SKIPPED' : check?.passed === true ? 'PASSED' : check?.passed === false ? 'FAILED' : 'UNKNOWN',
      message: text(check?.message) })) : [];
    snapshot.steps = knownIndices.slice(0, 200).map(index => {
      const definition = planned.find(row => row.step_index === index);
      const result = latest.get(index);
      return { step_index: index, name: text(definition?.name), tool_id: text(result?.tool_id || definition?.tool_id),
        optional: definition ? Boolean(definition.optional) : null, source: result?.source || (definition ? 'playbook' : 'unknown'),
        state: result ? outcome(result.success) : ['PENDING', 'RUNNING'].includes(run.status) ? 'WAITING' : 'NOT_RECORDED',
        args: result ? displayedJson(result.args) : '', template: displayedJson(definition?.args_template || ''),
        output: result && (sensitiveAttempts.has(result.attempt_id) || sensitiveLegacySteps.has(index)) ? hiddenOutput : text(result?.notes),
        exit_code: result?.exit_code ?? null, attempt_id: result?.attempt_id ?? null,
        executed_at: result?.executed_at ?? null };
    });
    snapshot.attempts = db.prepare('SELECT * FROM execution_attempts WHERE run_id = ? ORDER BY id DESC LIMIT 200').all(run.run_id)
      .reverse().map(row => ({ id: row.id, run_id: row.run_id, step_index: row.step_index, tool_id: text(row.tool_id),
        source: row.source, state: outcome(row.success), args: displayedJson(row.args),
        stdout: sensitiveAttempts.has(row.id) || sensitiveLegacySteps.has(row.step_index) ? hiddenOutput : text(row.stdout),
        stderr: sensitiveAttempts.has(row.id) || sensitiveLegacySteps.has(row.step_index) ? hiddenOutput : text(row.stderr),
        execution_mode: text(row.execution_mode), exit_code: row.exit_code, duration_ms: row.duration_ms,
        started_at: row.started_at, completed_at: row.completed_at }));
    snapshot.evidence = db.prepare('SELECT * FROM evidence_records WHERE run_id = ? ORDER BY id DESC LIMIT 200').all(run.run_id)
      .reverse().map(row => {
        const attempt = row.attempt_id ? db.prepare('SELECT run_id, step_index, tool_id, execution_mode FROM execution_attempts WHERE id = ?').get(row.attempt_id) : null;
        const linked = attempt?.run_id === run.run_id && attempt.step_index === row.step_index && attempt.tool_id === row.tool_id;
        const targetMatches = row.target === pipeline.target;
        const sensitive = /credential|password|session|cookie/i.test(row.evidence_type || '')
          || sensitiveAttempts.has(row.attempt_id) || sensitiveLegacySteps.has(row.step_index);
        const hidden = !targetMatches || row.attempt_id && !linked ? '[来源不匹配，内容不展示]' : '[凭证或会话内容已隐藏]';
        const suppress = sensitive || !targetMatches || row.attempt_id && !linked;
        return { id: row.id, run_id: row.run_id, step_index: row.step_index, tool_id: text(row.tool_id),
          attempt_id: row.attempt_id, source_state: !targetMatches ? 'target_mismatch' : !row.attempt_id ? 'legacy' : linked ? 'linked' : 'mismatch',
          evidence_type: text(row.evidence_type), execution_mode: linked ? text(attempt.execution_mode) : '',
          target: text(row.target), recorded_at: row.recorded_at,
          data: suppress ? hidden : displayedJson(row.evidence_data), stdout: suppress ? hidden : text(row.raw_stdout),
          stderr: suppress ? hidden : text(row.raw_stderr), mitre_hits: suppress ? '' : displayedJson(row.mitre_hits),
          recommendations: suppress ? '' : displayedJson(row.recommendations), rule_matches: suppress ? '' : displayedJson(row.rule_matches) };
      });
    return snapshot;
  })();
}
