import { pipelineScans } from './scanResultQuery.js';
import { summarizeScanRecords } from './scanResultCatalog.js';
import { getWsManager } from './wsManager.js';

export function broadcastTaskEvent(db, event, data) {
  const ws = getWsManager();
  if (!ws) return;
  const pipeline = db.prepare('SELECT created_by FROM pipelines WHERE pipeline_id = ?').get(data.pipeline_id);
  if (!pipeline) return;
  ws.broadcastToRole('admin', event, data);
  if (pipeline.created_by) {
    const owner = db.prepare('SELECT role FROM users WHERE username = ?').get(pipeline.created_by);
    if (owner?.role !== 'admin') ws.broadcastToUser(pipeline.created_by, event, data);
  }
}

export function sanitizeTaskLog(message) {
  return String(message)
    .replace(/\b(https?:\/\/)[^\s/@]+:[^\s/@]+@/gi, '$1[已隐藏]@')
    .replace(/\bBearer\s+[a-z0-9._~+/=-]+/gi, 'Bearer [已隐藏]')
    .replace(/((?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret|authorization|cookie)["']?\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s&,;]+)/gi, '$1[已隐藏]')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '')
    .slice(0, 2000);
}

export function appendTaskLog(db, pipelineId, message, level = 'info') {
  const row = db.transaction(() => {
    if (!db.prepare('SELECT pipeline_id FROM pipelines WHERE pipeline_id = ?').get(pipelineId)) return null;
    const safeLevel = ['info', 'warn', 'error'].includes(level) ? level : 'info';
    const safeMessage = sanitizeTaskLog(message);
    const timestamp = new Date().toISOString();
    const result = db.prepare('INSERT INTO pipeline_logs (pipeline_id, level, message, created_at) VALUES (?, ?, ?, ?)')
      .run(pipelineId, safeLevel, safeMessage, timestamp);
    db.prepare(`DELETE FROM pipeline_logs WHERE pipeline_id = ? AND id < COALESCE(
      (SELECT id FROM pipeline_logs WHERE pipeline_id = ? ORDER BY id DESC LIMIT 1 OFFSET 1999), 0)`)
      .run(pipelineId, pipelineId);
    return { id: Number(result.lastInsertRowid), pipeline_id: pipelineId, level: safeLevel, message: safeMessage, created_at: timestamp };
  })();
  if (row) broadcastTaskEvent(db, 'pipeline:log', row);
  return row;
}

export function taskSummary(db, pipeline) {
  const scanIds=pipelineScans(db,pipeline).map(s=>s.scan_task_id);
  const scanRows=scanIds.length ? db.prepare(`SELECT result_type,severity FROM scan_results WHERE scan_task_id IN (${scanIds.map(()=>'?').join(',')})`).all(...scanIds) : [];
  const counts=summarizeScanRecords(scanRows);
  const scanFindings=counts.categories.vulnerability;
  let analysis = {};
  try { analysis = typeof pipeline.analysis_result === 'string' ? JSON.parse(pipeline.analysis_result || '{}') : pipeline.analysis_result || {}; } catch {}
  if (!analysis || typeof analysis !== 'object' || Array.isArray(analysis)) analysis = {};
  const candidateRisks = Array.isArray(analysis.risk_assessment) ? analysis.risk_assessment.length
    : analysis.risk_assessment && (typeof analysis.risk_assessment === 'string'
      || typeof analysis.risk_assessment === 'object' && Object.keys(analysis.risk_assessment).length) ? 1 : 0;
  const run = pipeline.run_id ? db.prepare('SELECT run_id, status FROM execution_runs WHERE run_id = ? AND target = ? AND user_sub = ?')
    .get(pipeline.run_id, pipeline.target, pipeline.created_by) : null;
  const countForRun = table => run ? db.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE run_id = ?`).get(run.run_id).count : 0;
  const plan = db.prepare('SELECT state, revision FROM task_plans WHERE pipeline_id = ?').get(pipeline.pipeline_id);
  return { scan_task_ids: scanIds, scan_findings: scanFindings, scan_record_counts:counts, candidate_risks: candidateRisks,
    evidence_records: countForRun('evidence_records'), reports: countForRun('test_reports'),
    execution: run || null, plan: plan || null };
}
