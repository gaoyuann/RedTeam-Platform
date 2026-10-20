import { resultCategory } from './scanResultCatalog.js';
import { verificationSummary } from './findingVerificationSummary.js';

export function usesFindingWorkflow(config) {
  try { return (typeof config === 'string' ? JSON.parse(config) : config)?.workflow === 'per_finding'; }
  catch { return false; }
}

// Count stable finding records, not tool exits or retries. Cross-tool instances
// are not deduplicated, and an unknown ground truth must never become zero.
export function findingStatistics(db, pipeline, rows) {
  const candidates = new Set(rows.filter(row => resultCategory(row) === 'vulnerability').map(row => row.id));
  const counts = { expected_count: null, candidate_records: candidates.size, submitted_records: 0,
    tested_records: 0, attempt_count: 0, completed_records: 0, failed_records: 0,
    confirmed_records: 0, not_verified_records: 0, inconclusive_records: 0, false_positive_records: 0,
    unreviewed_records: 0, active_attempts: 0, unknown_attempts: 0,
    count_basis: 'scan_result_ids_without_cross_tool_deduplication' };
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE name='finding_verifications'").get()) {
    const items = db.prepare('SELECT id,finding_id FROM finding_verifications WHERE pipeline_id=?').all(pipeline.pipeline_id);
    const attempts = db.prepare('SELECT * FROM finding_verification_attempts WHERE pipeline_id=? ORDER BY rowid').all(pipeline.pipeline_id);
    // Keep active/unknown calls visible even if a legacy finding was reclassified.
    counts.active_attempts = attempts.filter(a => ['queued','running','cancelling'].includes(a.state)).length;
    counts.unknown_attempts = attempts.filter(a => a.state === 'unknown' || !a.stop_confirmed && !['queued','running','cancelling'].includes(a.state)).length;
    const started = new Set(db.prepare(`SELECT DISTINCT a.verification_id FROM finding_verification_attempts a
      JOIN evidence_records e ON e.run_id=a.run_id WHERE a.pipeline_id=? AND json_valid(e.evidence_data)
      AND json_extract(e.evidence_data,'$.finding_verification.attempt_id')=a.id
      AND json_extract(e.evidence_data,'$.finding_verification.verification_id')=a.verification_id
      AND json_extract(e.evidence_data,'$.finding_verification.tool_started')=1`).all(pipeline.pipeline_id).map(a => a.verification_id));
    for (const item of items) {
      if (!candidates.has(item.finding_id)) continue;
      const history = attempts.filter(a => a.verification_id === item.id);
      counts.attempt_count += history.length;
      if (!history.length) continue;
      counts.submitted_records++;
      if (started.has(item.id)) counts.tested_records++;
      const latest = history.at(-1);
      if (latest.state === 'completed') counts.completed_records++;
      if (latest.state === 'failed') counts.failed_records++;
      const summary = verificationSummary(db, item.finding_id, pipeline.pipeline_id);
      const field = `${summary?.conclusion}_records`;
      if (['confirmed_records','not_verified_records','inconclusive_records','false_positive_records'].includes(field)) counts[field]++;
      else if (started.has(item.id)) counts.unreviewed_records++;
    }
  }
  counts.untested_records = counts.candidate_records - counts.tested_records;
  counts.conclusion = !counts.candidate_records ? '本次没有有效漏洞候选；请结合扫描覆盖与错误判断，不能据此认定目标安全。'
    : `候选记录 ${counts.candidate_records} 条，实际执行 ${counts.tested_records} 条，验证成立 ${counts.confirmed_records} 条，尚未实际执行 ${counts.untested_records} 条。工具执行完成与漏洞成立分别统计。`;
  return counts;
}
