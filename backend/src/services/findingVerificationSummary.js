const json=(value,fallback)=>{try{return JSON.parse(value);}catch{return fallback;}};
const dbSafe=(db,sql,...args)=>db.prepare(sql).get(...args);
export function verificationSummary(db, findingId, pipelineId) {
  if (!dbSafe(db, "SELECT 1 FROM sqlite_master WHERE name='finding_verifications'")) return null;
  const item = dbSafe(db, 'SELECT * FROM finding_verifications WHERE finding_id=? AND pipeline_id=?', findingId, pipelineId);
  if (!item) return null;
  const attempt = dbSafe(db, 'SELECT * FROM finding_verification_attempts WHERE verification_id=? ORDER BY rowid DESC LIMIT 1', item.id);
  const review = attempt && dbSafe(db, 'SELECT * FROM finding_verification_reviews WHERE attempt_id=? ORDER BY id DESC LIMIT 1', attempt.id);
  const assessment=attempt && dbSafe(db,"SELECT 1 FROM sqlite_master WHERE name='finding_verification_assessments'")
    ? dbSafe(db,'SELECT * FROM finding_verification_assessments WHERE attempt_id=? ORDER BY id DESC LIMIT 1',attempt.id) : null;
  const judgement=review || assessment;
  return { id:item.id, state:item.state, revision:item.revision, reason:item.reason, run_id:attempt?.run_id || null,
    attempt_id:attempt?.id || null, stop_confirmed:Boolean(attempt?.stop_confirmed), conclusion:judgement?.conclusion || 'pending',method:review?'manual':assessment?'automatic':'pending',rule_id:assessment?.rule_id || null,limitations:assessment?.limitations || null,
    evidence_ids:json(judgement?.evidence_ids, []), note:review?.note || assessment?.reason || null };
}
