import {projectVerificationResult,legacyConclusion} from './findingVerificationResult.js';
const json=(value,fallback)=>{try{return JSON.parse(value);}catch{return fallback;}};
const dbSafe=(db,sql,...args)=>db.prepare(sql).get(...args);
export function attemptVerificationSummary(db, item, attempt) {
  const review = attempt && dbSafe(db, 'SELECT * FROM finding_verification_reviews WHERE attempt_id=? ORDER BY id DESC LIMIT 1', attempt.id);
  const assessment=attempt && dbSafe(db,"SELECT 1 FROM sqlite_master WHERE name='finding_verification_assessments'")
    ? dbSafe(db,'SELECT * FROM finding_verification_assessments WHERE attempt_id=? ORDER BY id DESC LIMIT 1',attempt.id) : null;
  const legacyJudgement=review || assessment;
  const result=projectVerificationResult(db,item,attempt,assessment);
  const human_opinions=attempt?db.prepare('SELECT * FROM finding_verification_reviews WHERE attempt_id=? ORDER BY id DESC').all(attempt.id).map(r=>({...r,evidence_ids:json(r.evidence_ids,[]),notice:'人工意见不替代自动验证结论'})):[];
  return { id:item.id, state:attempt?.state || item.state, revision:attempt?.revision ?? item.revision, reason:attempt?.reason ?? null,
    run_id:attempt?.run_id || null, attempt_id:attempt?.id || null, stop_confirmed:Boolean(attempt?.stop_confirmed),
    conclusion:legacyConclusion(result),method:['achieved','not_achieved'].includes(result.status)?'automatic':'pending',result,human_opinions,
    legacy_summary:{conclusion:legacyJudgement?.conclusion || 'pending',method:review?'manual':assessment?'automatic':'pending',notice:'历史口径，仅供参考'},
    rule_id:assessment?.rule_id || null,limitations:assessment?.limitations || null,
    evidence_ids:result.evidence_ids, note:result.reason,
    automatic:assessment ? {...assessment,note:assessment.reason,evidence_ids:json(assessment.evidence_ids,[])} : null,
    manual:review ? {...review,evidence_ids:json(review.evidence_ids,[])} : null,
    disagreement:Boolean(review && assessment && review.conclusion!==assessment.conclusion) };
}
export function verificationSummary(db, findingId, pipelineId) {
  if (!dbSafe(db, "SELECT 1 FROM sqlite_master WHERE name='finding_verifications'")) return null;
  const item = dbSafe(db, 'SELECT * FROM finding_verifications WHERE finding_id=? AND pipeline_id=?', findingId, pipelineId);
  if (!item) return null;
  const attempt = dbSafe(db, 'SELECT * FROM finding_verification_attempts WHERE verification_id=? ORDER BY rowid DESC LIMIT 1', item.id);
  // Keep the legacy aggregate's draft state/revision; attempt summaries describe their frozen execution.
  return {...attemptVerificationSummary(db,item,attempt),state:item.state,revision:item.revision,reason:item.reason};
}
