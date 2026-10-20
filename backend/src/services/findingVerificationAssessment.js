import { evaluateFindingRule } from './findingVerificationRules.js';
export function assessVerificationAttempt(db,attemptId) {
  const stored=db.prepare('SELECT * FROM finding_verification_assessments WHERE attempt_id=? ORDER BY id DESC LIMIT 1').get(attemptId);
  if(stored)return {...stored,evidence_ids:JSON.parse(stored.evidence_ids)};
  const attempt=db.prepare(`SELECT a.*,p.content,p.fingerprint,v.finding_id FROM finding_verification_attempts a
    JOIN finding_verification_plans p ON p.verification_id=a.verification_id AND p.revision=a.revision
    JOIN finding_verifications v ON v.id=a.verification_id WHERE a.id=?`).get(attemptId);
  if(!attempt)return null;
  const plan=JSON.parse(attempt.content),rule=plan.assessment_rule;
  if(!rule)return null;
  const evidence=db.prepare('SELECT * FROM evidence_records WHERE run_id=? ORDER BY id DESC').all(attempt.run_id);
  const result=evaluateFindingRule(rule,evidence,attempt,{...plan,finding_id:attempt.finding_id});
  db.prepare(`INSERT OR IGNORE INTO finding_verification_assessments(attempt_id,rule_id,rule_version,conclusion,evidence_ids,reason,limitations)
    VALUES(?,?,?,?,?,?,?)`).run(attemptId,result.rule_id,result.rule_version,result.conclusion,JSON.stringify(result.evidence_ids),result.reason,result.limitations);
  const saved=db.prepare('SELECT * FROM finding_verification_assessments WHERE attempt_id=? AND rule_id=? AND rule_version=?')
    .get(attemptId,result.rule_id,result.rule_version);
  return {...saved,evidence_ids:JSON.parse(saved.evidence_ids)};
}
