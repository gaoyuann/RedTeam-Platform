import { getDb } from '../db/connection.js';

const MITRE_TOTAL = 114;

export function computeGrade(runId) {
  const db = getDb();

  // Get execution run
  const run = db.prepare(
    'SELECT run_id, playbook_id, target, status, final_summary, score_data FROM execution_runs WHERE run_id = ?'
  ).get(runId);
  if (!run) return { ok: false, error: 'Run not found' };

  // Get execution steps
  const execSteps = db.prepare(
    'SELECT step_index, tool_id, success, exit_code, notes FROM execution_steps WHERE run_id = ? ORDER BY step_index'
  ).all(runId);

  // Get playbook steps (with scores)
  let pbSteps = [];
  if (run.playbook_id) {
    pbSteps = db.prepare(
      'SELECT step_index, step_id, name, tool_id, score, expected_mitre FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index'
    ).all(run.playbook_id);
  }

  // Get playbook MITRE techniques
  let playbookMitre = [];
  if (run.playbook_id) {
    const pb = db.prepare('SELECT mitre_techniques FROM playbooks WHERE playbook_id = ?').get(run.playbook_id);
    if (pb?.mitre_techniques) {
      try { playbookMitre = JSON.parse(pb.mitre_techniques); } catch {}
    }
  }

  // Collect MITRE hits from evidence
  const evidence = db.prepare(
    'SELECT mitre_hits FROM evidence_records WHERE run_id = ?'
  ).all(runId);
  const mitreHitSet = new Set();
  for (const e of evidence) {
    if (!e.mitre_hits) continue;
    try {
      const hits = JSON.parse(e.mitre_hits);
      for (const h of hits) mitreHitSet.add(h);
    } catch {}
  }
  // Also count playbook-declared techniques as covered if run completed
  if (run.status === 'COMPLETED') {
    for (const t of playbookMitre) mitreHitSet.add(t);
  }

  // Step-based scoring
  let total = 0;
  let earned = 0;
  const breakdown = [];

  if (pbSteps.length > 0) {
    for (const pbStep of pbSteps) {
      const score = pbStep.score || 0;
      total += score;
      const execStep = execSteps.find(s => s.step_index === pbStep.step_index);
      const success = execStep ? execStep.success === 1 : false;
      const stepEarned = success ? score : 0;
      earned += stepEarned;
      breakdown.push({
        stepIndex: pbStep.step_index,
        stepId: pbStep.step_id,
        name: pbStep.name,
        toolId: pbStep.tool_id,
        success,
        score,
        earned: stepEarned,
      });
    }
  } else {
    // Fallback: 10 points per execution step
    for (const s of execSteps) {
      total += 10;
      const stepEarned = s.success === 1 ? 10 : 0;
      earned += stepEarned;
      breakdown.push({
        stepIndex: s.step_index,
        stepId: null,
        name: null,
        toolId: s.tool_id,
        success: s.success === 1,
        score: 10,
        earned: stepEarned,
      });
    }
  }

  // MITRE coverage bonus (max 20 points)
  const mitreCovered = mitreHitSet.size;
  const mitreScore = Math.round((mitreCovered / MITRE_TOTAL) * 20);
  const mitrePercent = Math.round((mitreCovered / MITRE_TOTAL) * 10000) / 100;

  // Final score
  const finalEarned = earned + mitreScore;
  const finalTotal = total + 20;
  const percent = finalTotal > 0 ? Math.round((finalEarned / finalTotal) * 1000) / 10 : 0;

  // Letter grade
  let grade = 'F';
  if (percent >= 90) grade = 'A';
  else if (percent >= 80) grade = 'B';
  else if (percent >= 70) grade = 'C';
  else if (percent >= 60) grade = 'D';

  const result = {
    ok: true,
    runId,
    total: finalTotal,
    earned: finalEarned,
    percent,
    grade,
    stepScore: { total, earned },
    breakdown,
    mitre: {
      covered: mitreCovered,
      total: MITRE_TOTAL,
      percent: mitrePercent,
      score: mitreScore,
      techniques: [...mitreHitSet],
    },
    summary: run.final_summary,
  };

  // Cache score_data in execution_runs
  db.prepare("UPDATE execution_runs SET score_data = ?, updated_at = datetime('now') WHERE run_id = ?")
    .run(JSON.stringify(result), runId);

  return result;
}
