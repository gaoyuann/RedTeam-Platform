import { getDb } from '../db/connection.js';
import { computeGrade } from './gradingEngine.js';
import { randomUUID } from 'crypto';

export function generateReport(runId, title) {
  const db = getDb();

  const run = db.prepare(
    'SELECT run_id, playbook_id, target, status, final_summary FROM execution_runs WHERE run_id = ?'
  ).get(runId);
  if (!run) return { ok: false, error: 'Run not found' };

  // Compute grade (uses cache if already computed)
  const grade = computeGrade(runId);

  // Get execution steps
  const steps = db.prepare(
    'SELECT step_index, tool_id, args, success, exit_code, notes FROM execution_steps WHERE run_id = ? ORDER BY step_index'
  ).all(runId);

  // Get playbook name
  let playbookName = null;
  if (run.playbook_id) {
    const pb = db.prepare('SELECT name FROM playbooks WHERE playbook_id = ?').get(run.playbook_id);
    playbookName = pb?.name || run.playbook_id;
  }

  // Build report content
  const content = {
    run_id: runId,
    playbook_id: run.playbook_id,
    playbook_name: playbookName,
    target: run.target,
    run_status: run.status,
    grade: grade.ok ? grade : null,
    steps: steps.map(s => ({
      step_index: s.step_index,
      tool_id: s.tool_id,
      success: s.success === 1,
      exit_code: s.exit_code,
      output_preview: (s.notes || '').slice(0, 500),
    })),
    summary: run.final_summary,
    generated_at: new Date().toISOString(),
  };

  // Insert into test_reports
  const reportId = `rpt_${randomUUID().slice(0, 12)}`;
  const now = new Date().toISOString();
  const reportTitle = title || `测试报告 - ${playbookName || runId} - ${now.slice(0, 10)}`;

  db.prepare(`
    INSERT INTO test_reports (report_id, title, run_id, template, status, content, created_at, updated_at)
    VALUES (?, ?, ?, 'standard', 'draft', ?, ?, ?)
  `).run(reportId, reportTitle, runId, JSON.stringify(content), now, now);

  return {
    ok: true,
    report_id: reportId,
    title: reportTitle,
    status: 'draft',
  };
}
