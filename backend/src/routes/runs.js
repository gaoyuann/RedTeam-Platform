import { Router } from 'express';
import { randomUUID } from 'crypto';
import { executeRun } from '../services/executionEngine.js';
import { computeGrade } from '../services/gradingEngine.js';
import { buildAttackGraph, buildAttackGraphSummary } from '../services/graphBuilder.js';
import { inferNextActions } from '../services/pathPlanner.js';
import { runPreflightChecks } from '../services/preflightGate.js';

export default function (db) {
  const router = Router();

  router.get('/', (req, res) => {
    const { status, playbook_id, user_sub, limit, offset } = req.query;
    let sql = 'SELECT * FROM execution_runs WHERE 1=1';
    const params = [];
    if (status) { sql += ' AND status = ?'; params.push(status); }
    if (playbook_id) { sql += ' AND playbook_id = ?'; params.push(playbook_id); }
    if (user_sub) { sql += ' AND user_sub = ?'; params.push(user_sub); }
    sql += ' ORDER BY created_at DESC';
    if (limit) { sql += ' LIMIT ?'; params.push(Number(limit)); }
    if (offset) { sql += ' OFFSET ?'; params.push(Number(offset)); }
    const rows = db.prepare(sql).all(...params);
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.get('/:runId', (req, res) => {
    const row = db.prepare('SELECT * FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });
    row.steps = db.prepare('SELECT * FROM execution_steps WHERE run_id = ? ORDER BY step_index').all(req.params.runId);
    row.evidence = db.prepare('SELECT * FROM evidence_records WHERE run_id = ? ORDER BY recorded_at').all(req.params.runId);
    res.json({ status: 'ok', data: row });
  });

  router.post('/', (req, res) => {
    const { run_id, playbook_id, user_sub, user_role, target, scan_task_id } = req.body;
    const rid = run_id || `run_${randomUUID().slice(0, 12)}`;
    try {
      const now = new Date().toISOString();
      db.prepare(`INSERT INTO execution_runs (run_id, playbook_id, user_sub, user_role, target, scan_task_id, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)`).run(rid, playbook_id || null, user_sub || null, user_role || null, target || null, scan_task_id || null, now, now);
      const row = db.prepare('SELECT * FROM execution_runs WHERE run_id = ?').get(rid);
      res.status(201).json({ status: 'ok', data: row });
    } catch (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({ status: 'error', error: { message: 'Run ID already exists' } });
      throw err;
    }
  });

  // ── Blue Team Interventions ─────────────────────────────────────────
  router.post('/:runId/interventions', (req, res) => {
    const { type, target, port, proto, path } = req.body;
    if (!type) return res.status(400).json({ status: 'error', error: { message: 'type is required' } });
    const validTypes = ['block_port', 'block_path', 'isolate_host'];
    if (!validTypes.includes(type)) {
      return res.status(400).json({ status: 'error', error: { message: `Invalid type. Must be one of: ${validTypes.join(', ')}` } });
    }

    // Validate run exists
    const run = db.prepare('SELECT run_id FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!run) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });

    const row = db.prepare(`
      INSERT INTO blue_team_interventions (run_id, type, target, port, proto, path)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(req.params.runId, type, target || null, port || null, proto || 'tcp', path || null);

    const intervention = db.prepare('SELECT * FROM blue_team_interventions WHERE id = ?').get(row.lastInsertRowid);
    res.status(201).json({ status: 'ok', data: intervention });
  });

  router.get('/:runId/interventions', (req, res) => {
    const run = db.prepare('SELECT run_id FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!run) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });

    const interventions = db.prepare(
      'SELECT * FROM blue_team_interventions WHERE run_id = ? ORDER BY id'
    ).all(req.params.runId);
    res.json({ status: 'ok', data: interventions, meta: { total: interventions.length } });
  });

  router.delete('/:runId/interventions/:id', (req, res) => {
    const { runId, id } = req.params;
    const row = db.prepare(
      'DELETE FROM blue_team_interventions WHERE id = ? AND run_id = ?'
    ).run(id, runId);
    if (row.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Intervention not found' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  // ── Attack Graph ──────────────────────────────────────────────────────
  router.get('/:runId/attack-graph', (req, res) => {
    const run = db.prepare('SELECT run_id, target FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!run) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });

    const findings = db.prepare(
      'SELECT evidence_type, tool_id, evidence_data, step_index FROM evidence_records WHERE run_id = ? ORDER BY recorded_at'
    ).all(req.params.runId);

    const interventions = db.prepare(
      'SELECT * FROM blue_team_interventions WHERE run_id = ? ORDER BY id'
    ).all(req.params.runId);

    const graph = buildAttackGraph({ target: run.target, findings, interventions });
    const summary = buildAttackGraphSummary(graph);

    res.json({
      status: 'ok',
      data: graph,
      summary,
    });
  });

  // ── Suggested Next Steps ──────────────────────────────────────────────
  router.get('/:runId/next-steps', (req, res) => {
    const run = db.prepare('SELECT run_id, target FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!run) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });

    const findings = db.prepare(
      'SELECT evidence_type, tool_id, evidence_data, step_index FROM evidence_records WHERE run_id = ? ORDER BY recorded_at'
    ).all(req.params.runId);

    const interventions = db.prepare(
      'SELECT * FROM blue_team_interventions WHERE run_id = ? ORDER BY id'
    ).all(req.params.runId);

    const recentSteps = db.prepare(
      "SELECT tool_id FROM execution_steps WHERE run_id = ? AND success = 1 ORDER BY step_index DESC LIMIT 5"
    ).all(req.params.runId);
    const recentTools = recentSteps.map(s => s.tool_id).filter(Boolean);

    // Gather rule matches from evidence
    const ruleMatches = [];
    for (const f of findings) {
      if (f.evidence_data) {
        try {
          const data = typeof f.evidence_data === 'string' ? JSON.parse(f.evidence_data) : f.evidence_data;
          if (data.ruleMatches) {
            ruleMatches.push(...data.ruleMatches);
          }
        } catch { /* skip */ }
      }
    }

    const result = inferNextActions({ findings, ruleMatches, interventions, recentTools });

    res.json({
      status: 'ok',
      data: result,
    });
  });

  // ── Grading ────────────────────────────────────────────────────────
  router.get('/:runId/grade', (req, res) => {
    const run = db.prepare('SELECT score_data FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!run) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });
    if (!run.score_data) return res.json({ status: 'ok', data: null, message: 'Not yet graded' });
    try {
      res.json({ status: 'ok', data: JSON.parse(run.score_data) });
    } catch {
      res.json({ status: 'ok', data: null });
    }
  });

  router.post('/:runId/grade', (req, res) => {
    const result = computeGrade(req.params.runId);
    if (!result.ok) return res.status(404).json({ status: 'error', error: { message: result.error } });
    res.json({ status: 'ok', data: result });
  });

  // ── Trigger Execution ───────────────────────────────────────────────
  router.post('/:runId/execute', async (req, res) => {
    const run = db.prepare('SELECT run_id, status FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!run) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });
    if (run.status === 'RUNNING') return res.status(409).json({ status: 'error', error: { message: 'Run is already executing' } });
    if (run.status === 'COMPLETED') return res.status(409).json({ status: 'error', error: { message: 'Run already completed' } });

    // Optionally set engine_type before execution
    const { engine_type } = req.body;
    if (engine_type) {
      db.prepare("UPDATE execution_runs SET engine_type = ? WHERE run_id = ?").run(engine_type, req.params.runId);
    }

    // Fire and forget — execution happens in background
    executeRun(req.params.runId).catch(() => {});
    res.status(202).json({ status: 'ok', data: { run_id: req.params.runId, message: 'Execution started' } });
  });

  // ── Preflight Check (without starting execution) ───────────────────────
  router.post('/:runId/preflight', async (req, res) => {
    const run = db.prepare('SELECT run_id, playbook_id, target FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!run) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });
    if (!run.playbook_id) return res.status(400).json({ status: 'error', error: { message: 'Run has no playbook_id assigned' } });

    try {
      const preflight = await runPreflightChecks({ playbookId: run.playbook_id, target: run.target, db });
      // Persist preflight data regardless of pass/fail
      db.prepare(
        "UPDATE execution_runs SET preflight_status = ?, preflight_data = ?, updated_at = datetime('now') WHERE run_id = ?"
      ).run(preflight.passed ? 'PASSED' : 'FAILED', JSON.stringify(preflight.checks), req.params.runId);

      res.json({
        status: 'ok',
        data: {
          run_id: req.params.runId,
          passed: preflight.passed,
          checks: preflight.checks,
        },
      });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: `Preflight check failed: ${err.message}` } });
    }
  });

  // ── ReAct State ─────────────────────────────────────────────────────
  router.get('/:runId/react-state', (req, res) => {
    const run = db.prepare(
      'SELECT run_id, engine_type, evidence_history, react_thoughts, stop_reason FROM execution_runs WHERE run_id = ?'
    ).get(req.params.runId);
    if (!run) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });

    // Parse JSON fields
    let evidenceHistory = [], reactThoughts = [];
    try { evidenceHistory = JSON.parse(run.evidence_history || '[]'); } catch {}
    try { reactThoughts = JSON.parse(run.react_thoughts || '[]'); } catch {}

    // Get latest thought from steps
    const steps = db.prepare(
      'SELECT step_index, tool_id, react_thought, react_action FROM execution_steps WHERE run_id = ? AND react_thought IS NOT NULL ORDER BY step_index'
    ).all(req.params.runId);

    res.json({
      status: 'ok',
      data: {
        run_id: run.run_id,
        engine_type: run.engine_type || 'mechanical',
        evidence_history: evidenceHistory,
        react_thoughts: reactThoughts,
        step_thoughts: steps,
        stop_reason: run.stop_reason,
      },
    });
  });

  router.put('/:runId', (req, res) => {
    const { status, final_summary, score_data, stop_reason } = req.body;
    const sets = [], params = [];
    if (status) { sets.push('status = ?'); params.push(status); }
    if (final_summary !== undefined) { sets.push('final_summary = ?'); params.push(final_summary); }
    if (score_data !== undefined) { sets.push('score_data = ?'); params.push(JSON.stringify(score_data)); }
    if (stop_reason !== undefined) { sets.push('stop_reason = ?'); params.push(stop_reason); }
    if (sets.length === 0) return res.status(400).json({ status: 'error', error: { message: 'No fields to update' } });
    sets.push("updated_at = datetime('now')");
    params.push(req.params.runId);
    const result = db.prepare(`UPDATE execution_runs SET ${sets.join(', ')} WHERE run_id = ?`).run(...params);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });
    res.json({ status: 'ok', data: db.prepare('SELECT * FROM execution_runs WHERE run_id = ?').get(req.params.runId) });
  });

  router.delete('/:runId', (req, res) => {
    const result = db.prepare('DELETE FROM execution_runs WHERE run_id = ?').run(req.params.runId);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  return router;
}
