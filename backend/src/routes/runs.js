import {isProgramScan} from '../services/programScan.js';
import {canAccessProgramRun,canAccessProgramTask} from '../services/programAccess.js';
import { Router } from 'express';
import { sourceTarget } from '../services/sourceScanConnections.js';
import { randomUUID } from 'crypto';
import { executeRun, requestAbort } from '../services/executionEngine.js';
import { computeGrade } from '../services/gradingEngine.js';
import { buildAttackGraph, buildAttackGraphSummary } from '../services/graphBuilder.js';
import { inferNextActions } from '../services/pathPlanner.js';
import { runPreflightChecks } from '../services/preflightGate.js';
import { getWsManager } from '../services/wsManager.js';
import { requireActor, recordParam, checkRecordAccess, getRecord } from '../middleware/recordAccess.js';
import { assertPlaybookUse } from '../services/playbookAccess.js';
import { summarizeRunResultCounts } from '../services/runResultCounts.js';

export default function (db) {
  const router = Router();
  router.use(requireActor(db));
  router.param('runId', recordParam(db, 'run'));
  router.post(['/:runId/execute', '/:runId/preflight'], (req, res, next) => {
    const run = getRecord(db, 'run', req.params.runId);
    if (run?.playbook_id) {
      try { assertPlaybookUse(db, run.playbook_id, req.user, run.user_sub); }
      catch (error) { return res.status(error.status || 500).json({ status: 'error', error: { message: error.message } }); }
    }
    next();
  });

  router.get('/', (req, res) => {
    const { status, playbook_id, user_sub, limit, offset } = req.query;
    let sql = 'SELECT * FROM execution_runs WHERE 1=1';
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND user_sub = ?'; params.push(req.user.sub); }
    if (status) { sql += ' AND status = ?'; params.push(status); }
    if (playbook_id) { sql += ' AND playbook_id = ?'; params.push(playbook_id); }
    if (user_sub) { sql += ' AND user_sub = ?'; params.push(user_sub); }
    sql += ' ORDER BY created_at DESC';
    const pageLimit = limit === undefined ? null : Number(limit);
    const pageOffset = offset === undefined ? 0 : Number(offset);
    if ((pageLimit !== null && (!Number.isSafeInteger(pageLimit) || pageLimit < 1)) || !Number.isSafeInteger(pageOffset) || pageOffset < 0)
      return res.status(400).json({ status: 'error', error: { message: 'limit 和 offset 必须为有效的分页整数' } });
    if (pageLimit !== null || pageOffset) { sql += ' LIMIT ? OFFSET ?'; params.push(pageLimit ?? -1, pageOffset); }
    const rows = db.prepare(sql).all(...params).filter(row => canAccessProgramRun(db, req.user, row));
    // Enrich each row with playbook_name for display
    for (const row of rows) {
      if (row.playbook_id) {
        const pb = db.prepare('SELECT name FROM playbooks WHERE playbook_id = ?').get(row.playbook_id);
        row.playbook_name = pb ? pb.name : row.playbook_id;
      } else {
        row.playbook_name = '';
      }
    }
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.use('/:runId', (req,res,next)=>{
    const record=db.prepare('SELECT plan_data FROM execution_runs WHERE run_id=?').get(req.params.runId);
    let managed; try {managed=JSON.parse(record?.plan_data || '{}').finding_verification;} catch {}
    if(managed && req.method!=='GET') return res.status(409).json({status:'error',error:{message:'请通过任务漏洞验证入口操作，验证记录不可改写或删除'}});
    next();
  });
  router.use('/:runId',(req,res,next)=>{
    const run=db.prepare('SELECT playbook_id,scan_task_id FROM execution_runs WHERE run_id=?').get(req.params.runId);
    if(run && !canAccessProgramRun(db,req.user,run)) return res.status(403).json({status:'error',error:{message:'没有权限访问此程序验证执行'}});
    next();
  });
  router.get('/:runId', (req, res) => {
    const row = db.prepare('SELECT * FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });
    row.steps = db.prepare('SELECT * FROM execution_steps WHERE run_id = ? ORDER BY step_index').all(req.params.runId);
    row.evidence = db.prepare('SELECT * FROM evidence_records WHERE run_id = ? ORDER BY recorded_at').all(req.params.runId);
    row.attempts = db.prepare('SELECT * FROM execution_attempts WHERE run_id = ? ORDER BY id').all(req.params.runId);
    const planned = row.playbook_id
      ? db.prepare('SELECT COUNT(*) AS count FROM playbook_steps WHERE playbook_id = ?').get(row.playbook_id).count
      : 0;
    row.result_counts = summarizeRunResultCounts(row.steps, row.status, { knownStepCount: planned });
    // Enrich with playbook name for display
    if (row.playbook_id) {
      const pb = db.prepare('SELECT name FROM playbooks WHERE playbook_id = ?').get(row.playbook_id);
      row.playbook_name = pb ? pb.name : row.playbook_id;
    } else {
      row.playbook_name = '';
    }
    res.json({ status: 'ok', data: row });
  });

  router.post('/', (req, res) => {
    let { run_id, playbook_id, target, scan_task_id } = req.body;
    const pb=db.prepare('SELECT metadata FROM playbooks WHERE playbook_id=?').get(playbook_id || '');
    let source;
    try {source=JSON.parse(pb?.metadata || '{}').source_verification;} catch {}
    if(source) {
      try {
        if(sourceTarget(target)!==source.target) throw new Error('验证目标必须与生成预案时一致，请重新生成预案');
        const task=db.prepare('SELECT created_by FROM scan_tasks WHERE scan_task_id=?').get(source.scan_task_id);
        if(!task || req.user?.role!=='admin' && task.created_by!==req.user?.sub) return res.status(403).json({status:'error',error:{message:'没有权限执行此源码任务的预案'}});
        scan_task_id=source.scan_task_id;
      } catch(error) {return res.status(400).json({status:'error',error:{message:error.message}});}
    }
    if (!canAccessProgramTask(db,req.user,scan_task_id)) return res.status(403).json({status:'error',error:{message:'没有权限使用此源码任务'}});
    if (playbook_id) {
      try { assertPlaybookUse(db, playbook_id, req.user); }
      catch (error) { return res.status(error.status || 500).json({ status: 'error', error: { message: error.message } }); }
    }
    if (scan_task_id) {
      if (!checkRecordAccess(db, 'scan', scan_task_id, req, res)) return;
      const scan = getRecord(db, 'scan', scan_task_id);
      if (scan.created_by !== req.user.sub || scan.target !== target)
        return res.status(409).json({ status: 'error', error: { message: '关联扫描必须属于当前用户且目标相同' } });
    }
    const rid = run_id || `run_${randomUUID().slice(0, 12)}`;
    try {
      const now = new Date().toISOString();
      db.prepare(`INSERT INTO execution_runs (run_id, playbook_id, user_sub, user_role, target, scan_task_id, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)`).run(rid, playbook_id || null, req.user.sub, req.user.role, target || null, scan_task_id || null, now, now);
      const row = db.prepare('SELECT * FROM execution_runs WHERE run_id = ?').get(rid);
      // WebSocket: notify run created
      const ws = getWsManager();
      if (ws) (source ? (event,data)=>ws.broadcastProgram(req.user.sub,event,data) : (event,data)=>ws.broadcast(event,data))('run:created', {
        runId: rid, playbookId: playbook_id || null, target: target || null,
        userId: req.user.sub,
        username: req.user?.sub || null,
        role: req.user?.role || null,
      });
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
      INSERT INTO blue_team_interventions (run_id, type, target, port, proto, path, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(req.params.runId, type, target || null, port || null, proto || 'tcp', path || null, req.user.sub);

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
    const run = db.prepare('SELECT run_id, playbook_id, scan_task_id, user_sub, status, engine_type FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!run) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });
    if (run.status !== 'PENDING') return res.status(409).json({ status: 'error', error: { message: `Run is ${run.status}, expected PENDING; create a new run to execute again` } });
    if (!run.playbook_id || !db.prepare('SELECT 1 FROM playbook_steps WHERE playbook_id = ? LIMIT 1').get(run.playbook_id)) {
      return res.status(400).json({ status: 'error', error: { message: 'Run has no executable playbook steps' } });
    }

    // Optionally set engine_type before execution
    const { engine_type } = req.body || {};
    const requestedEngine = engine_type === undefined ? run.engine_type : engine_type;
    if ((engine_type !== undefined || requestedEngine) && !['auto', 'playbook', 'mechanical', 'react'].includes(requestedEngine)) {
      return res.status(400).json({ status: 'error', error: { message: 'Invalid engine_type; expected auto, playbook, mechanical or react' } });
    }
    if (engine_type !== undefined) {
      db.prepare("UPDATE execution_runs SET engine_type = ? WHERE run_id = ?").run(engine_type, req.params.runId);
    }

    // Fire and forget — execution happens in background
    executeRun(req.params.runId).catch(err => {
      console.error(`[runs] executeRun failed for ${req.params.runId}:`, err.message || err);
    });
    // WebSocket: notify run started
    const ws = getWsManager();
    const programTask=run.scan_task_id && db.prepare('SELECT scan_type FROM scan_tasks WHERE scan_task_id=?').get(run.scan_task_id);
    if (ws) (isProgramScan(programTask?.scan_type) ? (event,data)=>ws.broadcastProgram(run.user_sub,event,data) : (event,data)=>ws.broadcast(event,data))('run:started', {
      runId: req.params.runId,
      userId: req.user?.sub || null,
      username: req.user?.sub || null,
      role: req.user?.role || null,
    });
    res.status(202).json({ status: 'ok', data: { run_id: req.params.runId, message: 'Execution started' } });
  });

  // ── Abort a running execution ─────────────────────────────────────────
  router.post('/:runId/abort', (req, res) => {
    const run = db.prepare('SELECT status FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!run) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });
    if (run.status !== 'RUNNING' && run.status !== 'PENDING') {
      return res.status(400).json({ status: 'error', error: { message: `Run is ${run.status}, cannot abort` } });
    }
    requestAbort(req.params.runId);
    db.prepare("UPDATE execution_runs SET status = 'ABORTED', stop_reason = '操作员手动中止', updated_at = datetime('now') WHERE run_id = ?")
      .run(req.params.runId);
    res.json({ status: 'ok', data: { aborted: true } });
  });

  // ── Preflight Check (without starting execution) ───────────────────────
  router.post('/:runId/preflight', async (req, res) => {
    const run = db.prepare('SELECT run_id, playbook_id, target, scan_task_id, plan_data FROM execution_runs WHERE run_id = ?').get(req.params.runId);
    if (!run) return res.status(404).json({ status: 'error', error: { message: 'Run not found' } });
    if (!run.playbook_id) return res.status(400).json({ status: 'error', error: { message: 'Run has no playbook_id assigned' } });

    try {
      let scanTaskIds = run.scan_task_id ? [run.scan_task_id] : [];
      try { scanTaskIds = JSON.parse(run.plan_data || '{}')._scan_task_ids || scanTaskIds; } catch {}
      const preflight = await runPreflightChecks({ playbookId: run.playbook_id, target: run.target, db, scanTaskIds, runId: run.run_id });
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
