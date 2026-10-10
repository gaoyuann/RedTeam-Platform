import { normalizeTopologyTarget } from '../services/nmapTopology.js';
import { Router } from 'express';
import { randomUUID } from 'crypto';
import { matchPlaybooks } from '../services/playbookMatcher.js';
import { generatePlaybook } from '../services/playbookGenerator.js';
import { executeScan, requestScanAbort } from '../services/scanExecutor.js';
import { getWsManager } from '../services/wsManager.js';
import { resolveTargetProfile } from '../services/targetProfileResolver.js';
import { loadTargetProfile } from '../services/targetDiscovery.js';

export default function (db) {
  const router = Router();

  router.get('/', (req, res) => {
    const { status, target, scan_type } = req.query;
    let sql = 'SELECT * FROM scan_tasks WHERE 1=1';
    const params = [];
    if (status) { sql += ' AND status = ?'; params.push(status); }
    if (target) { sql += ' AND target = ?'; params.push(target); }
    if (scan_type) { sql += ' AND scan_type = ?'; params.push(scan_type); }
    sql += ' ORDER BY created_at DESC';
    const rows = db.prepare(sql).all(...params);
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.get('/:scanTaskId', (req, res) => {
    const row = db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id = ?').get(req.params.scanTaskId);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Scan task not found' } });
    row.results = db.prepare('SELECT * FROM scan_results WHERE scan_task_id = ? ORDER BY captured_at').all(req.params.scanTaskId);
    res.json({ status: 'ok', data: row });
  });

  router.post('/', (req, res) => {
    let { target, scan_type, parameters, created_by } = req.body;
    if (!target || !scan_type) return res.status(400).json({ status: 'error', error: { message: 'target, scan_type are required' } });
    if (scan_type === 'topology_scan') {
      try { target = normalizeTopologyTarget(target); }
      catch (error) { return res.status(400).json({ status: 'error', error: { message: error.message } }); }
      const pipelineId = parameters?.pipeline_id;
      if (pipelineId) {
        const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(pipelineId);
        if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '任务不存在' } });
        if (req.user.role !== 'admin' && req.user.sub !== pipeline.created_by)
          return res.status(403).json({ status: 'error', error: { message: '没有权限为此任务探测拓扑' } });
        let expectedTarget;
        try { expectedTarget = normalizeTopologyTarget(pipeline.target); }
        catch (error) { return res.status(400).json({ status: 'error', error: { message: error.message } }); }
        if (target !== expectedTarget)
          return res.status(400).json({ status: 'error', error: { message: '拓扑探测范围必须与当前任务目标一致' } });
      }
      parameters = { ...(pipelineId ? { pipeline_id: pipelineId } : {}), timeout: 300 };
      created_by = req.user?.sub || null;
    }
    const scan_task_id = `scan_${randomUUID().slice(0, 12)}`;
    const now = new Date().toISOString();
    // Auto-resolve target_class for the new scan task
    const targetProfile = resolveTargetProfile(target);
    db.prepare(`INSERT INTO scan_tasks (scan_task_id, target, scan_type, target_class, parameters, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(scan_task_id, target, scan_type, targetProfile.target_class, parameters ? JSON.stringify(parameters) : null, created_by || null, now);
    const row = db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id = ?').get(scan_task_id);
    // WebSocket: notify all clients about new scan (include operator info)
    const ws = getWsManager();
    if (ws) ws.broadcast('scan:created', {
      scanTaskId: scan_task_id, target, scanType: scan_type,
      userId: req.user?.sub || created_by || null,
      username: req.user?.sub || null,
      role: req.user?.role || null,
    });
    res.status(201).json({ status: 'ok', data: row });
  });

  router.put('/:scanTaskId', (req, res) => {
    const { status, error_message } = req.body;
    const sets = [], params = [];
    if (status) {
      sets.push('status = ?'); params.push(status);
      if (status === 'RUNNING') { sets.push('started_at = ?'); params.push(new Date().toISOString()); }
      if (['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED'].includes(status)) { sets.push('completed_at = ?'); params.push(new Date().toISOString()); }
    }
    if (error_message !== undefined) { sets.push('error_message = ?'); params.push(error_message); }
    if (sets.length === 0) return res.status(400).json({ status: 'error', error: { message: 'No fields to update' } });
    params.push(req.params.scanTaskId);
    const result = db.prepare(`UPDATE scan_tasks SET ${sets.join(', ')} WHERE scan_task_id = ?`).run(...params);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Scan task not found' } });
    res.json({ status: 'ok', data: db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id = ?').get(req.params.scanTaskId) });
  });

  router.delete('/:scanTaskId', (req, res) => {
    const result = db.prepare('DELETE FROM scan_tasks WHERE scan_task_id = ?').run(req.params.scanTaskId);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Scan task not found' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  // ── Resolve Target Profile ──────────────────────────────────────────
  // MUST be before /:scanTaskId routes to avoid being matched as a scanTaskId
  router.post('/resolve-target', (req, res) => {
    const { target } = req.body;
    if (!target) return res.status(400).json({ status: 'error', error: { message: 'target is required' } });
    const profile = resolveTargetProfile(target);
    res.json({ status: 'ok', data: profile });
  });

  // ── Execute Scan ─────────────────────────────────────────────────────
  router.post('/:scanTaskId/execute', async (req, res) => {
    const task = db.prepare('SELECT scan_task_id, target, scan_type, status FROM scan_tasks WHERE scan_task_id = ?').get(req.params.scanTaskId);
    if (!task) return res.status(404).json({ status: 'error', error: { message: 'Scan task not found' } });
    if (task.status === 'RUNNING') return res.status(409).json({ status: 'error', error: { message: 'Scan is already running' } });

    // Reset to PENDING if not already (allows re-execution of COMPLETED/FAILED/CANCELLED)
    if (task.status !== 'PENDING') {
      // Clear old results for re-execution
      db.prepare('DELETE FROM scan_results WHERE scan_task_id = ?').run(req.params.scanTaskId);
      db.prepare("UPDATE scan_tasks SET status = 'PENDING', started_at = NULL, completed_at = NULL, error_message = NULL WHERE scan_task_id = ?")
        .run(req.params.scanTaskId);
    }

    // Fire and forget — execution happens in background
    executeScan(req.params.scanTaskId).catch(err => {
      console.error(`[scans] executeScan failed for ${req.params.scanTaskId}:`, err.message || err);
    });
    // WebSocket: notify scan started (include operator info)
    const ws = getWsManager();
    if (ws) ws.broadcast('scan:started', {
      scanTaskId: req.params.scanTaskId,
      target: task.target,
      scanType: task.scan_type,
      userId: req.user?.sub || null,
      username: req.user?.sub || null,
      role: req.user?.role || null,
    });
    res.status(202).json({ status: 'ok', data: { scan_task_id: req.params.scanTaskId, message: 'Scan execution started' } });
  });

  // ── Playbook Recommendations ────────────────────────────────────────
  router.get('/:scanTaskId/recommendations', (req, res) => {
    const task = db.prepare('SELECT scan_task_id, target, status FROM scan_tasks WHERE scan_task_id = ?').get(req.params.scanTaskId);
    if (!task) return res.status(404).json({ status: 'error', error: { message: 'Scan task not found' } });
    const results = db.prepare('SELECT * FROM scan_results WHERE scan_task_id = ?').all(req.params.scanTaskId);
    if (!results.length) return res.json({ status: 'ok', data: [] });
    // Resolve target class for better playbook matching
    const targetProfile = loadTargetProfile(db, task.target);
    const recommendations = matchPlaybooks(results, targetProfile);
    res.json({ status: 'ok', data: recommendations });
  });

  // ── AI Generate Playbook ────────────────────────────────────────────
  router.post('/:scanTaskId/generate-playbook', async (req, res) => {
    try {
      const result = await generatePlaybook(req.params.scanTaskId);
      if (!result.ok) return res.status(400).json({ status: 'error', error: { message: result.error } });
      res.status(201).json({ status: 'ok', data: result });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── Scan Results ─────────────────────────────────────────────────────
  router.post('/:scanTaskId/results', (req, res) => {
    const { result_type, result_data, severity, confidence, mitre_technique_id, source_tool } = req.body;
    if (!result_type) return res.status(400).json({ status: 'error', error: { message: 'result_type is required' } });
    const task = db.prepare('SELECT scan_task_id FROM scan_tasks WHERE scan_task_id = ?').get(req.params.scanTaskId);
    if (!task) return res.status(404).json({ status: 'error', error: { message: 'Scan task not found' } });
    db.prepare(`INSERT INTO scan_results (scan_task_id, result_type, result_data, severity, confidence, mitre_technique_id, source_tool, captured_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
      req.params.scanTaskId, result_type,
      result_data ? JSON.stringify(result_data) : null,
      severity || null, confidence || null, mitre_technique_id || null,
      source_tool || null, new Date().toISOString()
    );
    res.status(201).json({ status: 'ok', data: { added: true } });
  });

  // ── Abort a running scan ─────────────────────────────────────────────
  router.post('/:scanTaskId/abort', (req, res) => {
    const task = db.prepare('SELECT status FROM scan_tasks WHERE scan_task_id = ?').get(req.params.scanTaskId);
    if (!task) return res.status(404).json({ status: 'error', error: { message: 'Scan task not found' } });
    if (task.status !== 'RUNNING' && task.status !== 'PENDING') {
      return res.status(400).json({ status: 'error', error: { message: `Scan is ${task.status}, cannot abort` } });
    }
    requestScanAbort(req.params.scanTaskId);
    db.prepare("UPDATE scan_tasks SET status = 'CANCELLED', error_message = '操作员手动中止' WHERE scan_task_id = ?")
      .run(req.params.scanTaskId);
    res.json({ status: 'ok', data: { aborted: true } });
  });

  return router;
}
