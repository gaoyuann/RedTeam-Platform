import { Router } from 'express';
import { randomUUID } from 'crypto';
import { executeCapture, stopCapture, isCaptureRunning } from '../services/captureExecutor.js';
import { analyzeCapture } from '../services/captureAnalyzer.js';
import { getWsManager } from '../services/wsManager.js';
import { existsSync, unlinkSync } from 'fs';

export default function (db) {
  const router = Router();

  // ── List capture tasks ────────────────────────────────────────────────
  router.get('/', (req, res) => {
    const { status } = req.query;
    let sql = 'SELECT * FROM capture_tasks WHERE 1=1';
    const params = [];
    if (status) { sql += ' AND status = ?'; params.push(status); }
    sql += ' ORDER BY created_at DESC';
    const rows = db.prepare(sql).all(...params);
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  // ── List available network interfaces ─────────────────────────────────
  // MUST be registered before /:captureTaskId to avoid route shadowing
  router.get('/interfaces/list', async (req, res) => {
    try {
      const { getEngine } = await import('../tools/containerEngine.js');
      const engine = await getEngine();
      const { execFile } = await import('child_process');
      const { promisify } = await import('util');
      const execFileAsync = promisify(execFile);

      let stdout;
      if (engine === 'host') {
        const result = await execFileAsync('ip', ['link', 'show'], { timeout: 5000 });
        stdout = result.stdout;
      } else {
        // Run in container
        const result = await execFileAsync(engine, [
          'run', '--rm', '--network', 'host', '--privileged',
          'rt-capture', 'ip', 'link', 'show',
        ], { timeout: 15000 });
        stdout = result.stdout;
      }

      // Parse: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
      const interfaces = [];
      for (const line of stdout.split('\n')) {
        const match = line.match(/^\d+:\s+(\S+):/);
        if (match && !match[1].startsWith('lo')) {
          interfaces.push(match[1].replace(/:$/, ''));
        }
      }
      // Always include 'any' for capture on all interfaces
      interfaces.unshift('any');
      res.json({ status: 'ok', data: interfaces });
    } catch (err) {
      // Fallback: return common interface names
      res.json({ status: 'ok', data: ['any', 'eth0', 'eth1'] });
    }
  });

  // ── Get single capture task ───────────────────────────────────────────
  router.get('/:captureTaskId', (req, res) => {
    const row = db.prepare('SELECT * FROM capture_tasks WHERE capture_task_id = ?').get(req.params.captureTaskId);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Capture task not found' } });
    // Include analysis results
    row.analysis = db.prepare('SELECT * FROM capture_analysis WHERE capture_task_id = ? ORDER BY created_at').all(req.params.captureTaskId);
    res.json({ status: 'ok', data: row });
  });

  // ── Create capture task ───────────────────────────────────────────────
  router.post('/', (req, res) => {
    const { interface: iface, bpf_filter, capture_type, duration_sec, created_by } = req.body;
    if (!iface) return res.status(400).json({ status: 'error', error: { message: 'interface is required' } });
    const capture_task_id = `cap_${randomUUID().slice(0, 12)}`;
    const now = new Date().toISOString();
    db.prepare(`INSERT INTO capture_tasks (capture_task_id, interface, bpf_filter, capture_type, duration_sec, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
      capture_task_id,
      iface,
      bpf_filter || null,
      capture_type || 'timed',
      duration_sec || 60,
      created_by || null,
      now
    );
    const row = db.prepare('SELECT * FROM capture_tasks WHERE capture_task_id = ?').get(capture_task_id);
    // WebSocket: notify capture created
    const ws = getWsManager();
    if (ws) ws.broadcast('capture:created', {
      captureTaskId: capture_task_id, interface: iface,
      userId: req.user?.sub || created_by || null,
    });
    res.status(201).json({ status: 'ok', data: row });
  });

  // ── Start capture execution ──────────────────────────────────────────
  router.post('/:captureTaskId/start', async (req, res) => {
    const task = db.prepare('SELECT capture_task_id, status FROM capture_tasks WHERE capture_task_id = ?').get(req.params.captureTaskId);
    if (!task) return res.status(404).json({ status: 'error', error: { message: 'Capture task not found' } });
    if (task.status === 'RUNNING') return res.status(409).json({ status: 'error', error: { message: 'Capture is already running' } });

    // Reset to PENDING if re-executing
    if (task.status !== 'PENDING') {
      db.prepare("UPDATE capture_tasks SET status = 'PENDING', started_at = NULL, stopped_at = NULL, error_message = NULL, packet_count = 0, file_size_bytes = 0 WHERE capture_task_id = ?")
        .run(req.params.captureTaskId);
    }

    // Fire and forget — execution happens in background
    executeCapture(req.params.captureTaskId).catch(() => {});
    res.status(202).json({ status: 'ok', data: { capture_task_id: req.params.captureTaskId, message: 'Capture execution started' } });
  });

  // ── Stop a running capture ────────────────────────────────────────────
  router.post('/:captureTaskId/stop', (req, res) => {
    if (!isCaptureRunning(req.params.captureTaskId)) {
      return res.status(409).json({ status: 'error', error: { message: 'Capture is not running' } });
    }
    const result = stopCapture(req.params.captureTaskId);
    res.json({ status: 'ok', data: result });
  });

  // ── Delete capture task ───────────────────────────────────────────────
  router.delete('/:captureTaskId', (req, res) => {
    const task = db.prepare('SELECT capture_task_id, pcap_path, status FROM capture_tasks WHERE capture_task_id = ?').get(req.params.captureTaskId);
    if (!task) return res.status(404).json({ status: 'error', error: { message: 'Capture task not found' } });
    if (task.status === 'RUNNING') return res.status(409).json({ status: 'error', error: { message: 'Cannot delete a running capture. Stop it first.' } });

    // Delete PCAP file if it exists
    if (task.pcap_path && existsSync(task.pcap_path)) {
      try { unlinkSync(task.pcap_path); } catch {}
    }

    // Delete from DB (cascade will remove analysis results)
    db.prepare('DELETE FROM capture_tasks WHERE capture_task_id = ?').run(req.params.captureTaskId);
    res.json({ status: 'ok', data: { deleted: true } });
  });

  // ── Get analysis results ──────────────────────────────────────────────
  router.get('/:captureTaskId/analysis', (req, res) => {
    const task = db.prepare('SELECT capture_task_id FROM capture_tasks WHERE capture_task_id = ?').get(req.params.captureTaskId);
    if (!task) return res.status(404).json({ status: 'error', error: { message: 'Capture task not found' } });
    const { analysis_type } = req.query;
    let sql = 'SELECT * FROM capture_analysis WHERE capture_task_id = ?';
    const params = [req.params.captureTaskId];
    if (analysis_type) { sql += ' AND analysis_type = ?'; params.push(analysis_type); }
    sql += ' ORDER BY created_at';
    const rows = db.prepare(sql).all(...params);
    res.json({ status: 'ok', data: rows });
  });

  // ── Trigger analysis ──────────────────────────────────────────────────
  router.post('/:captureTaskId/analyze', async (req, res) => {
    const task = db.prepare('SELECT capture_task_id, status FROM capture_tasks WHERE capture_task_id = ?').get(req.params.captureTaskId);
    if (!task) return res.status(404).json({ status: 'error', error: { message: 'Capture task not found' } });
    if (task.status !== 'COMPLETED' && task.status !== 'STOPPED') {
      return res.status(400).json({ status: 'error', error: { message: 'Capture must be completed before analysis' } });
    }

    // Fire and forget — analysis happens in background
    analyzeCapture(req.params.captureTaskId)
      .then(result => {
        if (!result.ok) console.warn(`[Analyze] Failed: ${result.error}`);
      })
      .catch(() => {});

    res.status(202).json({ status: 'ok', data: { capture_task_id: req.params.captureTaskId, message: 'Analysis started' } });
  });

  return router;
}
