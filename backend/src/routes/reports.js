import { Router } from 'express';
import { generateReport } from '../services/reportGenerator.js';

export default function (db) {
  const router = Router();

  router.get('/', (_req, res) => {
    const rows = db.prepare('SELECT * FROM test_reports ORDER BY created_at DESC').all();
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.get('/:reportId', (req, res) => {
    const row = db.prepare('SELECT * FROM test_reports WHERE report_id = ?').get(req.params.reportId);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Report not found' } });
    res.json({ status: 'ok', data: row });
  });

  router.post('/', (req, res) => {
    const { report_id, title, run_id, scan_task_id, template, content, generated_by } = req.body;
    if (!report_id || !title) return res.status(400).json({ status: 'error', error: { message: 'report_id, title are required' } });
    const now = new Date().toISOString();
    db.prepare(`INSERT INTO test_reports (report_id, title, run_id, scan_task_id, template, content, generated_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      report_id, title, run_id || null, scan_task_id || null,
      template || null, content ? JSON.stringify(content) : null,
      generated_by || null, now, now
    );
    const row = db.prepare('SELECT * FROM test_reports WHERE report_id = ?').get(report_id);
    res.status(201).json({ status: 'ok', data: row });
  });

  router.delete('/:reportId', (req, res) => {
    const result = db.prepare('DELETE FROM test_reports WHERE report_id = ?').run(req.params.reportId);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Report not found' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  // ── Generate Report from Run ────────────────────────────────────────
  router.post('/generate', (req, res) => {
    const { run_id, title } = req.body;
    if (!run_id) return res.status(400).json({ status: 'error', error: { message: 'run_id is required' } });
    const result = generateReport(run_id, title);
    if (!result.ok) return res.status(400).json({ status: 'error', error: { message: result.error } });
    res.status(201).json({ status: 'ok', data: result });
  });

  // ── Update Report ───────────────────────────────────────────────────
  router.put('/:reportId', (req, res) => {
    const { title, status, content } = req.body;
    const sets = [], params = [];
    if (title !== undefined) { sets.push('title = ?'); params.push(title); }
    if (status !== undefined) { sets.push('status = ?'); params.push(status); }
    if (content !== undefined) { sets.push('content = ?'); params.push(JSON.stringify(content)); }
    if (sets.length === 0) return res.status(400).json({ status: 'error', error: { message: 'No fields to update' } });
    sets.push("updated_at = datetime('now')");
    params.push(req.params.reportId);
    const result = db.prepare(`UPDATE test_reports SET ${sets.join(', ')} WHERE report_id = ?`).run(...params);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Report not found' } });
    res.json({ status: 'ok', data: db.prepare('SELECT * FROM test_reports WHERE report_id = ?').get(req.params.reportId) });
  });

  return router;
}
