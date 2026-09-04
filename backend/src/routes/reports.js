import { Router } from 'express';
import { generateReport } from '../services/reportGenerator.js';

export default function (db) {
  const router = Router();

  // ── Static routes (MUST be before /:reportId to avoid shadowing) ──────

  router.get('/', (_req, res) => {
    const rows = db.prepare('SELECT * FROM test_reports ORDER BY created_at DESC').all();
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  // ── Generate Report from Run ────────────────────────────────────────
  router.post('/generate', (req, res) => {
    const { run_id, title, generated_by } = req.body;
    if (!run_id) return res.status(400).json({ status: 'error', error: { message: 'run_id is required' } });
    const result = generateReport(run_id, title, generated_by || req.user?.sub);
    if (!result.ok) return res.status(400).json({ status: 'error', error: { message: result.error } });
    res.status(201).json({ status: 'ok', data: result });
  });

  // ── Generate and Export in one step ─────────────────────────────────
  // POST /api/reports/generate-and-export  { run_id, title?, format? }
  router.post('/generate-and-export', async (req, res) => {
    try {
      const { run_id, title, format = 'docx' } = req.body;
      if (!run_id) return res.status(400).json({ status: 'error', error: { message: 'run_id is required' } });

      // Generate report record first
      const reportResult = generateReport(run_id, title, req.user?.sub);
      if (!reportResult.ok) return res.status(400).json({ status: 'error', error: { message: reportResult.error } });

      // Then export
      if (format === 'docx') {
        const { generateDocx } = await import('../services/reportDocx.js');
        const result = await generateDocx(run_id);
        if (!result.ok) return res.status(400).json({ status: 'error', error: { message: result.error } });
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
        res.setHeader('Content-Disposition', `attachment; filename="${result.fileName}"`);
        return res.send(result.buffer);
      }

      if (format === 'pdf') {
        const { generatePdf } = await import('../services/reportPdf.js');
        const result = await generatePdf(run_id);
        if (!result.ok) return res.status(400).json({ status: 'error', error: { message: result.error } });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${result.fileName}"`);
        return res.send(result.buffer);
      }

      if (format === 'html') {
        const { generateHtml } = await import('../services/reportHtml.js');
        const result = generateHtml(run_id);
        if (!result.ok) return res.status(400).json({ status: 'error', error: { message: result.error } });
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Content-Disposition', `inline; filename="report_${reportResult.report_id}.html"`);
        return res.send(result.html);
      }

      return res.status(400).json({ status: 'error', error: { message: 'Unsupported format' } });
    } catch (err) {
      console.error('[reports/generate-and-export] Error:', err);
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── List Templates ─────────────────────────────────────────────────
  // GET /api/reports/templates/list
  router.get('/templates/list', async (_req, res) => {
    try {
      const { listTemplates } = await import('../services/reportTemplate.js');
      const templates = listTemplates();
      res.json({ status: 'ok', data: templates });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── Dynamic routes (with :reportId) ───────────────────────────────────

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

  router.get('/:reportId', (req, res) => {
    const row = db.prepare('SELECT * FROM test_reports WHERE report_id = ?').get(req.params.reportId);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Report not found' } });
    res.json({ status: 'ok', data: row });
  });

  router.delete('/:reportId', (req, res) => {
    const result = db.prepare('DELETE FROM test_reports WHERE report_id = ?').run(req.params.reportId);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Report not found' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  // ── Export Report ───────────────────────────────────────────────────
  // GET /api/reports/:reportId/export?format=docx|pdf|html
  router.get('/:reportId/export', async (req, res) => {
    try {
      const report = db.prepare('SELECT * FROM test_reports WHERE report_id = ?').get(req.params.reportId);
      if (!report) return res.status(404).json({ status: 'error', error: { message: 'Report not found' } });
      if (!report.run_id) return res.status(400).json({ status: 'error', error: { message: 'Report has no associated run_id' } });

      const format = req.query.format || 'docx';

      if (format === 'docx') {
        const { generateDocx } = await import('../services/reportDocx.js');
        const result = await generateDocx(report.run_id);
        if (!result.ok) return res.status(400).json({ status: 'error', error: { message: result.error } });
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
        res.setHeader('Content-Disposition', `attachment; filename="${result.fileName}"`);
        return res.send(result.buffer);
      }

      if (format === 'pdf') {
        const { generatePdf } = await import('../services/reportPdf.js');
        const result = await generatePdf(report.run_id);
        if (!result.ok) return res.status(400).json({ status: 'error', error: { message: result.error } });
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="${result.fileName}"`);
        return res.send(result.buffer);
      }

      if (format === 'html') {
        const { generateHtml } = await import('../services/reportHtml.js');
        const result = generateHtml(report.run_id);
        if (!result.ok) return res.status(400).json({ status: 'error', error: { message: result.error } });
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.setHeader('Content-Disposition', `inline; filename="report_${report.report_id}.html"`);
        return res.send(result.html);
      }

      return res.status(400).json({ status: 'error', error: { message: 'Unsupported format. Use docx, pdf, or html.' } });
    } catch (err) {
      console.error('[reports/export] Error:', err);
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── Template-based Export ───────────────────────────────────────────
  // POST /api/reports/:reportId/export-template  { template? }
  router.post('/:reportId/export-template', async (req, res) => {
    try {
      const report = db.prepare('SELECT * FROM test_reports WHERE report_id = ?').get(req.params.reportId);
      if (!report) return res.status(404).json({ status: 'error', error: { message: 'Report not found' } });
      if (!report.run_id) return res.status(400).json({ status: 'error', error: { message: 'Report has no associated run_id' } });

      const { generateDocxFromTemplate } = await import('../services/reportTemplate.js');
      const { template } = req.body;
      const result = await generateDocxFromTemplate(report.run_id, template || undefined);
      if (!result.ok) return res.status(400).json({ status: 'error', error: { message: result.error } });
      res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document');
      res.setHeader('Content-Disposition', `attachment; filename="${result.fileName}"`);
      return res.send(result.buffer);
    } catch (err) {
      console.error('[reports/export-template] Error:', err);
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── Report Status Flow ─────────────────────────────────────────────
  // PATCH /api/reports/:reportId/status  { status: 'draft'|'reviewed'|'published' }
  router.patch('/:reportId/status', (req, res) => {
    const VALID_STATES = ['draft', 'reviewed', 'published'];
    const { status } = req.body;
    if (!VALID_STATES.includes(status)) {
      return res.status(400).json({ status: 'error', error: { message: `Invalid status. Must be one of: ${VALID_STATES.join(', ')}` } });
    }
    const report = db.prepare('SELECT status FROM test_reports WHERE report_id = ?').get(req.params.reportId);
    if (!report) return res.status(404).json({ status: 'error', error: { message: 'Report not found' } });

    // Validate state transitions
    const currentStatus = report.status;
    const currentIndex = VALID_STATES.indexOf(currentStatus);
    const newIndex = VALID_STATES.indexOf(status);
    if (currentIndex === -1) {
      return res.status(400).json({ status: 'error', error: { message: `Current status '${currentStatus}' is not a valid report state` } });
    }
    if (newIndex < currentIndex) {
      return res.status(400).json({ status: 'error', error: { message: `Cannot transition from '${currentStatus}' back to '${status}'` } });
    }

    const now = new Date().toISOString();
    db.prepare("UPDATE test_reports SET status = ?, updated_at = ? WHERE report_id = ?").run(status, now, req.params.reportId);
    const updated = db.prepare('SELECT * FROM test_reports WHERE report_id = ?').get(req.params.reportId);
    res.json({ status: 'ok', data: updated });
  });

  // ── Update Report ───────────────────────────────────────────────────
  router.put('/:reportId', (req, res) => {
    const VALID_STATES = ['draft', 'reviewed', 'published'];
    const { title, status, content } = req.body;
    const sets = [], params = [];
    if (title !== undefined) { sets.push('title = ?'); params.push(title); }
    if (status !== undefined) {
      if (!VALID_STATES.includes(status)) {
        return res.status(400).json({ status: 'error', error: { message: `Invalid status. Must be one of: ${VALID_STATES.join(', ')}` } });
      }
      sets.push('status = ?'); params.push(status);
    }
    if (content !== undefined) { sets.push('content = ?'); params.push(JSON.stringify(content)); }
    if (sets.length === 0) return res.status(400).json({ status: 'error', error: { message: 'No fields to update' } });
    sets.push('updated_at = ?');
    params.push(new Date().toISOString());
    params.push(req.params.reportId);
    const result = db.prepare(`UPDATE test_reports SET ${sets.join(', ')} WHERE report_id = ?`).run(...params);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Report not found' } });
    res.json({ status: 'ok', data: db.prepare('SELECT * FROM test_reports WHERE report_id = ?').get(req.params.reportId) });
  });

  return router;
}
