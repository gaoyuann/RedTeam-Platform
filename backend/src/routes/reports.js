import { canAccessProgramReport } from '../services/programAccess.js';
import { Router } from 'express';
import { generateReport } from '../services/reportGenerator.js';
import { readTaskReport, recordTaskReportExport } from '../services/taskResults.js';
import { exportTaskReport } from '../services/taskReportExport.js';
import { requireActor, recordParam, canAccessRecord, checkRecordAccess, getRecord } from '../middleware/recordAccess.js';
import { taskDisplayText } from '../services/taskExecution.js';

export default function (db) {
  const router = Router();
  router.use(requireActor(db));
  const allowed = (req, report) => canAccessProgramReport(db, req.user, report);
  const deny = res => res.status(403).json({status:'error',error:{message:'没有权限访问此程序测试报告'}});
  router.use((req, res, next) => {
    if (req.method === 'POST' && (req.body?.run_id || req.body?.scan_task_id) && !allowed(req, req.body)) return deny(res);
    next();
  });
  router.param('reportId', recordParam(db, 'report'));
  router.post(['/', '/generate', '/generate-and-export'], (req, res, next) => {
    const { run_id, scan_task_id } = req.body;
    if (run_id && !checkRecordAccess(db, 'run', run_id, req, res)) return;
    if (scan_task_id && !checkRecordAccess(db, 'scan', scan_task_id, req, res)) return;
    if (run_id && scan_task_id) {
      const run = getRecord(db, 'run', run_id);
      const scan = getRecord(db, 'scan', scan_task_id);
      if (run.user_sub !== scan.created_by || run.target !== scan.target)
        return res.status(409).json({ status: 'error', error: { message: '报告关联的 Run 与扫描必须属于同一用户且目标相同' } });
    }
    next();
  });
  const traceDocument = (row, user) => {
    let pipelineId;
    try { pipelineId = JSON.parse(row.content || '{}').provenance?.pipeline_id; } catch {}
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(pipelineId || '');
    if (!pipeline || !user || user.role !== 'admin' && user.sub !== pipeline.created_by)
      throw Object.assign(new Error('没有权限查看此任务追溯报告'), { status: 403 });
    return readTaskReport(db, pipeline, row.report_id);
  };

  // ── Static routes (MUST be before /:reportId to avoid shadowing) ──────

  router.get('/index', (req, res) => {
    const { limit = '50', offset = '0', kind = 'all', search = '' } = req.query;
    if (typeof limit !== 'string' || !/^\d+$/.test(limit) || !Number.isSafeInteger(Number(limit)) || Number(limit) < 1
        || typeof offset !== 'string' || !/^\d+$/.test(offset) || !Number.isSafeInteger(Number(offset))
        || !['all', 'trace_snapshot', 'legacy'].includes(kind) || typeof search !== 'string' || search.length > 120)
      return res.status(400).json({ status: 'error', error: { message: '报告筛选或分页参数无效' } });
    const pageSize = Math.min(Number(limit), 100);
    const records = [];
    for (const row of db.prepare('SELECT * FROM test_reports ORDER BY created_at DESC, id DESC').all()) {
      if (!canAccessRecord(db, 'report', row, req.user) || !allowed(req, row)) continue;
      let document;
      if (['task_trace_v1','task_trace_v2'].includes(row.template)) {
        try { document = traceDocument(row, req.user); } catch { continue; }
      }
      const reportKind = document ? 'trace_snapshot' : 'legacy';
      const source = getRecord(db, 'run', row.run_id) || getRecord(db, 'scan', row.scan_task_id);
      const record = { report_id: row.report_id, title: taskDisplayText(row.title), run_id: row.run_id,
        pipeline_id: document?.pipeline_id || null, owner: document?.owner || source?.user_sub || source?.created_by || row.generated_by || null,
        target: document?.target || taskDisplayText(source?.target || ''),
        kind: reportKind, status: row.status, review: document?.report.review
          ? { available: document.report.review.available, state: document.report.review.state, revision: document.report.review.revision } : null,
        created_at: row.created_at };
      if (kind !== 'all' && kind !== reportKind) continue;
      if (search && ![record.report_id, record.title, record.pipeline_id || '', record.target].some(value => value.toLowerCase().includes(search.toLowerCase()))) continue;
      records.push(record);
    }
    res.json({ status: 'ok', data: { schema_version: 1, records: records.slice(Number(offset), Number(offset) + pageSize),
      total: records.length, limit: pageSize, offset: Number(offset), kind, search } });
  });

  router.get('/', (req, res) => {
    const rows = db.prepare('SELECT * FROM test_reports ORDER BY created_at DESC').all().filter(row => {
      if (!canAccessRecord(db, 'report', row, req.user) || !allowed(req, row)) return false;
      if (!['task_trace_v1','task_trace_v2'].includes(row.template)) return true;
      try { traceDocument(row, req.user); return true; } catch { return false; }
    });
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  // ── Generate Report from Run ────────────────────────────────────────
  router.post('/generate', (req, res) => {
    const { run_id, title } = req.body;
    if (!run_id) return res.status(400).json({ status: 'error', error: { message: 'run_id is required' } });
    const result = generateReport(run_id, title, req.user.sub);
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

  router.use('/:reportId', (req, res, next) => {
    const report = db.prepare('SELECT * FROM test_reports WHERE report_id=?').get(req.params.reportId);
    if (report && !allowed(req, report)) return deny(res);
    next();
  });

  // ── Dynamic routes (with :reportId) ───────────────────────────────────

  router.use('/:reportId', (req, res, next) => {
    const row = db.prepare('SELECT * FROM test_reports WHERE report_id = ?').get(req.params.reportId);
    if (!['task_trace_v1','task_trace_v2'].includes(row?.template)) return next();
    try {
      req.taskTraceDocument = traceDocument(row, req.user);
      if (req.method !== 'GET') return res.status(409).json({ status: 'error', error: { message: '任务追溯报告是保存时的只读草稿，不能经旧接口编辑、删除、发布或按当前 Run 重新导出模板' } });
      next();
    } catch (error) { res.status(error.status || 500).json({ status: 'error', error: { message: error.message } }); }
  });

  router.post('/', (req, res) => {
    const { report_id, title, run_id, scan_task_id, template, content } = req.body;
    if (['task_trace_v1','task_trace_v2'].includes(template)) return res.status(400).json({ status: 'error', error: { message: '任务追溯模板仅允许通过任务来源接口生成' } });
    if (!report_id || !title) return res.status(400).json({ status: 'error', error: { message: 'report_id, title are required' } });
    const now = new Date().toISOString();
    db.prepare(`INSERT INTO test_reports (report_id, title, run_id, scan_task_id, template, content, generated_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      report_id, title, run_id || null, scan_task_id || null,
      template || null, content ? JSON.stringify(content) : null,
      req.user.sub, now, now
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
  // GET /api/reports/:reportId/export?format=docx|pdf|html|json (JSON for task snapshots)
  router.get('/:reportId/export', async (req, res) => {
    try {
      const report = db.prepare('SELECT * FROM test_reports WHERE report_id = ?').get(req.params.reportId);
      if (!report) return res.status(404).json({ status: 'error', error: { message: 'Report not found' } });
      if (!report.run_id && !req.taskTraceDocument) return res.status(400).json({ status: 'error', error: { message: 'Report has no associated run_id' } });

      const format = req.query.format || 'docx';
      if (req.taskTraceDocument) {
        const output = await exportTaskReport(req.taskTraceDocument, format);
        recordTaskReportExport(db, req.taskTraceDocument, req.user, format);
        res.setHeader('Content-Disposition', `attachment; filename="${output.filename}"`);
        res.setHeader('X-Content-Type-Options', 'nosniff');
        return res.type(output.contentType).send(output.buffer);
      }

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
      res.status(err.status || 500).json({ status: 'error', error: { message: err.message } });
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
