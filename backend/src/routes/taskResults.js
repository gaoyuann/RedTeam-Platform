import { Router } from 'express';
import { taskResultsSnapshot, createTaskReport, readTaskReport, taskReportHtml, recordTaskReportExport } from '../services/taskResults.js';
import { transitionReportReview } from '../services/reportReview.js';
import { requireActor } from '../middleware/recordAccess.js';

export default function (db) {
  const router = Router({ mergeParams: true });
  router.use(requireActor(db));
  router.use((req, res, next) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '任务不存在' } });
    if (!req.user || req.user.role !== 'admin' && req.user.sub !== pipeline.created_by)
      return res.status(403).json({ status: 'error', error: { message: '没有权限查看此任务结果或报告' } });
    req.taskPipeline = pipeline;
    next();
  });
  router.get('/', (req, res) => res.json({ status: 'ok', data: taskResultsSnapshot(db, req.taskPipeline) }));
  router.post('/reports', (req, res) => {
    const result = createTaskReport(db, req.taskPipeline, req.user, req.body);
    res.status(result.reused ? 200 : 201).json({ status: 'ok', data: result });
  });
  router.get('/reports/:reportId', (req, res) => res.json({ status: 'ok', data: readTaskReport(db, req.taskPipeline, req.params.reportId) }));
  router.post('/reports/:reportId/review', (req, res) => {
    const result = db.transaction(() => {
      const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
      if (!pipeline) throw Object.assign(new Error('任务不存在'), { status: 404 });
      if (req.user.role !== 'admin' && req.user.sub !== pipeline.created_by)
        throw Object.assign(new Error('没有权限审阅此任务报告'), { status: 403 });
      return transitionReportReview(db, pipeline, readTaskReport(db, pipeline, req.params.reportId), req.user, req.body);
    })();
    res.status(201).json({ status: 'ok', data: result });
  });
  router.get('/reports/:reportId/export', (req, res) => {
    const format = req.query.format || 'json';
    if (!['json', 'html'].includes(format)) return res.status(400).json({ status: 'error', error: { message: '任务追溯报告目前仅支持 JSON 或 HTML 导出' } });
    const document = readTaskReport(db, req.taskPipeline, req.params.reportId);
    if (document.report.kind !== 'trace_snapshot') return res.status(409).json({ status: 'error', error: { message: '旧报告缺少完整来源，请生成新的追溯报告' } });
    const filename = `report_${req.params.reportId.replace(/[^a-z0-9_-]/gi, '_')}.${format}`;
    const output = format === 'json' ? JSON.stringify(document, null, 2) : taskReportHtml(document);
    recordTaskReportExport(db, document, req.user, format);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.type(format === 'json' ? 'application/json' : 'text/html').send(output);
  });
  router.use((error, req, res, next) => {
    if (!error.status) return next(error);
    res.status(error.status).json({ status: 'error', error: { message: error.message } });
  });
  return router;
}
