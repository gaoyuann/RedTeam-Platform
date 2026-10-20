import { taskStatistics } from '../services/taskStatistics.js';
import { syncInstances, fail } from '../services/findingInstances.js';
import { baselineVersions, importBaseline } from '../services/taskBaselines.js';
import { scanPage, scanCollection, pipelineScans } from '../services/scanResultQuery.js';
import { publicScanRecord, parseResultData, redactScanValue } from '../services/scanResultCatalog.js';
import { Router } from 'express';
import { taskResultsSnapshot, createTaskReport, readTaskReport, taskReportHtml, recordTaskReportExport } from '../services/taskResults.js';
import { requireActor } from '../middleware/recordAccess.js';
import { scanCoveragePage } from '../services/scanCoverage.js';
import { bindFindingPayload, findingPayloadMatches } from '../services/findingPayloads.js';

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
  router.get('/', (req, res) => res.json({ status: 'ok', data: req.query.view==='scans' ? scanPage(db,req.taskPipeline,req.query) : {...taskResultsSnapshot(db, req.taskPipeline),...scanPage(db,req.taskPipeline,req.query)} }));
  const current=req=>{
    const value=taskStatistics(db,req.taskPipeline);
    const expected=req.query.source_fingerprint || req.body?.source_fingerprint;
    if(expected!==undefined && expected!==value.source_fingerprint)fail(409,'来源已变化，请刷新');
    return value;
  };
  router.post('/instances/sync',(req,res)=>res.json({status:'ok',data:db.transaction(()=>{
    if(!/^[a-f0-9]{64}$/.test(req.body?.source_fingerprint || ''))fail(400,'缺少来源指纹');
    current(req);syncInstances(db,req.taskPipeline);return current({...req,body:{},query:{}});
  })()}));
  router.get('/instances',(req,res)=>{
    const data=current(req), {conclusion='all',severity='all',after='',limit='100'}=req.query;
    if(!['all','pending','confirmed','not_verified','inconclusive','false_positive','conflict'].includes(conclusion)
      || !['all','unknown','info','low','medium','high','critical'].includes(severity)
      || !/^\d+$/.test(String(limit)) || Number(limit)<1 || Number(limit)>500 || typeof after!=='string' || after && !/^fi_[a-f0-9]{32}$/.test(after))fail(400,'实例分页或筛选无效');
    const filtered=data.instances.filter(i=>(conclusion==='all'||i.conclusion===conclusion)&&(severity==='all'||i.severity===severity));
    const remaining=filtered.filter(i=>i.instance_id>after),rows=remaining.slice(0,Number(limit));
    res.json({status:'ok',data:{source_fingerprint:data.source_fingerprint,rows,page:{total:filtered.length,has_more:remaining.length>rows.length,next_after:rows.at(-1)?.instance_id || after}}});
  });
  router.get('/instances/:instanceId',(req,res)=>{
    const data=current(req),instance=data.instances.find(i=>i.instance_id===req.params.instanceId);
    if(!instance)fail(404,'实例不存在或不属于此任务');
    res.json({status:'ok',data:{source_fingerprint:data.source_fingerprint,instance,records:data.records.filter(r=>instance.record_ids.includes(r.id))}});
  });
  router.get('/baselines',(req,res)=>res.json({status:'ok',data:baselineVersions(db,req.taskPipeline)}));
  router.post('/baselines',(req,res)=>res.json({status:'ok',data:db.transaction(()=>{
    if(!/^[a-f0-9]{64}$/.test(req.body?.source_fingerprint || ''))fail(400,'缺少来源指纹');
    current(req);return importBaseline(db,req.taskPipeline,req.user,req.body.content,{preview:req.body.preview===true});
  })()}));
  router.get('/coverage', (req,res) => res.json({status:'ok',data:scanCoveragePage(db,req.taskPipeline.pipeline_id,req.query)}));
  const taskFinding = (req) => {
    if (!/^[1-9]\d*$/.test(req.params.recordId))
      throw Object.assign(new Error('发现编号无效'), {status:400});
    const row=db.prepare('SELECT * FROM scan_results WHERE id=?').get(req.params.recordId);
    if(!row || !pipelineScans(db,req.taskPipeline).some(scan=>scan.scan_task_id===row.scan_task_id))
      throw Object.assign(new Error('结果不存在或不属于此任务'), {status:404});
    return row;
  };
  router.get('/records/:recordId/payload-matches', (req,res) => {
    const row=taskFinding(req);
    res.json({status:'ok',data:findingPayloadMatches(db,row)});
  });
  router.post('/records/:recordId/payload-links', (req,res) => {
    const row=taskFinding(req);
    const data=bindFindingPayload(db,row,req.body?.payload_id,req.body?.version,req.user.sub);
    res.json({status:'ok',data});
  });
  router.get('/records/:recordId', (req,res) => {
    const collection=scanCollection(db,req.taskPipeline);
    const row=collection.rows.find(r=>String(r.id)===req.params.recordId);
    if(!row) return res.status(404).json({status:'error',error:{message:'结果不存在或不属于此任务'}});
    const run=collection.runs.find(r=>r.tool_run_id===row.tool_run_id);
    res.json({status:'ok',data:{record:publicScanRecord(row),evidence:redactScanValue(parseResultData(run?.evidence))}});
  });
  router.post('/reports', (req, res) => {
    const result = createTaskReport(db, req.taskPipeline, req.user, req.body);
    res.status(result.reused ? 200 : 201).json({ status: 'ok', data: result });
  });
  router.get('/reports/:reportId', (req, res) => res.json({ status: 'ok', data: readTaskReport(db, req.taskPipeline, req.params.reportId) }));
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
