import { hasStatistics } from '../services/findingInstances.js';
import { publicScanRecord, summarizeScanRecords } from '../services/scanResultCatalog.js';
import { hasScanIntegrity } from '../services/scanResultStore.js';
import { normalizeTopologyTarget } from '../services/nmapTopology.js';
import { Router } from 'express';
import { randomUUID } from 'crypto';
import { recommendForScans } from '../services/playbookRecommendations.js';
import { generatePlaybook } from '../services/playbookGenerator.js';
import { executeScan, requestScanAbort, isScanActive } from '../services/scanExecutor.js';
import { getWsManager } from '../services/wsManager.js';
import { resolveTargetProfile } from '../services/targetProfileResolver.js';
import { requireActor, recordParam } from '../middleware/recordAccess.js';

import { loadSourceConnections, publicSourceConnection, resolveSourceConnection, resolveSourceConnectionForTarget, sourceTarget, httpSourceConnection } from '../services/sourceScanConnections.js';
import { browseHttpSourceDirectory } from '../services/sourceSnapshot.js';
import { recordSourceVerification } from '../services/sourceVerification.js';
import {isProgramScan, isProgramFinding, loadProgramProjects, publicProgramProject} from '../services/programScan.js';
import {appendTaskLog} from '../services/taskActivity.js';

export default function (db) {
  const router = Router();
  router.use(requireActor(db));
  router.param('scanTaskId', recordParam(db, 'scan'));
  const sourceAccess = (req, task) => !isProgramScan(task.scan_type) || req.user?.role === 'admin' || task.created_by === req.user?.sub;
  router.get('/program-projects', async (req,res) => {
    try {res.json({status:'ok',data:(await loadProgramProjects()).map(publicProgramProject)});}
    catch (error) {res.status(400).json({status:'error',error:{message:error.message}});}
  });
  router.get('/source-connections', async (req,res) => {
    try { res.json({status:'ok',data:(await loadSourceConnections()).map(publicSourceConnection)}); }
    catch(error) {res.status(400).json({status:'error',error:{message:error.message}});}
  });
  router.post('/source-directory', async (req, res) => {
    try { res.json({status:'ok',data:await browseHttpSourceDirectory(req.body.target, req.body.source_url)}); }
    catch (error) { res.status(400).json({status:'error',error:{message:error.message}}); }
  });
  router.param('scanTaskId', (req,res,next,scanTaskId)=>{
    const task=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(scanTaskId);
    if(task && !sourceAccess(req,task)) return res.status(403).json({status:'error',error:{message:'没有权限操作源码任务'}});
    next();
  });
  router.get('/:scanTaskId/source-verifications', (req,res) => {
    const task=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(req.params.scanTaskId);
    if(!task || !sourceAccess(req,task)) return res.status(404).json({status:'error',error:{message:'任务不存在或无权查看'}});
    const runs=db.prepare('SELECT r.run_id,r.status,r.target,p.metadata FROM execution_runs r JOIN playbooks p ON r.playbook_id=p.playbook_id WHERE r.scan_task_id=? OR p.generated_from=? ORDER BY r.created_at DESC LIMIT 30')
      .all(task.scan_task_id,task.scan_task_id).filter(run=>{
        try {return JSON.parse(run.metadata || '{}').source_verification?.scan_task_id===task.scan_task_id;} catch {return false;}
      }).map(({metadata,...run})=>run);
    for(const run of runs) run.evidence=db.prepare('SELECT id,step_index,raw_stdout,raw_stderr,evidence_data FROM evidence_records WHERE run_id=? ORDER BY id').all(run.run_id);
    const reviews=db.prepare('SELECT v.* FROM source_verifications v JOIN scan_results f ON v.finding_id=f.id WHERE f.scan_task_id=? ORDER BY v.id DESC').all(task.scan_task_id);
    res.json({status:'ok',data:{runs,reviews}});
  });
  router.post('/:scanTaskId/source-verifications', (req,res) => {
    const task=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(req.params.scanTaskId);
    if(!task || !sourceAccess(req,task)) return res.status(404).json({status:'error',error:{message:'任务不存在或无权复核'}});
    try {
      const row=db.prepare('SELECT scan_task_id FROM scan_results WHERE id=?').get(req.body.finding_id);
      if(row?.scan_task_id!==task.scan_task_id) throw new Error('发现不属于当前任务');
      res.json({status:'ok',data:recordSourceVerification(db,req.body.finding_id,req.body,req.user.sub)});
    } catch(error) {res.status(400).json({status:'error',error:{message:error.message}});}
  });

  router.get('/', (req, res) => {
    const { status, target, scan_type } = req.query;
    let sql = 'SELECT * FROM scan_tasks WHERE 1=1';
    const params = [];
    if (req.user.role !== 'admin') { sql += ' AND created_by = ?'; params.push(req.user.sub); }
    if (status) { sql += ' AND status = ?'; params.push(status); }
    if (target) { sql += ' AND target = ?'; params.push(target); }
    if (scan_type) { sql += ' AND scan_type = ?'; params.push(scan_type); }
    sql += ' ORDER BY created_at DESC';
    const rows = db.prepare(sql).all(...params).filter(task=>sourceAccess(req,task));
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.get('/:scanTaskId', (req, res) => {
    const row = db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id = ?').get(req.params.scanTaskId);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Scan task not found' } });
    if (!sourceAccess(req,row)) return res.status(403).json({status:'error',error:{message:'没有权限查看源码任务'}});
    row.results = db.prepare('SELECT * FROM scan_results WHERE scan_task_id = ? ORDER BY captured_at,id').all(req.params.scanTaskId);
    if(!isProgramScan(row.scan_type)) row.results=row.results.map(publicScanRecord);
    row.scan_summary=summarizeScanRecords(row.results);
    if(isProgramScan(row.scan_type)) {
      for(const result of row.results) {
        if(!isProgramFinding(result.result_type)) continue;
        const review=db.prepare('SELECT status,note,run_id,reviewed_by,created_at FROM source_verifications WHERE finding_id=? ORDER BY id DESC LIMIT 1').get(result.id);
        if(review) result.result_data=JSON.stringify({...JSON.parse(result.result_data),review});
      }
    }
    res.json({ status: 'ok', data: row });
  });

  router.post('/', async (req, res) => {
    let { target, scan_type, parameters } = req.body;
    let createdBy=req.user.sub;
    if (!target || !scan_type) return res.status(400).json({ status: 'error', error: { message: 'target, scan_type are required' } });
    if (isProgramScan(scan_type)) {
      try {
        target=sourceTarget(target);
        const inputKind=parameters?.input_kind || 'runtime';
        if(!['source','runtime'].includes(inputKind)) throw new Error('请选择源码目录或程序运行入口');
        const runtimeTarget=parameters?.runtime_target ? sourceTarget(parameters.runtime_target) : null;
        if(inputKind==='source' && !/^https?:/i.test(target)) throw new Error('源码目录须为 HTTP/HTTPS 目录地址');
        if(inputKind==='source' && runtimeTarget) httpSourceConnection(runtimeTarget,target);
        if(inputKind==='source') parameters={...parameters,source_url:parameters?.source_url || target};
        const suppliedSource = parameters?.source_url ? httpSourceConnection(target, parameters.source_url) : null;
        const matched = suppliedSource ? null : parameters?.connection_id
          ? await resolveSourceConnection(parameters.connection_id,target)
          : await resolveSourceConnectionForTarget(target);
        parameters={connection_id:matched?.id || null,source_url:suppliedSource?.source_url || null,
          input_kind:inputKind,runtime_target:runtimeTarget};
        if(inputKind==='source' && runtimeTarget) target=runtimeTarget;
      } catch(error) {return res.status(400).json({status:'error',error:{message:error.message}});}
    }
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
        createdBy=pipeline.created_by;
      }
      parameters = { ...(pipelineId ? { pipeline_id: pipelineId } : {}), timeout: 300 };
    }
    const scan_task_id = `scan_${randomUUID().slice(0, 12)}`;
    const now = new Date().toISOString();
    // Auto-resolve target_class for the new scan task
    // Source-assisted tasks retain the deployment protocol and target class.
    const targetProfile = resolveTargetProfile(target);
    db.prepare(`INSERT INTO scan_tasks (scan_task_id, target, scan_type, target_class, parameters, created_by, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(scan_task_id, target, scan_type, targetProfile.target_class, parameters ? JSON.stringify(parameters) : null, createdBy, now);
    if(scan_type==='topology_scan' && parameters?.pipeline_id && hasScanIntegrity(db))
      db.prepare('UPDATE scan_tasks SET pipeline_id=? WHERE scan_task_id=?').run(parameters.pipeline_id,scan_task_id);
    const row = db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id = ?').get(scan_task_id);
    // WebSocket: notify all clients about new scan (include operator info)
    const ws = getWsManager();
    if (ws) (isProgramScan(scan_type) ? (event,data)=>ws.broadcastProgram(req.user.sub,event,data) : (event,data)=>ws.broadcast(event,data))('scan:created', {
      scanTaskId: scan_task_id, target, scanType: scan_type,
      userId: req.user.sub,
      username: req.user?.sub || null,
      role: req.user?.role || null,
    });
    res.status(201).json({ status: 'ok', data: row });
  });

  router.put('/:scanTaskId', (req, res) => {
    const task=db.prepare('SELECT scan_type FROM scan_tasks WHERE scan_task_id=?').get(req.params.scanTaskId);
    if(isProgramScan(task?.scan_type)) return res.status(409).json({status:'error',error:{message:'程序测试状态由执行器管理，请新建任务保留证据'}});
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
    if(isScanActive(req.params.scanTaskId) || db.prepare("SELECT 1 FROM scan_tasks WHERE scan_task_id=? AND status='RUNNING'").get(req.params.scanTaskId))
      return res.status(409).json({status:'error',error:{message:'扫描尚未收束，不能删除'}});
    if(hasScanIntegrity(db) && db.prepare('SELECT 1 FROM scan_tasks WHERE retry_of_scan_task_id=?').get(req.params.scanTaskId))
      return res.status(409).json({status:'error',error:{message:'存在关联重试，须保留原扫描来源'}});
    if(hasStatistics(db) && db.prepare(`SELECT 1 FROM finding_instance_records m JOIN scan_results r ON r.id=m.finding_id
      WHERE r.scan_task_id=? LIMIT 1`).get(req.params.scanTaskId))
      return res.status(409).json({status:'error',error:{message:'扫描发现已被漏洞实例引用，须保留原始证据'}});
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
    const task = db.prepare('SELECT scan_task_id, target, scan_type, status, created_by FROM scan_tasks WHERE scan_task_id = ?').get(req.params.scanTaskId);
    if (!task) return res.status(404).json({ status: 'error', error: { message: 'Scan task not found' } });
    if (task.status === 'RUNNING') return res.status(409).json({ status: 'error', error: { message: 'Scan is already running' } });

    if(isProgramScan(task.scan_type) && task.status!=='PENDING') return res.status(409).json({status:'error',error:{message:'请新建程序测试任务以保留发现和验证证据'}});
    if (task.status !== 'PENDING') return res.status(409).json({status:'error',error:{message:'原扫描结果保留，请通过 retry 新建关联扫描'}});

    // Fire and forget — execution happens in background
    executeScan(req.params.scanTaskId).catch(err => {
      console.error(`[scans] executeScan failed for ${req.params.scanTaskId}:`, err.message || err);
    });
    // WebSocket: notify scan started (include operator info)
    const ws = getWsManager();
    if (ws) (isProgramScan(task.scan_type) ? (event,data)=>ws.broadcastProgram(task.created_by,event,data) : (event,data)=>ws.broadcast(event,data))('scan:started', {
      scanTaskId: req.params.scanTaskId,
      target: task.target,
      scanType: task.scan_type,
      userId: req.user?.sub || null,
      username: req.user?.sub || null,
      role: req.user?.role || null,
    });
    res.status(202).json({ status: 'ok', data: { scan_task_id: req.params.scanTaskId, message: 'Scan execution started' } });
  });

  // A retry is a new immutable scan identity, never a reset of old evidence.
  router.post('/:scanTaskId/retry', (req,res) => {
    const task=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(req.params.scanTaskId);
    if(isProgramScan(task.scan_type)) return res.status(409).json({status:'error',error:{message:'程序测试请新建任务'}});
    if(isScanActive(task.scan_task_id) || ['RUNNING','PENDING'].includes(task.status)) return res.status(409).json({status:'error',error:{message:'原扫描尚未收束'}});
    if(!hasScanIntegrity(db)) return res.status(409).json({status:'error',error:{message:'扫描结果迁移尚未安装'}});
    if(db.prepare("SELECT 1 FROM scan_tool_runs WHERE scan_task_id=? AND (state='running' OR json_extract(outcome,'$.stopped')=0)").get(task.scan_task_id))
      return res.status(409).json({status:'error',error:{message:'工具停止状态尚未确认'}});
    const requestId=req.body?.request_id;
    if(typeof requestId!=='string' || !/^[a-zA-Z0-9_-]{8,128}$/.test(requestId))
      return res.status(400).json({status:'error',error:{message:'重试需要 request_id（8—128 位字母、数字、横线或下划线）'}});
    const {retry,created}=db.transaction(()=>{
      let retry=db.prepare('SELECT * FROM scan_tasks WHERE retry_of_scan_task_id=? AND retry_request_id=?').get(task.scan_task_id,requestId);
      if(retry) return {retry,created:false};
      retry=db.prepare("SELECT * FROM scan_tasks WHERE retry_of_scan_task_id=? AND status IN ('PENDING','RUNNING') ORDER BY id DESC LIMIT 1").get(task.scan_task_id);
      if(retry) return {retry,created:false};
      const id=`scan_${randomUUID().slice(0,12)}`;
      // A retry is an explicitly selected follow-up, outside the original parent run.
      let parameters={};try{parameters=JSON.parse(task.parameters || '{}');}catch{}
      delete parameters.pipeline_id;
      db.prepare(`INSERT INTO scan_tasks(scan_task_id,target,scan_type,target_class,parameters,created_by,created_at,retry_of_scan_task_id,retry_request_id)
        VALUES (?,?,?,?,?,?,?,?,?)`).run(id,task.target,task.scan_type,task.target_class,JSON.stringify(parameters),task.created_by,new Date().toISOString(),task.scan_task_id,requestId);
      return {retry:db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(id),created:true};
    })();
    if(created) executeScan(retry.scan_task_id).catch(error=>console.error('[scan retry]',error.message));
    res.status(202).json({status:'ok',data:{scan_task_id:retry.scan_task_id,retry_of_scan_task_id:task.scan_task_id}});
  });

  // ── Playbook Recommendations ────────────────────────────────────────
  router.get('/:scanTaskId/recommendations', (req, res) => {
    const task = db.prepare('SELECT scan_task_id, target, status, scan_type, created_by FROM scan_tasks WHERE scan_task_id = ?').get(req.params.scanTaskId);
    if (!task) return res.status(404).json({ status: 'error', error: { message: 'Scan task not found' } });
    if (!sourceAccess(req,task)) return res.status(403).json({status:'error',error:{message:'没有权限查看源码任务'}});
    if (isProgramScan(task.scan_type)) return res.json({status:'ok',data:db.prepare("SELECT playbook_id,name,difficulty,baseline_group FROM playbooks WHERE generated_from=? ORDER BY generated_at DESC LIMIT 10").all(task.scan_task_id).map(p=>({...p,match_reason:'根据本任务程序发现及证据生成，执行后仍需复核',match_score:0,match_stage_label:'程序验证',match_status_label:'待执行 / 复核'}))});
    const recommendations = recommendForScans(db, task.target, [task.scan_task_id]);
    res.json({ status: 'ok', data: recommendations });
  });

  // ── AI Generate Playbook ────────────────────────────────────────────
  router.post('/:scanTaskId/generate-playbook', async (req, res) => {
    try {
      const task=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(req.params.scanTaskId);
      if (!task || !sourceAccess(req,task)) return res.status(404).json({status:'error',error:{message:'任务不存在或无权操作'}});
      if (req.body.adaptive !== undefined && typeof req.body.adaptive !== 'boolean') return res.status(400).json({status:'error',error:{message:'adaptive 须为布尔值'}});
      if (req.body.demonstration !== undefined && typeof req.body.demonstration !== 'boolean') return res.status(400).json({status:'error',error:{message:'demonstration 须为布尔值'}});
      if (req.body.demonstration && !isProgramScan(task.scan_type)) return res.status(400).json({status:'error',error:{message:'逐项验证仅适用于程序测试任务'}});
      const pipelines = isProgramScan(task.scan_type) ? db.prepare('SELECT pipeline_id,scan_task_id FROM pipelines WHERE created_by=?')
        .all(task.created_by).filter(row=>String(row.scan_task_id || '').split(',').includes(task.scan_task_id)) : [];
      const log = (message,level='info') => pipelines.forEach(row=>appendTaskLog(db,row.pipeline_id,message,level));
      const selectedIds=Array.isArray(req.body.finding_ids) ? req.body.finding_ids.filter(Number.isInteger).slice(0,10) : [];
      log('开始根据选中的程序发现生成验证预案'+(selectedIds.length ? ' · 漏洞编号 '+selectedIds.join(',') : ''));
      const result = await generatePlaybook(req.params.scanTaskId, null, {findingIds:req.body.finding_ids ?? [],adaptive:req.body.adaptive !== false,demonstration:req.body.demonstration === true});
      if (!result.ok) {
        log('验证预案生成失败：'+String(result.error || '未知错误').slice(0,1200)
          +(result.generation ? ` · 模型调用 ${result.generation.calls} 次，纠正 ${result.generation.corrective_attempts} 次` : ''),'warn');
        return res.status(400).json({ status: 'error', error: { message: result.error, ...(result.code ? { code: result.code } : {}) } });
      }
      log(result.requires_runtime_target ? '已保存程序预案草稿；需要补充运行地址后才能执行'
        : `已生成验证预案 · ${result.steps_count} 个步骤 · 等待建立任务草稿和审批`);
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
