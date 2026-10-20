import { hasStatistics } from '../services/findingInstances.js';
import findingVerificationRoutes from './findingVerifications.js';
import {isProgramMode} from '../services/programScan.js';
import { Router } from 'express';
import { randomUUID } from 'crypto';
import { askTaskAssistant } from '../services/taskAssistant.js';
import taskPlanRoutes from './taskPlans.js';
import { appendTaskLog, broadcastTaskEvent, taskSummary } from '../services/taskActivity.js';
import { taskExecutionSnapshot } from '../services/taskExecution.js';
import taskResultsRoutes from './taskResults.js';
import { assertPlaybookUse } from '../services/playbookAccess.js';
import { requireActor } from '../middleware/recordAccess.js';
import { taskAnalysisIndex } from '../services/taskAnalysisIndex.js';
import { recommendForScans } from '../services/playbookRecommendations.js';
import { captureTopologyOrigin, readTopologyOrigin } from '../services/topologyOrigin.js';
import { sourceTarget, httpSourceConnection, resolveSourceConnection } from '../services/sourceScanConnections.js';
import { normalizeTaskScope, scopeBlockingConditions, scopeConditions, taskScope } from '../services/taskScope.js';

// ── Validation helpers ────────────────────────────────────────────────────
const asyncRoute = handler => (req,res,next) => Promise.resolve().then(()=>handler(req,res,next)).catch(next);

/** Validate supported network target formats. Program URLs receive stricter validation below. */
function validateTarget(target) {
  if (typeof target !== 'string' || !target || target.length > 256) return false;
  if (/^tcp:\/\//i.test(target)) {
    try { sourceTarget(target); return true; } catch { return false; }
  }
  // Allow URLs (http://, https://) — pipelines target web applications
  if (/^https?:\/\//i.test(target)) {
    try { new URL(target); return true; } catch { return false; }
  }
  const ipCidr = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  const hostname = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
  return ipCidr.test(target) || hostname.test(target);
}

async function normalizeProgramConfig(config, target) {
  if (!isProgramMode(config.scan_mode) && !['source','program'].includes(config.test_type) && !/^tcp:\/\//i.test(target)) return {config,target};
  target=sourceTarget(target);
  const inputKind=config.input_kind || 'runtime';
  if(!['source','runtime'].includes(inputKind)) throw new Error('请选择源码目录或运行入口');
  if(inputKind==='source' && !/^https?:/i.test(target)) throw new Error('源码目录须为HTTP/HTTPS地址');
  const runtime=config.runtime_target ? sourceTarget(config.runtime_target) : null;
  if(inputKind==='source' && runtime) httpSourceConnection(runtime,target);
  const sourceValue=inputKind==='source' ? config.source_url || target : config.source_url;
  const source=sourceValue ? httpSourceConnection(target,sourceValue) : null;
  if(!source && config.source_connection_id) await resolveSourceConnection(config.source_connection_id,target);
  const legacy=config.scan_mode==='source_assisted' || config.test_type==='source';
  return {target:inputKind==='source' && runtime ? runtime : target,config:{...config,test_type:legacy?'source':'program',scan_mode:legacy?'source_assisted':'program_dynamic',input_kind:inputKind,runtime_target:runtime,require_approval:true,
    source_url:source?.source_url || null,source_connection_id:source ? null : config.source_connection_id || null}};
}

/** Only creator or admin can modify a pipeline. */
function canModifyPipeline(req, pipeline) {
  return req.user.role === 'admin' || req.user.sub === pipeline.created_by;
}

/** Enforce pipeline creation limits. */
function checkPipelineLimits(db, username) {
  const userActive = db.prepare(
    "SELECT COUNT(*) AS n FROM pipelines WHERE created_by = ? AND status IN ('created','running')"
  ).get(username).n;
  if (userActive >= 20) return '活跃流水线数量已达上限(20)';

  const globalRunning = db.prepare(
    "SELECT COUNT(*) AS n FROM pipelines WHERE status = 'running'"
  ).get().n;
  if (globalRunning >= 5) return '运行中流水线数量已达上限(5)';

  return null;
}

/** Write audit log entry. */
function auditLog(db, type, pipelineId, userRole, target, reasons) {
  try {
    db.prepare(`INSERT INTO audit_log (type, execution_id, user_role, target, timestamp, reasons)
      VALUES (?, ?, ?, ?, datetime('now'), ?)`).run(type, pipelineId, userRole, target, JSON.stringify(reasons));
  } catch { /* audit failure should not break business logic */ }
}

// ── Status translation ────────────────────────────────────────────────────

function statusCn(s) {
  const map = {
    created: '已创建', running: '运行中', paused: '已暂停',
    awaiting_approval: '待确认',
    completed: '已完成', failed: '失败', cancelled: '已取消',
    pending: '待执行', skipped: '已跳过',
  };
  return map[s] || s;
}

// ── Step type translation ─────────────────────────────────────────────────

const STEP_TYPE_CN = {
  scan: '扫描', analyze: '分析', generate: '生成', execute: '执行',
};

// ── Route factory ─────────────────────────────────────────────────────────

export default function (db) {
  const router = Router();
  const assistantRequests = new Set();
  router.use('/:id/results', taskResultsRoutes(db));
  router.use('/:id/verifications', findingVerificationRoutes(db));

  router.get('/analysis-index', requireActor(db), (req, res, next) => {
    try {
      res.json({ status: 'ok', data: taskAnalysisIndex(db, { username: req.user.sub, role: req.user.role }, req.query) });
    } catch (error) {
      next(error);
    }
  });

  // ── Pipeline CRUD ──────────────────────────────────────────────────────

  // List pipelines
  router.get('/', (req, res) => {
    const { status } = req.query;
    let sql = 'SELECT * FROM pipelines WHERE 1=1';
    const params = [];
    if (status) { sql += ' AND status = ?'; params.push(status); }
    // Non-admin sees only their own
    if (req.user.role !== 'admin') { sql += ' AND created_by = ?'; params.push(req.user.sub); }
    sql += ' ORDER BY created_at DESC';
    const rows = db.prepare(sql).all(...params);
    for (const row of rows) { row.status_cn = statusCn(row.status); }
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  // Get pipeline detail (with steps)
  router.get('/:id', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
    // Access check
    if (req.user.role !== 'admin' && pipeline.created_by !== req.user.sub) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限查看此流水线' } });
    }
    pipeline.status_cn = statusCn(pipeline.status);

    // Parse JSON fields
    try { pipeline.config = JSON.parse(pipeline.config || '{}'); } catch {}
    try { pipeline.analysis_result = JSON.parse(pipeline.analysis_result || '{}'); } catch {}
    try { pipeline.result = JSON.parse(pipeline.result || '{}'); } catch {}

    // Steps
    pipeline.steps = db.prepare(
      'SELECT * FROM pipeline_steps WHERE pipeline_id = ? ORDER BY step_order'
    ).all(pipeline.pipeline_id);
    for (const step of pipeline.steps) {
      step.status_cn = statusCn(step.status);
      step.step_type_cn = STEP_TYPE_CN[step.step_type] || step.step_type;
      try { step.input_data = JSON.parse(step.input_data || '{}'); } catch {}
      try { step.output_data = JSON.parse(step.output_data || '{}'); } catch {}
    }

    pipeline.summary = taskSummary(db, pipeline);
    pipeline.missing_conditions = scopeConditions(taskScope(pipeline));

    res.json({ status: 'ok', data: pipeline });
  });

  router.get('/:id/execution', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '任务不存在' } });
    if (!canModifyPipeline(req, pipeline))
      return res.status(403).json({ status: 'error', error: { message: '没有权限查看此任务执行记录' } });
    const snapshot = taskExecutionSnapshot(db, pipeline);
    if (!snapshot) return res.status(409).json({ status: 'error', error: { message: '任务关联执行记录的所有者或目标不匹配，请核对来源' } });
    res.json({ status: 'ok', data: snapshot });
  });

  router.get('/:id/logs', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '任务不存在' } });
    if (!canModifyPipeline(req, pipeline))
      return res.status(403).json({ status: 'error', error: { message: '没有权限查看此任务日志' } });
    const limit = req.query.limit === undefined ? 100 : Number(req.query.limit);
    const after = req.query.after === undefined ? null : Number(req.query.after);
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200 || (after !== null && (!Number.isSafeInteger(after) || after < 0)))
      return res.status(400).json({ status: 'error', error: { message: '日志游标或条数无效（每次 1–200 条）' } });
    let rows;
    if (after === null) rows = db.prepare('SELECT * FROM pipeline_logs WHERE pipeline_id = ? ORDER BY id DESC LIMIT ?')
      .all(req.params.id, limit).reverse();
    else rows = db.prepare('SELECT * FROM pipeline_logs WHERE pipeline_id = ? AND id > ? ORDER BY id ASC LIMIT ?')
      .all(req.params.id, after, limit + 1);
    const hasMore = after !== null && rows.length > limit;
    if (hasMore) rows.pop();
    res.json({ status: 'ok', pipeline_id: req.params.id, data: rows,
      meta: { has_more: hasMore, history_limit: 2000, next_cursor: rows.at(-1)?.id ?? after ?? 0 } });
  });

  router.post('/:id/assistant', async (req, res, next) => {
    let requestKey;
    try {
      const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
      if (!message || message.length > 2000)
        return res.status(400).json({ status: 'error', error: { message: '问题不能为空，且不能超过 2000 个字符' } });
      const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
      if (!pipeline)
        return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
      if (!canModifyPipeline(req, pipeline))
        return res.status(403).json({ status: 'error', error: { message: '没有权限查看此流水线' } });
      const key = `${req.user.sub}:${pipeline.pipeline_id}`;
      if (assistantRequests.has(key) || assistantRequests.size >= 5)
        return res.status(429).json({ status: 'error', error: { message: 'AI 问答繁忙，请等待当前请求完成后重试' } });
      requestKey = key;
      assistantRequests.add(key);
      const history = Array.isArray(req.body?.history) ? req.body.history
        .filter(item => item && ['user', 'assistant'].includes(item.role) && typeof item.content === 'string')
        .slice(-6).map(item => ({ role: item.role, content: item.content.trim().slice(0, 800) })) : [];
      const result = await askTaskAssistant(db, pipeline, message, history);
      const stage = typeof req.body?.stage === 'string' ? req.body.stage.slice(0, 80) : null;
      auditLog(db, result.ok ? 'pipeline_assistant_query' : 'pipeline_assistant_error',
        pipeline.pipeline_id, req.user.role, pipeline.target, { message_length: message.length, stage });
      if (!result.ok)
        return res.status(503).json({ status: 'error', error: { message: '模型未配置、调用失败或返回空内容，请检查模型服务后重试' } });
      res.json({ status: 'ok', data: {
        task_id: pipeline.pipeline_id, answer: result.answer, citations: result.citations,
      } });
    } catch (error) {
      next(error);
    } finally {
      if (requestKey) assistantRequests.delete(requestKey);
    }
  });

  // Create pipeline
  router.post('/', asyncRoute(async (req, res) => {
    let { target, config } = req.body;
    if (!target) {
      return res.status(400).json({ status: 'error', error: { message: '目标地址不能为空' } });
    }
    if (target && !validateTarget(target)) {
      return res.status(400).json({ status: 'error', error: { message: '目标地址格式无效（支持HTTP/HTTPS、tcp://主机:端口、IP/CIDR/主机名）' } });
    }

    const limitErr = checkPipelineLimits(db, req.user.sub);
    if (limitErr) {
      return res.status(429).json({ status: 'error', error: { message: limitErr } });
    }

    const pipelineId = `pipe_${randomUUID().slice(0, 12)}`;
    const now = new Date().toISOString();

    // Validate and sanitize config
    let configJson = '{}';
    if (config) {
      try {
        const parsed = typeof config === 'string' ? JSON.parse(config) : config;
        // Only allow known config keys
        const sanitized = {};
        const allowedKeys = ['auto_execute', 'timeout', 'scan_parameters', 'execution_parameters', 'require_approval', 'task_name', 'test_type', 'authorization_confirmed', 'authorization_scope', 'creation_mode', 'created_by_label', 'scan_mode', 'source_url', 'source_connection_id', 'input_kind', 'runtime_target', 'task_scope'];
        for (const key of allowedKeys) {
          if (parsed[key] !== undefined) sanitized[key] = parsed[key];
        }
        configJson = JSON.stringify(sanitized);
      } catch {
        configJson = '{}';
      }
    }

    try {
      const program=await normalizeProgramConfig(JSON.parse(configJson),target);
      target=program.target;
      configJson=JSON.stringify({...program.config,task_scope:normalizeTaskScope(program.config,target),topology_origin:captureTopologyOrigin(req)});
    } catch(error) {return res.status(400).json({status:'error',error:{message:error.message}});}
    try {
      db.prepare(`INSERT INTO pipelines (pipeline_id, target, status, config, created_by, created_at, updated_at)
        VALUES (?, ?, 'created', ?, ?, ?, ?)`).run(pipelineId, target, configJson, req.user.sub, now, now);

      auditLog(db, 'pipeline_create', pipelineId, req.user.role, target, { config: configJson });
      appendTaskLog(db, pipelineId, '任务已创建，等待启动');

      const row = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(pipelineId);
      row.status_cn = statusCn(row.status);
      // Parse JSON fields for the response
      try { row.config = JSON.parse(row.config || '{}'); } catch {}
      try { row.analysis_result = JSON.parse(row.analysis_result || '{}'); } catch {}
      try { row.result = JSON.parse(row.result || '{}'); } catch {}

      // WebSocket broadcast
      broadcastTaskEvent(db, 'pipeline:created', { pipeline_id: pipelineId, target, user: req.user.sub });

      res.status(201).json({ status: 'ok', data: row });
    } catch (err) {
      if (err.message.includes('UNIQUE')) {
        return res.status(409).json({ status: 'error', error: { message: '流水线ID冲突，请重试' } });
      }
      throw err;
    }
  }));

  router.use('/:id/plan', taskPlanRoutes(db));

  // Update pipeline
  router.put('/:id', asyncRoute(async (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
    if (!canModifyPipeline(req, pipeline)) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限修改此流水线' } });
    }

    const { config } = req.body;
    if (db.prepare('SELECT pipeline_id FROM task_plans WHERE pipeline_id = ?').get(req.params.id)) {
      return res.status(409).json({ status: 'error', error: { message: '已有任务预案，任务配置已冻结；请新建任务调整授权或执行策略' } });
    }
    const sets = [];
    const params = [];

    if (config !== undefined) {
      let configStr = '{}';
      try {
        const parsed = typeof config === 'string' ? JSON.parse(config) : config;
        if (typeof parsed === 'object' && parsed !== null) {
          // Only allow known config keys (same whitelist as create)
          const sanitized = {};
          const allowedKeys = ['auto_execute', 'timeout', 'scan_parameters', 'execution_parameters', 'require_approval', 'task_name', 'test_type', 'authorization_confirmed', 'authorization_scope', 'creation_mode', 'created_by_label', 'scan_mode', 'source_url', 'source_connection_id', 'input_kind', 'runtime_target', 'task_scope'];
          for (const key of allowedKeys) {
            if (parsed[key] !== undefined) sanitized[key] = parsed[key];
          }
          configStr = JSON.stringify(sanitized);
        }
      } catch {}
      try {
        const previous=JSON.parse(pipeline.config || '{}');
        const requested=JSON.parse(configStr);
        if(requested.task_scope === undefined) requested.task_scope=previous.task_scope;
        const normalized=await normalizeProgramConfig(requested,pipeline.target);
        normalized.config.task_scope=normalizeTaskScope(normalized.config,normalized.target);
        if(pipeline.status!=='created' && JSON.stringify(previous.task_scope || normalizeTaskScope(previous,pipeline.target))!==JSON.stringify(normalized.config.task_scope))
          return res.status(409).json({status:'error',error:{message:'扫描已启动，不能改变测试范围；请新建任务'}});
        if(pipeline.status!=='created' && ['scan_mode','source_url','source_connection_id','input_kind','runtime_target'].some(key=>(previous[key] ?? null)!==(normalized.config[key] ?? null))) {
          return res.status(409).json({status:'error',error:{message:'扫描已启动，不能改变程序测试模式或源码来源；请新建任务'}});
        }
        configStr=JSON.stringify(normalized.config);
      } catch(error) {return res.status(400).json({status:'error',error:{message:error.message}});}
      const origin = readTopologyOrigin(pipeline.config);
      if (origin) configStr = JSON.stringify({ ...JSON.parse(configStr), topology_origin: origin });
      sets.push('config = ?');
      params.push(configStr);
    }

    if (sets.length === 0) {
      return res.status(400).json({ status: 'error', error: { message: '无更新内容' } });
    }

    sets.push("updated_at = datetime('now')");
    params.push(req.params.id);

    db.prepare(`UPDATE pipelines SET ${sets.join(', ')} WHERE pipeline_id = ?`).run(...params);

    auditLog(db, 'pipeline_update', req.params.id, req.user.role, pipeline.target, { fields: sets });

    const row = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    row.status_cn = statusCn(row.status);
    res.json({ status: 'ok', data: row });
  }));

  // Delete pipeline
  router.delete('/:id', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
    if (!canModifyPipeline(req, pipeline)) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限删除此流水线' } });
    }
    if (['running', 'awaiting_approval'].includes(pipeline.status)) {
      return res.status(400).json({ status: 'error', error: { message: '运行中或待确认的流水线不能删除，请先取消' } });
    }

    if(hasStatistics(db) && db.prepare(`SELECT 1 FROM finding_instances WHERE pipeline_id=?
      UNION ALL SELECT 1 FROM task_baselines WHERE pipeline_id=?
      UNION ALL SELECT 1 FROM test_reports WHERE pipeline_id=? LIMIT 1`).get(req.params.id,req.params.id,req.params.id))
      return res.status(409).json({status:'error',error:{message:'任务存在漏洞实例、基准或冻结报告引用，须保留统计来源'}});
    db.prepare('DELETE FROM pipelines WHERE pipeline_id = ?').run(req.params.id);
    auditLog(db, 'pipeline_delete', req.params.id, req.user.role, pipeline.target, {});
    res.json({ status: 'ok', data: { deleted: true } });
  });

  // ── Pipeline execution ─────────────────────────────────────────────────

  // Start pipeline (fire-and-forget)
  router.post('/:id/start', async (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
    if (!canModifyPipeline(req, pipeline)) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限启动此流水线' } });
    }
    if (pipeline.status !== 'created') {
      return res.status(400).json({ status: 'error', error: { message: `不能从"${statusCn(pipeline.status)}"状态启动` } });
    }
    if (!pipeline.target) {
      return res.status(400).json({ status: 'error', error: { message: '流水线未设置目标地址，无法启动' } });
    }
    const missing=scopeBlockingConditions(taskScope(pipeline));
    if(missing.length) return res.status(409).json({status:'error',error:{message:`启动条件缺失：${missing.join('；')}`}});

    const globalRunning = db.prepare("SELECT COUNT(*) AS n FROM pipelines WHERE status = 'running'").get().n;
    if (globalRunning >= 5) {
      return res.status(429).json({ status: 'error', error: { message: '运行中流水线数量已达上限(5)' } });
    }

    const now = new Date().toISOString();
    let startConfig = {};
    try { startConfig = JSON.parse(pipeline.config || '{}'); } catch {}
    startConfig = { ...startConfig, topology_origin: captureTopologyOrigin(req) };
    db.prepare("UPDATE pipelines SET status = 'running', updated_at = ?, config = ? WHERE pipeline_id = ?")
      .run(now, JSON.stringify(startConfig), req.params.id);
    auditLog(db, 'pipeline_start', req.params.id, req.user.role, pipeline.target, { from: pipeline.status, to: 'running' });
    appendTaskLog(db, req.params.id, '已请求启动任务');

    broadcastTaskEvent(db, 'pipeline:started', { pipeline_id: req.params.id, target: pipeline.target, user: req.user.sub });

    // Fire-and-forget: start pipeline engine
    try {
      const { runPipeline } = await import('../services/pipelineEngine.js');
      runPipeline(req.params.id).catch(err => {
        console.error(`[PipelineEngine] Error for ${req.params.id}:`, err.message);
      });
    } catch (err) {
      console.error('[PipelineEngine] Failed to import engine:', err.message);
    }

    const row = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    row.status_cn = statusCn(row.status);
    res.status(202).json({ status: 'ok', data: row });
  });

  // Cancel running pipeline
  router.post('/:id/cancel', async (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
    if (!canModifyPipeline(req, pipeline)) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限取消此流水线' } });
    }
    if (!['running', 'awaiting_approval'].includes(pipeline.status)) {
      return res.status(400).json({ status: 'error', error: { message: '只有运行中或待确认的流水线可以取消' } });
    }

    // Call cancelPipeline from the engine
    try {
      const { cancelPipeline } = await import('../services/pipelineEngine.js');
      const result = cancelPipeline(req.params.id);
      if (!result.ok) {
        console.error(`[PipelineEngine] Cancel failed for ${req.params.id}: ${result.error}`);
      }
    } catch (err) {
      console.error('[PipelineEngine] Failed to import engine for cancel:', err.message);
    }

    auditLog(db, 'pipeline_cancel', req.params.id, req.user.role, pipeline.target, {});
    appendTaskLog(db, req.params.id, '已请求取消任务', 'warn');

    const row = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    row.status_cn = statusCn(row.status);
    res.json({ status: 'ok', data: row });
  });

  // Approve a pipeline awaiting human approval (resume from execute step)
  router.post('/:id/approve', async (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
    if (!canModifyPipeline(req, pipeline)) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限审批此流水线' } });
    }
    let approvalConfig={};try {approvalConfig=JSON.parse(pipeline.config || '{}');} catch {}
    if(isProgramMode(approvalConfig.scan_mode)) {
      return res.status(409).json({status:'error',error:{message:'程序测试需先选择发现并建立任务预案，不能绕过演示对象清单直接执行'}});
    }
    if (db.prepare('SELECT pipeline_id FROM task_plans WHERE pipeline_id = ?').get(req.params.id)) {
      return res.status(409).json({ status: 'error', error: { message: '此任务已有预案草稿，请通过任务预案页提审并审批具体版本' } });
    }
    if (pipeline.status !== 'awaiting_approval') {
      return res.status(400).json({ status: 'error', error: { message: `只有待确认状态的流水线可以审批，当前状态: ${statusCn(pipeline.status)}` } });
    }

    // 用户可选择执行哪个 playbook（覆盖 AI 生成的）
    const selectedPlaybookId = req.body?.playbook_id;
    const recommendation = recommendForScans(db, pipeline.target, String(pipeline.scan_task_id || '').split(','))
      .find(candidate => candidate.playbook_id === (selectedPlaybookId || pipeline.generated_playbook_id));
    if (recommendation?.match_status === 'needs_input') {
      return res.status(409).json({ status: 'error', error: {
        message: `执行条件尚未满足：${recommendation.match_conditions.join('；')}。请补充入口后重新创建任务，或选择其他预案。`,
      } });
    }
    if (selectedPlaybookId || pipeline.generated_playbook_id) {
      try { assertPlaybookUse(db, selectedPlaybookId || pipeline.generated_playbook_id, req.user, pipeline.created_by); }
      catch (error) { return res.status(error.status || 500).json({ status: 'error', error: { message: error.message } }); }
    }
    if (selectedPlaybookId && selectedPlaybookId !== pipeline.generated_playbook_id) {
      db.prepare("UPDATE pipelines SET generated_playbook_id = ?, updated_at = datetime('now') WHERE pipeline_id = ?")
        .run(selectedPlaybookId, req.params.id);
      auditLog(db, 'pipeline_playbook_override', req.params.id, req.user.role, pipeline.target,
        { from: pipeline.generated_playbook_id, to: selectedPlaybookId });
    }

    auditLog(db, 'pipeline_approve', req.params.id, req.user.role, pipeline.target, { from: 'awaiting_approval', to: 'running' });

    // Fire-and-forget: resume pipeline from execute step
    // (resumePipelineAfterApproval will set status to 'running' and execute)
    try {
      const { resumePipelineAfterApproval } = await import('../services/pipelineEngine.js');
      resumePipelineAfterApproval(req.params.id).catch(err => {
        console.error(`[PipelineEngine] Resume after approval failed for ${req.params.id}:`, err.message);
      });
    } catch (err) {
      console.error('[PipelineEngine] Failed to import engine for resume:', err.message);
    }

    const row = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    row.status_cn = statusCn(row.status);
    res.status(202).json({ status: 'ok', data: row });
  });

  // ── Pipeline steps sub-routes ──────────────────────────────────────────

  // Get pipeline steps
  router.get('/:id/steps', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
    if (!canModifyPipeline(req, pipeline))
      return res.status(403).json({ status: 'error', error: { message: '没有权限查看此流水线步骤' } });

    const steps = db.prepare(
      'SELECT * FROM pipeline_steps WHERE pipeline_id = ? ORDER BY step_order'
    ).all(req.params.id);
    for (const step of steps) {
      step.status_cn = statusCn(step.status);
      step.step_type_cn = STEP_TYPE_CN[step.step_type] || step.step_type;
      try { step.input_data = JSON.parse(step.input_data || '{}'); } catch {}
      try { step.output_data = JSON.parse(step.output_data || '{}'); } catch {}
    }

    res.json({ status: 'ok', data: steps });
  });

  // ── Pipeline report ────────────────────────────────────────────────────

  router.get('/:id/report', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
    if (!canModifyPipeline(req, pipeline))
      return res.status(403).json({ status: 'error', error: { message: '没有权限查看此任务报告' } });

    const steps = db.prepare(
      'SELECT * FROM pipeline_steps WHERE pipeline_id = ? ORDER BY step_order'
    ).all(pipeline.pipeline_id);

    let analysisResult = {};
    try { analysisResult = JSON.parse(pipeline.analysis_result || '{}'); } catch {}

    let finalResult = {};
    try { finalResult = JSON.parse(pipeline.result || '{}'); } catch {}

    const report = {
      pipeline_id: pipeline.pipeline_id,
      target: pipeline.target,
      status: pipeline.status,
      created_at: pipeline.created_at,
      created_by: pipeline.created_by,
      steps: steps.map(s => ({
        step_order: s.step_order,
        step_type: s.step_type,
        step_type_cn: STEP_TYPE_CN[s.step_type] || s.step_type,
        status: s.status,
        started_at: s.started_at,
        completed_at: s.completed_at,
        error_message: s.error_message,
      })),
      analysis: {
        attack_surface: analysisResult.attack_surface || null,
        risk_assessment: analysisResult.risk_assessment || null,
        recommended_strategy: analysisResult.recommended_strategy || null,
      },
      result: finalResult,
    };

    res.json({ status: 'ok', data: report });
  });

  return router;
}
