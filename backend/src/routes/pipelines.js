import { Router } from 'express';
import { randomUUID } from 'crypto';
import { getWsManager } from '../services/wsManager.js';

// ── Validation helpers ────────────────────────────────────────────────────

/** Validate target: IP, CIDR, or hostname. Reject protocol prefixes (SSRF). */
function validateTarget(target) {
  if (!target || target.length > 256) return false;
  // Allow URLs (http://, https://) — pipelines target web applications
  if (/^https?:\/\//i.test(target)) {
    try { new URL(target); return true; } catch { return false; }
  }
  const ipCidr = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  const hostname = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
  return ipCidr.test(target) || hostname.test(target);
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

    res.json({ status: 'ok', data: pipeline });
  });

  // Create pipeline
  router.post('/', (req, res) => {
    const { target, config } = req.body;
    if (!target) {
      return res.status(400).json({ status: 'error', error: { message: '目标地址不能为空' } });
    }
    if (target && !validateTarget(target)) {
      return res.status(400).json({ status: 'error', error: { message: '目标地址格式无效（支持URL/IP/CIDR/主机名）' } });
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
        const allowedKeys = ['auto_execute', 'timeout', 'scan_parameters', 'execution_parameters'];
        for (const key of allowedKeys) {
          if (parsed[key] !== undefined) sanitized[key] = parsed[key];
        }
        configJson = JSON.stringify(sanitized);
      } catch {
        configJson = '{}';
      }
    }

    try {
      db.prepare(`INSERT INTO pipelines (pipeline_id, target, status, config, created_by, created_at, updated_at)
        VALUES (?, ?, 'created', ?, ?, ?, ?)`).run(pipelineId, target, configJson, req.user.sub, now, now);

      auditLog(db, 'pipeline_create', pipelineId, req.user.role, target, { config: configJson });

      const row = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(pipelineId);
      row.status_cn = statusCn(row.status);
      // Parse JSON fields for the response
      try { row.config = JSON.parse(row.config || '{}'); } catch {}
      try { row.analysis_result = JSON.parse(row.analysis_result || '{}'); } catch {}
      try { row.result = JSON.parse(row.result || '{}'); } catch {}

      // WebSocket broadcast
      const ws = getWsManager();
      if (ws) ws.broadcast('pipeline:created', { pipeline_id: pipelineId, target, user: req.user.sub });

      res.status(201).json({ status: 'ok', data: row });
    } catch (err) {
      if (err.message.includes('UNIQUE')) {
        return res.status(409).json({ status: 'error', error: { message: '流水线ID冲突，请重试' } });
      }
      throw err;
    }
  });

  // Update pipeline
  router.put('/:id', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
    if (!canModifyPipeline(req, pipeline)) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限修改此流水线' } });
    }

    const { config } = req.body;
    const sets = [];
    const params = [];

    if (config !== undefined) {
      let configStr = '{}';
      try {
        const parsed = typeof config === 'string' ? JSON.parse(config) : config;
        if (typeof parsed === 'object' && parsed !== null) {
          configStr = JSON.stringify(parsed);
        }
      } catch {}
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
  });

  // Delete pipeline
  router.delete('/:id', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
    if (!canModifyPipeline(req, pipeline)) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限删除此流水线' } });
    }
    if (pipeline.status === 'running') {
      return res.status(400).json({ status: 'error', error: { message: '运行中的流水线不能删除，请先取消' } });
    }

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

    const globalRunning = db.prepare("SELECT COUNT(*) AS n FROM pipelines WHERE status = 'running'").get().n;
    if (globalRunning >= 5) {
      return res.status(429).json({ status: 'error', error: { message: '运行中流水线数量已达上限(5)' } });
    }

    const now = new Date().toISOString();
    db.prepare("UPDATE pipelines SET status = 'running', updated_at = ? WHERE pipeline_id = ?").run(now, req.params.id);
    auditLog(db, 'pipeline_start', req.params.id, req.user.role, pipeline.target, { from: pipeline.status, to: 'running' });

    const ws = getWsManager();
    if (ws) ws.broadcast('pipeline:started', { pipeline_id: req.params.id, target: pipeline.target, user: req.user.sub });

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
  router.post('/:id/cancel', (req, res) => {
    const pipeline = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });
    if (!canModifyPipeline(req, pipeline)) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限取消此流水线' } });
    }
    if (pipeline.status !== 'running') {
      return res.status(400).json({ status: 'error', error: { message: '只有运行中的流水线可以取消' } });
    }

    // Import and call cancelPipeline from the engine
    try {
      import('../services/pipelineEngine.js').then(({ cancelPipeline }) => {
        const result = cancelPipeline(req.params.id);
        if (!result.ok) {
          console.error(`[PipelineEngine] Cancel failed for ${req.params.id}: ${result.error}`);
        }
      });
    } catch (err) {
      console.error('[PipelineEngine] Failed to import engine for cancel:', err.message);
    }

    auditLog(db, 'pipeline_cancel', req.params.id, req.user.role, pipeline.target, {});

    const row = db.prepare('SELECT * FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    row.status_cn = statusCn(row.status);
    res.json({ status: 'ok', data: row });
  });

  // ── Pipeline steps sub-routes ──────────────────────────────────────────

  // Get pipeline steps
  router.get('/:id/steps', (req, res) => {
    const pipeline = db.prepare('SELECT pipeline_id FROM pipelines WHERE pipeline_id = ?').get(req.params.id);
    if (!pipeline) return res.status(404).json({ status: 'error', error: { message: '流水线不存在' } });

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
