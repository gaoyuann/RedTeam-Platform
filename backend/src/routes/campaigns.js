import { Router } from 'express';
import { randomUUID } from 'crypto';
import { getWsManager } from '../services/wsManager.js';

// ── Security helpers ────────────────────────────────────────────────────

/** Validate target: IP, CIDR, or hostname. Reject protocol prefixes (SSRF). */
function validateTarget(target) {
  if (!target || target.length > 256) return false;
  if (/^(https?|ftp|file|data):/i.test(target)) return false;
  const ipCidr = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  const hostname = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
  return ipCidr.test(target) || hostname.test(target);
}

/** Only creator or admin can modify a campaign. */
function canModifyCampaign(req, campaign) {
  return req.user.role === 'admin' || req.user.sub === campaign.created_by;
}

/** Enforce campaign creation/running limits. */
function checkCampaignLimits(db, username) {
  const userActive = db.prepare(
    "SELECT COUNT(*) AS n FROM campaigns WHERE created_by = ? AND status IN ('draft','running','paused')"
  ).get(username).n;
  if (userActive >= 10) return '活跃战役数量已达上限(10)';

  const globalRunning = db.prepare(
    "SELECT COUNT(*) AS n FROM campaigns WHERE status = 'running'"
  ).get().n;
  if (globalRunning >= 3) return '运行中战役数量已达上限(3)';

  return null;
}

/** Sanitize credential artifacts for API response. */
function sanitizeArtifact(artifact) {
  if (artifact.artifact_type === 'credential') {
    try {
      const val = JSON.parse(artifact.artifact_value);
      if (val.password) val.password = String(val.password).slice(0, 4) + '****';
      if (val.hash) val.hash = String(val.hash).slice(0, 8) + '****';
      artifact.artifact_value = JSON.stringify(val);
      artifact._sanitized = true;
    } catch { /* non-JSON value, leave as-is */ }
  }
  return artifact;
}

/** Write audit log entry. */
function auditLog(db, type, campaignId, userRole, target, reasons) {
  try {
    db.prepare(`INSERT INTO audit_log (type, execution_id, user_role, target, timestamp, reasons)
      VALUES (?, ?, ?, ?, datetime('now'), ?)`).run(type, campaignId, userRole, target, JSON.stringify(reasons));
  } catch { /* audit failure should not break business logic */ }
}

// ── Phase type metadata ─────────────────────────────────────────────────
const PHASE_TYPES = [
  { type: 'data-exfiltration',  name: '数据抵近窃取', order: 0 },
  { type: 'tampering-deception', name: '信息篡改欺骗', order: 1 },
  { type: 'device-control',     name: '关键设备夺控', order: 2 },
];

const VALID_PHASE_TYPES = new Set(PHASE_TYPES.map(p => p.type));
const VALID_EXECUTION_MODES = new Set(['sequential', 'parallel', 'conditional']);
const VALID_ARTIFACT_TYPES = new Set(['credential', 'ip_list', 'file_hash', 'access_token', 'custom']);

// ── Status translation ──────────────────────────────────────────────────
function statusCn(s) {
  const map = { draft:'草稿', running:'运行中', paused:'已暂停', completed:'已完成', failed:'失败', aborted:'已终止',
    pending:'待执行', skipped:'已跳过' };
  return map[s] || s;
}

// ── Route factory ───────────────────────────────────────────────────────
export default function (db) {
  const router = Router();

  // ── Campaign CRUD ──────────────────────────────────────────────────────

  // List campaigns
  router.get('/', (req, res) => {
    const { status } = req.query;
    let sql = 'SELECT * FROM campaigns WHERE 1=1';
    const params = [];
    if (status) { sql += ' AND status = ?'; params.push(status); }
    // Non-admin sees only their own
    if (req.user.role !== 'admin') { sql += ' AND created_by = ?'; params.push(req.user.sub); }
    sql += ' ORDER BY created_at DESC';
    const rows = db.prepare(sql).all(...params);
    // Add status_cn for display
    for (const row of rows) { row.status_cn = statusCn(row.status); }
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  // Get campaign detail (with phases, playbooks, artifacts)
  router.get('/:id', (req, res) => {
    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });
    // Access check
    if (req.user.role !== 'admin' && campaign.created_by !== req.user.sub) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限查看此战役' } });
    }
    campaign.status_cn = statusCn(campaign.status);

    // Phases
    campaign.phases = db.prepare(
      'SELECT * FROM campaign_phases WHERE campaign_id = ? ORDER BY order_index'
    ).all(campaign.campaign_id);
    for (const phase of campaign.phases) {
      phase.status_cn = statusCn(phase.status);
      // Playbooks in this phase
      phase.playbooks = db.prepare(
        `SELECT cp.*, p.name as playbook_name, p.difficulty, p.baseline_group
         FROM campaign_playbooks cp
         JOIN playbooks p ON p.playbook_id = cp.playbook_id
         WHERE cp.phase_id = ? ORDER BY cp.execution_order`
      ).all(phase.phase_id);
      for (const pb of phase.playbooks) { pb.status_cn = statusCn(pb.status); }
    }

    // Artifacts
    campaign.artifacts = db.prepare(
      'SELECT * FROM campaign_artifacts WHERE campaign_id = ? ORDER BY created_at'
    ).all(campaign.campaign_id);
    for (const a of campaign.artifacts) { sanitizeArtifact(a); }

    res.json({ status: 'ok', data: campaign });
  });

  // Create campaign
  router.post('/', (req, res) => {
    const { name, description, target, phases: phaseConfig, auto_advance: autoAdvance = true } = req.body;
    if (!name || name.length > 200) {
      return res.status(400).json({ status: 'error', error: { message: '名称不能为空且不超过200字' } });
    }
    if (!target) {
      return res.status(400).json({ status: 'error', error: { message: '目标地址不能为空' } });
    }
    if (!validateTarget(target)) {
      return res.status(400).json({ status: 'error', error: { message: '目标地址格式无效（仅支持IP/CIDR/主机名）' } });
    }
    // 至少启用一个阶段
    if (phaseConfig) {
      const enabledCount = PHASE_TYPES.filter(pt => phaseConfig[pt.type] !== false).length;
      if (enabledCount === 0) {
        return res.status(400).json({ status: 'error', error: { message: '至少需要启用一个阶段' } });
      }
    }
    const limitErr = checkCampaignLimits(db, req.user.sub);
    if (limitErr) {
      return res.status(429).json({ status: 'error', error: { message: limitErr } });
    }

    const campaignId = `camp_${randomUUID().slice(0, 12)}`;
    const now = new Date().toISOString();

    try {
      db.prepare(`INSERT INTO campaigns (campaign_id, name, description, target, status, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'draft', ?, ?, ?)`).run(campaignId, name, description || null, target || null, req.user.sub, now, now);

      // Create 3 phases
      const insertPhase = db.prepare(`INSERT INTO campaign_phases (phase_id, campaign_id, phase_type, display_name, order_index, status, config, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`);
      for (const pt of PHASE_TYPES) {
        const phaseId = `phase_${randomUUID().slice(0, 12)}`;
        const enabled = phaseConfig ? phaseConfig[pt.type] !== false : true;
        const configJson = JSON.stringify({ auto_advance: autoAdvance !== false, enabled });
        insertPhase.run(phaseId, campaignId, pt.type, pt.name, pt.order, configJson, now);
      }

      auditLog(db, 'campaign_create', campaignId, req.user.role, target, { name });

      const row = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(campaignId);
      row.status_cn = statusCn(row.status);
      res.status(201).json({ status: 'ok', data: row });
    } catch (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({ status: 'error', error: { message: '战役ID冲突，请重试' } });
      throw err;
    }
  });

  // Update campaign
  router.put('/:id', (req, res) => {
    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });
    if (!canModifyCampaign(req, campaign)) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限修改此战役' } });
    }

    const { name, description, target } = req.body;
    const sets = [], params = [];
    if (name !== undefined) {
      if (name.length > 200) return res.status(400).json({ status: 'error', error: { message: '名称不超过200字' } });
      sets.push('name = ?'); params.push(name);
    }
    if (description !== undefined) { sets.push('description = ?'); params.push(description); }
    if (target !== undefined) {
      if (target && !validateTarget(target)) return res.status(400).json({ status: 'error', error: { message: '目标地址格式无效' } });
      sets.push('target = ?'); params.push(target);
    }
    if (sets.length === 0) return res.status(400).json({ status: 'error', error: { message: '无更新内容' } });
    sets.push("updated_at = datetime('now')");
    params.push(req.params.id);

    db.prepare(`UPDATE campaigns SET ${sets.join(', ')} WHERE campaign_id = ?`).run(...params);
    auditLog(db, 'campaign_update', req.params.id, req.user.role, campaign.target, { fields: sets });

    const row = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    row.status_cn = statusCn(row.status);
    res.json({ status: 'ok', data: row });
  });

  // Delete campaign
  router.delete('/:id', (req, res) => {
    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });
    if (!canModifyCampaign(req, campaign)) {
      return res.status(403).json({ status: 'error', error: { message: '没有权限删除此战役' } });
    }
    if (campaign.status === 'running') {
      return res.status(400).json({ status: 'error', error: { message: '运行中的战役不能删除，请先终止' } });
    }

    db.prepare('DELETE FROM campaigns WHERE campaign_id = ?').run(req.params.id);
    auditLog(db, 'campaign_delete', req.params.id, req.user.role, campaign.target, {});
    res.json({ status: 'ok', data: { deleted: true } });
  });

  // ── Phase management ───────────────────────────────────────────────────

  // Get phases
  router.get('/:id/phases', (req, res) => {
    const phases = db.prepare(
      'SELECT * FROM campaign_phases WHERE campaign_id = ? ORDER BY order_index'
    ).all(req.params.id);
    for (const p of phases) { p.status_cn = statusCn(p.status); }
    res.json({ status: 'ok', data: phases });
  });

  // Update phase
  router.put('/:id/phases/:phaseId', (req, res) => {
    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });
    if (!canModifyCampaign(req, campaign)) return res.status(403).json({ status: 'error', error: { message: '没有权限' } });

    const { display_name, config } = req.body;
    const sets = [], params = [];
    if (display_name !== undefined) { sets.push('display_name = ?'); params.push(display_name); }
    if (config !== undefined) { sets.push('config = ?'); params.push(JSON.stringify(config)); }
    if (sets.length === 0) return res.status(400).json({ status: 'error', error: { message: '无更新内容' } });
    params.push(req.params.phaseId);

    db.prepare(`UPDATE campaign_phases SET ${sets.join(', ')} WHERE phase_id = ?`).run(...params);
    const row = db.prepare('SELECT * FROM campaign_phases WHERE phase_id = ?').get(req.params.phaseId);
    row.status_cn = statusCn(row.status);
    res.json({ status: 'ok', data: row });
  });

  // Skip phase
  router.put('/:id/phases/:phaseId/skip', (req, res) => {
    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });
    if (!canModifyCampaign(req, campaign)) return res.status(403).json({ status: 'error', error: { message: '没有权限' } });

    const phase = db.prepare('SELECT * FROM campaign_phases WHERE phase_id = ?').get(req.params.phaseId);
    if (!phase) return res.status(404).json({ status: 'error', error: { message: '阶段不存在' } });
    if (phase.status === 'running') return res.status(400).json({ status: 'error', error: { message: '运行中的阶段不能跳过' } });

    const now = new Date().toISOString();
    db.prepare("UPDATE campaign_phases SET status = 'skipped', completed_at = ? WHERE phase_id = ?").run(now, req.params.phaseId);
    auditLog(db, 'campaign_phase_skip', req.params.id, req.user.role, campaign.target, { phase_id: req.params.phaseId });

    // Broadcast
    const ws = getWsManager();
    if (ws) ws.broadcast('phase:skipped', { campaign_id: req.params.id, phase_id: req.params.phaseId });

    const row = db.prepare('SELECT * FROM campaign_phases WHERE phase_id = ?').get(req.params.phaseId);
    row.status_cn = statusCn(row.status);
    res.json({ status: 'ok', data: row });
  });

  // ── Playbook orchestration ─────────────────────────────────────────────

  // Add playbook to phase
  router.post('/:id/phases/:phaseId/playbooks', (req, res) => {
    const { playbook_id, execution_order, execution_mode, target_override } = req.body;
    if (!playbook_id) return res.status(400).json({ status: 'error', error: { message: 'playbook_id 必填' } });

    // Verify playbook exists
    const pb = db.prepare('SELECT playbook_id, name FROM playbooks WHERE playbook_id = ?').get(playbook_id);
    if (!pb) return res.status(400).json({ status: 'error', error: { message: 'Playbook不存在' } });

    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });
    if (!canModifyCampaign(req, campaign)) return res.status(403).json({ status: 'error', error: { message: '没有权限' } });

    const mode = execution_mode || 'sequential';
    if (!VALID_EXECUTION_MODES.has(mode)) return res.status(400).json({ status: 'error', error: { message: '无效的执行模式' } });

    // Determine execution_order: append to end if not specified
    let order = execution_order;
    if (order === undefined || order === null) {
      const maxOrder = db.prepare(
        'SELECT MAX(execution_order) AS m FROM campaign_playbooks WHERE phase_id = ?'
      ).get(req.params.phaseId);
      order = (maxOrder.m ?? -1) + 1;
    }

    const now = new Date().toISOString();
    try {
      db.prepare(`INSERT INTO campaign_playbooks (campaign_id, phase_id, playbook_id, execution_order, execution_mode, status, target_override, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)`).run(
          req.params.id, req.params.phaseId, playbook_id, order, mode, target_override || null, now);

      auditLog(db, 'campaign_playbook_add', req.params.id, req.user.role, campaign.target, { phase_id: req.params.phaseId, playbook_id });

      const cpRow = db.prepare(
        'SELECT * FROM campaign_playbooks WHERE campaign_id = ? AND phase_id = ? AND playbook_id = ? ORDER BY id DESC LIMIT 1'
      ).get(req.params.id, req.params.phaseId, playbook_id);
      cpRow.status_cn = statusCn(cpRow.status);
      cpRow.playbook_name = pb.name;
      res.status(201).json({ status: 'ok', data: cpRow });
    } catch (err) {
      if (err.message.includes('FOREIGN KEY')) return res.status(400).json({ status: 'error', error: { message: '阶段或Playbook不存在' } });
      throw err;
    }
  });

  // Remove playbook from phase
  router.delete('/:id/phases/:phaseId/playbooks/:cpId', (req, res) => {
    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });
    if (!canModifyCampaign(req, campaign)) return res.status(403).json({ status: 'error', error: { message: '没有权限' } });

    const result = db.prepare('DELETE FROM campaign_playbooks WHERE id = ?').run(Number(req.params.cpId));
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: '编排记录不存在' } });

    auditLog(db, 'campaign_playbook_remove', req.params.id, req.user.role, campaign.target, { cp_id: req.params.cpId });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  // Reorder playbooks in phase
  router.put('/:id/phases/:phaseId/playbooks/reorder', (req, res) => {
    const { order } = req.body; // [{ id: 1, execution_order: 0 }, ...]
    if (!Array.isArray(order)) return res.status(400).json({ status: 'error', error: { message: 'order 必须是数组' } });

    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });
    if (!canModifyCampaign(req, campaign)) return res.status(403).json({ status: 'error', error: { message: '没有权限' } });

    const updateOrder = db.prepare('UPDATE campaign_playbooks SET execution_order = ? WHERE id = ?');
    for (const item of order) {
      updateOrder.run(item.execution_order, item.id);
    }
    res.json({ status: 'ok', data: { reordered: order.length } });
  });

  // ── Campaign execution ─────────────────────────────────────────────────

  // Start campaign
  router.post('/:id/start', async (req, res) => {
    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });
    if (!canModifyCampaign(req, campaign)) return res.status(403).json({ status: 'error', error: { message: '没有权限' } });
    if (campaign.status !== 'draft' && campaign.status !== 'paused') {
      return res.status(400).json({ status: 'error', error: { message: `不能从"${statusCn(campaign.status)}"状态启动` } });
    }
    if (!campaign.target) {
      return res.status(400).json({ status: 'error', error: { message: '战役未设置目标地址，无法启动' } });
    }
    // 检查是否有至少一个 Playbook
    const hasPlaybooks = db.prepare(`
      SELECT COUNT(*) AS n FROM campaign_playbooks cp
      JOIN campaign_phases cph ON cph.phase_id = cp.phase_id
      WHERE cph.campaign_id = ? AND cph.status != 'skipped'
    `).get(req.params.id).n;
    if (hasPlaybooks === 0) {
      return res.status(400).json({ status: 'error', error: { message: '战役没有任何Playbook，无法启动' } });
    }

    const globalRunning = db.prepare("SELECT COUNT(*) AS n FROM campaigns WHERE status = 'running'").get().n;
    if (globalRunning >= 3) return res.status(429).json({ status: 'error', error: { message: '运行中战役数量已达上限(3)' } });

    const now = new Date().toISOString();
    db.prepare("UPDATE campaigns SET status = 'running', updated_at = ? WHERE campaign_id = ?").run(now, req.params.id);
    auditLog(db, 'campaign_start', req.params.id, req.user.role, campaign.target, { from: campaign.status, to: 'running' });

    const ws = getWsManager();
    if (ws) ws.broadcast('campaign:started', { campaign_id: req.params.id });

    // Fire-and-forget: start campaign execution engine
    try {
      const { startCampaign } = await import('../services/campaignEngine.js');
      startCampaign(db, req.params.id, req.user.sub).catch(err => {
        console.error(`[CampaignEngine] Error for ${req.params.id}:`, err.message);
      });
    } catch (err) {
      console.error('[CampaignEngine] Failed to import engine:', err.message);
    }

    const row = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    row.status_cn = statusCn(row.status);
    res.status(202).json({ status: 'ok', data: row });
  });

  // Pause campaign
  router.post('/:id/pause', (req, res) => {
    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });
    if (!canModifyCampaign(req, campaign)) return res.status(403).json({ status: 'error', error: { message: '没有权限' } });
    if (campaign.status !== 'running') return res.status(400).json({ status: 'error', error: { message: '只有运行中的战役可以暂停' } });

    const now = new Date().toISOString();
    db.prepare("UPDATE campaigns SET status = 'paused', updated_at = ? WHERE campaign_id = ?").run(now, req.params.id);
    auditLog(db, 'campaign_pause', req.params.id, req.user.role, campaign.target, {});

    const ws = getWsManager();
    if (ws) ws.broadcast('campaign:paused', { campaign_id: req.params.id });

    const row = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    row.status_cn = statusCn(row.status);
    res.json({ status: 'ok', data: row });
  });

  // Abort campaign
  router.post('/:id/abort', (req, res) => {
    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });
    if (!canModifyCampaign(req, campaign)) return res.status(403).json({ status: 'error', error: { message: '没有权限' } });
    if (campaign.status !== 'running' && campaign.status !== 'paused') {
      return res.status(400).json({ status: 'error', error: { message: '只有运行中或已暂停的战役可以终止' } });
    }

    const now = new Date().toISOString();
    db.prepare("UPDATE campaigns SET status = 'aborted', updated_at = ? WHERE campaign_id = ?").run(now, req.params.id);
    // Also abort any running phases
    db.prepare("UPDATE campaign_phases SET status = 'failed', completed_at = ? WHERE campaign_id = ? AND status = 'running'").run(now, req.params.id);
    auditLog(db, 'campaign_abort', req.params.id, req.user.role, campaign.target, {});

    const ws = getWsManager();
    if (ws) ws.broadcast('campaign:aborted', { campaign_id: req.params.id });

    const row = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    row.status_cn = statusCn(row.status);
    res.json({ status: 'ok', data: row });
  });

  // ── Artifacts ──────────────────────────────────────────────────────────

  // List artifacts
  router.get('/:id/artifacts', (req, res) => {
    const { phase_id, type } = req.query;
    let sql = 'SELECT * FROM campaign_artifacts WHERE campaign_id = ?';
    const params = [req.params.id];
    if (phase_id) { sql += ' AND phase_id = ?'; params.push(phase_id); }
    if (type) { sql += ' AND artifact_type = ?'; params.push(type); }
    sql += ' ORDER BY created_at';

    const rows = db.prepare(sql).all(...params);
    for (const a of rows) { sanitizeArtifact(a); }
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  // Add artifact manually
  router.post('/:id/artifacts', (req, res) => {
    const { phase_id, artifact_type, artifact_key, artifact_value, source_run_id } = req.body;
    if (!phase_id || !artifact_type || !artifact_key || !artifact_value) {
      return res.status(400).json({ status: 'error', error: { message: 'phase_id, artifact_type, artifact_key, artifact_value 必填' } });
    }
    if (!VALID_ARTIFACT_TYPES.has(artifact_type)) {
      return res.status(400).json({ status: 'error', error: { message: '无效的产物类型' } });
    }
    // Validate JSON and size
    try {
      const parsed = JSON.parse(artifact_value);
      const serialized = JSON.stringify(parsed);
      if (serialized.length > 65536) return res.status(400).json({ status: 'error', error: { message: '产物值不能超过64KB' } });
    } catch {
      return res.status(400).json({ status: 'error', error: { message: 'artifact_value 必须是有效JSON' } });
    }

    // Check artifact count limit (500 per campaign)
    const count = db.prepare('SELECT COUNT(*) AS n FROM campaign_artifacts WHERE campaign_id = ?').get(req.params.id).n;
    if (count >= 500) return res.status(429).json({ status: 'error', error: { message: '产物数量已达上限(500)' } });

    const now = new Date().toISOString();
    db.prepare(`INSERT INTO campaign_artifacts (campaign_id, phase_id, artifact_type, artifact_key, artifact_value, source_run_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(req.params.id, phase_id, artifact_type, artifact_key, artifact_value, source_run_id || null, now);

    const row = db.prepare('SELECT * FROM campaign_artifacts WHERE campaign_id = ? ORDER BY id DESC LIMIT 1').get(req.params.id);
    sanitizeArtifact(row);
    res.status(201).json({ status: 'ok', data: row });
  });

  // Delete artifact
  router.delete('/:id/artifacts/:artifactId', (req, res) => {
    const result = db.prepare('DELETE FROM campaign_artifacts WHERE id = ? AND campaign_id = ?').run(Number(req.params.artifactId), req.params.id);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: '产物不存在' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  // ── Campaign report ────────────────────────────────────────────────────

  router.get('/:id/report', (req, res) => {
    const campaign = db.prepare('SELECT * FROM campaigns WHERE campaign_id = ?').get(req.params.id);
    if (!campaign) return res.status(404).json({ status: 'error', error: { message: '战役不存在' } });

    const phases = db.prepare('SELECT * FROM campaign_phases WHERE campaign_id = ? ORDER BY order_index').all(req.params.id);
    const artifacts = db.prepare('SELECT * FROM campaign_artifacts WHERE campaign_id = ? ORDER BY created_at').all(req.params.id);

    const report = {
      campaign_id: campaign.campaign_id,
      name: campaign.name,
      target: campaign.target,
      status: campaign.status,
      created_at: campaign.created_at,
      phases: phases.map(p => ({
        phase_type: p.phase_type,
        display_name: p.display_name,
        status: p.status,
        summary: p.summary ? JSON.parse(p.summary) : null,
      })),
      artifact_summary: {
        total: artifacts.length,
        by_type: artifacts.reduce((acc, a) => { acc[a.artifact_type] = (acc[a.artifact_type] || 0) + 1; return acc; }, {}),
      },
    };

    res.json({ status: 'ok', data: report });
  });

  return router;
}
