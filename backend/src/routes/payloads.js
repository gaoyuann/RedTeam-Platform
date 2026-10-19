import { resolveFindingPayload } from '../services/findingPayloadResolver.js';
/**
 * payloads.js — 载荷 API 路由
 *
 * 端点：
 *   GET  /               载荷列表（支持 category/type/keyword 过滤）
 *   GET  /categories      分类统计
 *   GET  /:id             载荷详情
 *   POST /generate        AI 载荷生成
 *   POST /resolve         按漏洞匹配或生成可消费载荷
 *   PUT  /:id/review      兼容旧候选记录的管理员审核
 */

import { Router } from 'express';
import { requireRole } from '../middleware/auth.js';
import {
  getPayloadById,
  getPayloadList,
  getPayloadCategories,
  extractPayloadData,
  refreshPayloadIndex,
} from '../services/payloadLoader.js';

export default function (db) {
  const router = Router();
  const verificationHistory = (payloadId, actor) => db.prepare(`
    SELECT e.id AS evidence_id, e.run_id, e.recorded_at,
      json_extract(e.evidence_data, '$.success') AS tool_success
    FROM evidence_records e JOIN execution_runs r ON r.run_id = e.run_id
    WHERE json_valid(e.evidence_data)
      AND json_extract(e.evidence_data, '$.payload_id') = ?
      AND (? = 'admin' OR r.user_sub = ?)
    ORDER BY e.id DESC LIMIT 10
  `).all(payloadId, actor.role, actor.sub);
  router.post('/resolve',async(req,res)=>{
    try {
      const data=await resolveFindingPayload(db,Number(req.body?.finding_id),req.user);
      res.json({status:'ok',data:{...data,payload:{...data.payload,payload_data:extractPayloadData(data.payload),verification_history:verificationHistory(data.payload.id,req.user)}}});
    } catch(error){res.status(error.status || 500).json({status:'error',error:{message:error.message}});}
  });

  // ── GET / — 载荷列表 ────────────────────────────────────────────────
  router.get('/', (req, res) => {
    try {
      const { category, type, keyword } = req.query;
      const list = getPayloadList({ category, type, keyword, db });
      res.json({ status: 'ok', data: list, meta: { total: list.length } });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── GET /categories — 分类统计 ──────────────────────────────────────
  router.get('/categories', (_req, res) => {
    try {
      const categories = getPayloadCategories(db);
      res.json({ status: 'ok', data: categories });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── GET /:id — 载荷详情 ────────────────────────────────────────────
  router.get('/:id', (req, res) => {
    try {
      const payload = getPayloadById(req.params.id, db);
      if (!payload) {
        return res.status(404).json({ status: 'error', error: { message: `Payload '${req.params.id}' not found` } });
      }
      const payloadData = extractPayloadData(payload);
      res.json({ status: 'ok', data: { ...payload, payload_data: payloadData,
        verification_history: verificationHistory(payload.id, req.user) } });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── POST /generate — AI 载荷生成 ───────────────────────────────────
  router.post('/generate', async (req, res) => {
    try {
      const { category, target_type, technique_id, constraints } = req.body;
      if (!category) {
        return res.status(400).json({ status: 'error', error: { message: 'category is required' } });
      }

      // Dynamic import to avoid circular dependency at startup
      const { generatePayload } = await import('../services/payloadGenerator.js');
      const result = await generatePayload({
        category,
        target_type: target_type || 'web',
        technique_id: technique_id || null,
        constraints: constraints || {},
        createdBy: req.user?.sub || 'system',
        db,
      });

      if (!result.ok) {
        return res.status(result.status || 422).json({ status: 'error', error: { message: result.error } });
      }

      // Refresh index so new payload is immediately available
      refreshPayloadIndex();

      res.status(201).json({ status: 'ok', data: result.payload });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── PUT /:id/review — 审核 AI 生成载荷 ────────────────────────────
  router.put('/:id/review', requireRole('admin'), (req, res) => {
    try {
      const { status: reviewStatus } = req.body;
      if (!['accepted', 'rejected'].includes(reviewStatus)) {
        return res.status(400).json({ status: 'error', error: { message: 'status must be "accepted" or "rejected"' } });
      }

      const row = db.prepare('SELECT * FROM generated_payloads WHERE payload_id = ?').get(req.params.id);
      if (!row) {
        return res.status(404).json({ status: 'error', error: { message: 'AI-generated payload not found' } });
      }

      const now = new Date().toISOString();
      db.prepare(
        `UPDATE generated_payloads SET import_status = ?, reviewed_by = ?, reviewed_at = ? WHERE payload_id = ?`
      ).run(reviewStatus, req.user?.sub || 'system', now, req.params.id);

      refreshPayloadIndex();

      const updated = db.prepare('SELECT * FROM generated_payloads WHERE payload_id = ?').get(req.params.id);
      res.json({ status: 'ok', data: updated });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  return router;
}
