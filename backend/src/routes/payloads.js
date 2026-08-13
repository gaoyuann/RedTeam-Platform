/**
 * payloads.js — 载荷 API 路由
 *
 * 端点：
 *   GET  /               载荷列表（支持 category/type/keyword 过滤）
 *   GET  /categories      分类统计
 *   GET  /:id             载荷详情
 *   POST /generate        AI 载荷生成
 *   PUT  /:id/review      审核 AI 生成载荷
 */

import { Router } from 'express';
import {
  getPayloadById,
  getPayloadList,
  getPayloadCategories,
  extractPayloadData,
  refreshPayloadIndex,
} from '../services/payloadLoader.js';

export default function (db) {
  const router = Router();

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
      res.json({ status: 'ok', data: { ...payload, payload_data: payloadData } });
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
        return res.status(500).json({ status: 'error', error: { message: result.error } });
      }

      // Refresh index so new payload is immediately available
      refreshPayloadIndex();

      res.status(201).json({ status: 'ok', data: result.payload });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── PUT /:id/review — 审核 AI 生成载荷 ────────────────────────────
  router.put('/:id/review', (req, res) => {
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

      // Refresh index if accepted
      if (reviewStatus === 'accepted') {
        refreshPayloadIndex();
      }

      const updated = db.prepare('SELECT * FROM generated_payloads WHERE payload_id = ?').get(req.params.id);
      res.json({ status: 'ok', data: updated });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  return router;
}
