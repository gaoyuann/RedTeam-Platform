import { Router } from 'express';
import { callLlm } from '../services/llmClient.js';
import { llmFailure } from '../services/llmFailure.js';

function maskConfig(row) {
  if (!row || row.category !== 'llm') return row;
  try {
    const value = JSON.parse(row.config_value);
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return { ...row, config_value: JSON.stringify('********') };
    }
    if (value.key) value.key = '********';
    return { ...row, config_value: JSON.stringify(value) };
  } catch {
    return { ...row, config_value: JSON.stringify('********') };
  }
}

export default function (db) {
  const router = Router();

  // Test the same effective configuration used by generation, including env overrides.
  // No scan context, database writes or provider response bodies are returned.
  router.post('/llm/test-connection', async (req, res) => {
    if (req.user?.role !== 'admin') return res.status(403).json({ status: 'error', error: { code: 'FORBIDDEN', message: '只有管理员可以测试模型连接' } });
    try {
      const result = await callLlm([{ role: 'user', content: 'Reply only OK.' }], { maxTokens: 256, timeoutMs: 20_000 });
      const truncated = result.finishReason === 'length';
      const hasOutput = !!result.content?.trim() || result.hasReasoning === true;
      if (!result.ok || !hasOutput) {
        const failure = llmFailure(result.ok ? { error: 'LLM returned empty content' } : result);
        return res.status(400).json({ status: 'error', error: { code: failure.code, message: failure.error } });
      }
      res.json({ status: 'ok', data: {
        truncated,
        message: truncated ? '模型连接成功；测试输出达到长度上限，未验证完整回答'
          : !result.content?.trim() ? '模型连接成功；已返回推理内容，未返回最终回答'
          : '当前生效配置的模型连接测试通过',
      } });
    } catch {
      res.status(500).json({ status: 'error', error: { code: 'LLM_SERVICE_ERROR', message: '模型连接测试失败，请检查服务配置' } });
    }
  });

  router.get('/', (_req, res) => {
    const rows = db.prepare('SELECT * FROM system_config ORDER BY category, config_key').all();
    res.json({ status: 'ok', data: rows.map(maskConfig), meta: { total: rows.length } });
  });

  router.get('/:category', (req, res) => {
    const rows = db.prepare('SELECT * FROM system_config WHERE category = ? ORDER BY config_key').all(req.params.category);
    if (rows.length === 0) return res.status(404).json({ status: 'error', error: { message: 'Category not found' } });
    res.json({ status: 'ok', data: rows.map(maskConfig), meta: { total: rows.length } });
  });

  router.get('/:category/:key', (req, res) => {
    const row = db.prepare('SELECT * FROM system_config WHERE category = ? AND config_key = ?').get(req.params.category, req.params.key);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Config not found' } });
    res.json({ status: 'ok', data: maskConfig(row) });
  });

  router.put('/:category/:key', (req, res) => {
    let { config_value, description } = req.body;
    if (config_value === undefined) return res.status(400).json({ status: 'error', error: { message: 'config_value is required' } });
    const storedCategory = db.prepare('SELECT category FROM system_config WHERE config_key = ?').get(req.params.key);
    if (storedCategory && storedCategory.category !== req.params.category) {
      return res.status(409).json({ status: 'error', error: { message: 'Config key already belongs to another category' } });
    }
    if (req.params.category === 'llm') {
      if (!config_value || typeof config_value !== 'object' || Array.isArray(config_value)) {
        return res.status(400).json({ status: 'error', error: { message: 'LLM config_value must be an object' } });
      }
      const existing = db.prepare('SELECT config_value FROM system_config WHERE category = ? AND config_key = ?')
        .get(req.params.category, req.params.key);
      let oldValue = {};
      try { oldValue = JSON.parse(existing?.config_value || '{}'); } catch {}
      config_value = { ...config_value };
      if (config_value.key === undefined || (typeof config_value.key === 'string' && config_value.key.includes('****'))) {
        config_value.key = oldValue?.key || '';
      }
    }
    db.prepare(`INSERT INTO system_config (config_key, config_value, category, description, updated_at)
      VALUES (?, ?, ?, ?, datetime('now'))
      ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value, description = excluded.description, updated_at = datetime('now')`)
      .run(req.params.key, JSON.stringify(config_value), req.params.category, description || null);
    const row = db.prepare('SELECT * FROM system_config WHERE category = ? AND config_key = ?').get(req.params.category, req.params.key);
    res.json({ status: 'ok', data: maskConfig(row) });
  });

  return router;
}
