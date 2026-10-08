import { Router } from 'express';

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
