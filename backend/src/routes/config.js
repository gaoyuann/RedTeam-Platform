import { Router } from 'express';

export default function (db) {
  const router = Router();

  router.get('/', (_req, res) => {
    const rows = db.prepare('SELECT * FROM system_config ORDER BY category, config_key').all();
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.get('/:category', (req, res) => {
    const rows = db.prepare('SELECT * FROM system_config WHERE category = ? ORDER BY config_key').all(req.params.category);
    if (rows.length === 0) return res.status(404).json({ status: 'error', error: { message: 'Category not found' } });
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.get('/:category/:key', (req, res) => {
    const row = db.prepare('SELECT * FROM system_config WHERE category = ? AND config_key = ?').get(req.params.category, req.params.key);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Config not found' } });
    res.json({ status: 'ok', data: row });
  });

  router.put('/:category/:key', (req, res) => {
    const { config_value, description } = req.body;
    if (config_value === undefined) return res.status(400).json({ status: 'error', error: { message: 'config_value is required' } });
    const result = db.prepare(`INSERT INTO system_config (config_key, config_value, category, description, updated_at)
      VALUES (?, ?, ?, ?, datetime('now'))
      ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value, description = excluded.description, updated_at = datetime('now')`)
      .run(req.params.key, JSON.stringify(config_value), req.params.category, description || null);
    const row = db.prepare('SELECT * FROM system_config WHERE category = ? AND config_key = ?').get(req.params.category, req.params.key);
    res.json({ status: 'ok', data: row });
  });

  return router;
}
