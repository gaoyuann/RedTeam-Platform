import { Router } from 'express';

export default function (db) {
  const router = Router();

  router.get('/', (req, res) => {
    const { type, tool_id, run_id, from, to, limit, offset } = req.query;
    let sql = 'SELECT * FROM audit_log WHERE 1=1';
    const params = [];
    if (type) { sql += ' AND type = ?'; params.push(type); }
    if (tool_id) { sql += ' AND tool_id = ?'; params.push(tool_id); }
    if (run_id) { sql += ' AND run_id = ?'; params.push(run_id); }
    if (from) { sql += ' AND timestamp >= ?'; params.push(from); }
    if (to) { sql += ' AND timestamp <= ?'; params.push(to); }
    sql += ' ORDER BY timestamp DESC';
    const lim = Math.min(Number(limit) || 100, 1000);
    sql += ' LIMIT ?';
    params.push(lim);
    if (offset) { sql += ' OFFSET ?'; params.push(Number(offset)); }
    const rows = db.prepare(sql).all(...params);
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.get('/stats', (req, res) => {
    const { from, to } = req.query;
    let where = '1=1';
    const params = [];
    if (from) { where += ' AND timestamp >= ?'; params.push(from); }
    if (to) { where += ' AND timestamp <= ?'; params.push(to); }
    const total = db.prepare(`SELECT COUNT(*) AS n FROM audit_log WHERE ${where}`).get(...params).n;
    const byType = db.prepare(`SELECT type, COUNT(*) AS count FROM audit_log WHERE ${where} GROUP BY type ORDER BY count DESC`).all(...params);
    const byTool = db.prepare(`SELECT tool_id, COUNT(*) AS count FROM audit_log WHERE ${where} GROUP BY tool_id ORDER BY count DESC LIMIT 20`).all(...params);
    res.json({ status: 'ok', data: { total, byType, byTool } });
  });

  return router;
}
