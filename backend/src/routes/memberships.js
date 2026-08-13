import { Router } from 'express';

export default function (db) {
  const router = Router();

  router.post('/', (req, res) => {
    const { class_id, user_sub, role } = req.body;
    if (!class_id || !user_sub || !role) return res.status(400).json({ status: 'error', error: { message: 'class_id, user_sub, role are required' } });
    try {
      db.prepare('INSERT INTO memberships (class_id, user_sub, role, joined_at) VALUES (?, ?, ?, ?)')
        .run(class_id, user_sub, role, new Date().toISOString());
      res.status(201).json({ status: 'ok', data: { class_id, user_sub, role } });
    } catch (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({ status: 'error', error: { message: 'Membership already exists' } });
      throw err;
    }
  });

  router.delete('/', (req, res) => {
    const { class_id, user_sub } = req.body;
    if (!class_id || !user_sub) return res.status(400).json({ status: 'error', error: { message: 'class_id, user_sub are required' } });
    const result = db.prepare('DELETE FROM memberships WHERE class_id = ? AND user_sub = ?').run(class_id, user_sub);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Membership not found' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  return router;
}
