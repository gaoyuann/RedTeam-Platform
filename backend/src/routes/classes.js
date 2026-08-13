import { Router } from 'express';

export default function (db) {
  const router = Router();

  router.get('/', (_req, res) => {
    const rows = db.prepare('SELECT * FROM classes ORDER BY created_at DESC').all();
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.get('/:classId', (req, res) => {
    const row = db.prepare('SELECT * FROM classes WHERE class_id = ?').get(req.params.classId);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Class not found' } });
    row.members = db.prepare('SELECT * FROM memberships WHERE class_id = ? ORDER BY joined_at').all(req.params.classId);
    res.json({ status: 'ok', data: row });
  });

  router.post('/', (req, res) => {
    const { class_id, name, teacher_sub, join_code } = req.body;
    if (!class_id || !name) return res.status(400).json({ status: 'error', error: { message: 'class_id, name are required' } });
    try {
      db.prepare('INSERT INTO classes (class_id, name, teacher_sub, join_code, created_at) VALUES (?, ?, ?, ?, ?)')
        .run(class_id, name, teacher_sub || null, join_code || null, new Date().toISOString());
      const cls = db.prepare('SELECT * FROM classes WHERE class_id = ?').get(class_id);
      res.status(201).json({ status: 'ok', data: cls });
    } catch (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({ status: 'error', error: { message: 'Class ID already exists' } });
      throw err;
    }
  });

  router.put('/:classId', (req, res) => {
    const { name, teacher_sub, join_code } = req.body;
    const sets = [], params = [];
    if (name !== undefined) { sets.push('name = ?'); params.push(name); }
    if (teacher_sub !== undefined) { sets.push('teacher_sub = ?'); params.push(teacher_sub); }
    if (join_code !== undefined) { sets.push('join_code = ?'); params.push(join_code); }
    if (sets.length === 0) return res.status(400).json({ status: 'error', error: { message: 'No fields to update' } });
    params.push(req.params.classId);
    const result = db.prepare(`UPDATE classes SET ${sets.join(', ')} WHERE class_id = ?`).run(...params);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Class not found' } });
    res.json({ status: 'ok', data: db.prepare('SELECT * FROM classes WHERE class_id = ?').get(req.params.classId) });
  });

  router.delete('/:classId', (req, res) => {
    const result = db.prepare('DELETE FROM classes WHERE class_id = ?').run(req.params.classId);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Class not found' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  return router;
}
