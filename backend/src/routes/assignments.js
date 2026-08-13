import { Router } from 'express';

export default function (db) {
  const router = Router();

  router.get('/', (req, res) => {
    const { class_id } = req.query;
    let rows;
    if (class_id) {
      rows = db.prepare('SELECT * FROM assignments WHERE class_id = ? ORDER BY created_at DESC').all(class_id);
    } else {
      rows = db.prepare('SELECT * FROM assignments ORDER BY created_at DESC').all();
    }
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.get('/:assignmentId', (req, res) => {
    const row = db.prepare('SELECT * FROM assignments WHERE assignment_id = ?').get(req.params.assignmentId);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Assignment not found' } });
    res.json({ status: 'ok', data: row });
  });

  router.post('/', (req, res) => {
    const { assignment_id, class_id, title, playbook_id, due_at, rubric, created_by } = req.body;
    if (!assignment_id || !class_id || !title) return res.status(400).json({ status: 'error', error: { message: 'assignment_id, class_id, title are required' } });
    try {
      db.prepare('INSERT INTO assignments (assignment_id, class_id, title, playbook_id, due_at, rubric, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(assignment_id, class_id, title, playbook_id || null, due_at || null, rubric ? JSON.stringify(rubric) : null, created_by || null, new Date().toISOString());
      const row = db.prepare('SELECT * FROM assignments WHERE assignment_id = ?').get(assignment_id);
      res.status(201).json({ status: 'ok', data: row });
    } catch (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({ status: 'error', error: { message: 'Assignment ID already exists' } });
      throw err;
    }
  });

  router.put('/:assignmentId', (req, res) => {
    const { title, playbook_id, due_at, rubric } = req.body;
    const sets = [], params = [];
    if (title !== undefined) { sets.push('title = ?'); params.push(title); }
    if (playbook_id !== undefined) { sets.push('playbook_id = ?'); params.push(playbook_id); }
    if (due_at !== undefined) { sets.push('due_at = ?'); params.push(due_at); }
    if (rubric !== undefined) { sets.push('rubric = ?'); params.push(JSON.stringify(rubric)); }
    if (sets.length === 0) return res.status(400).json({ status: 'error', error: { message: 'No fields to update' } });
    params.push(req.params.assignmentId);
    const result = db.prepare(`UPDATE assignments SET ${sets.join(', ')} WHERE assignment_id = ?`).run(...params);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Assignment not found' } });
    res.json({ status: 'ok', data: db.prepare('SELECT * FROM assignments WHERE assignment_id = ?').get(req.params.assignmentId) });
  });

  router.delete('/:assignmentId', (req, res) => {
    const result = db.prepare('DELETE FROM assignments WHERE assignment_id = ?').run(req.params.assignmentId);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Assignment not found' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  return router;
}
