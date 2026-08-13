import { Router } from 'express';

export default function (db) {
  const router = Router();

  router.get('/', (req, res) => {
    const { assignment_id, student_sub } = req.query;
    let rows;
    if (assignment_id) {
      rows = db.prepare('SELECT * FROM submissions WHERE assignment_id = ? ORDER BY submitted_at DESC').all(assignment_id);
    } else if (student_sub) {
      rows = db.prepare('SELECT * FROM submissions WHERE student_sub = ? ORDER BY submitted_at DESC').all(student_sub);
    } else {
      rows = db.prepare('SELECT * FROM submissions ORDER BY submitted_at DESC').all();
    }
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.get('/:submissionId', (req, res) => {
    const row = db.prepare('SELECT * FROM submissions WHERE submission_id = ?').get(req.params.submissionId);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Submission not found' } });
    res.json({ status: 'ok', data: row });
  });

  router.post('/', (req, res) => {
    const { submission_id, assignment_id, class_id, student_sub, run_id } = req.body;
    if (!submission_id || !assignment_id || !student_sub) return res.status(400).json({ status: 'error', error: { message: 'submission_id, assignment_id, student_sub are required' } });
    try {
      db.prepare('INSERT INTO submissions (submission_id, assignment_id, class_id, student_sub, run_id, submitted_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run(submission_id, assignment_id, class_id || null, student_sub, run_id || null, new Date().toISOString());
      const row = db.prepare('SELECT * FROM submissions WHERE submission_id = ?').get(submission_id);
      res.status(201).json({ status: 'ok', data: row });
    } catch (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({ status: 'error', error: { message: 'Submission ID already exists' } });
      throw err;
    }
  });

  router.put('/:submissionId', (req, res) => {
    const { override_grade, feedback } = req.body;
    const sets = [], params = [];
    if (override_grade !== undefined) { sets.push('override_grade = ?'); params.push(JSON.stringify(override_grade)); }
    if (feedback !== undefined) { sets.push('feedback = ?'); params.push(feedback); }
    sets.push("reviewed_at = datetime('now')");
    if (sets.length === 0) return res.status(400).json({ status: 'error', error: { message: 'No fields to update' } });
    params.push(req.params.submissionId);
    const result = db.prepare(`UPDATE submissions SET ${sets.join(', ')} WHERE submission_id = ?`).run(...params);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Submission not found' } });
    res.json({ status: 'ok', data: db.prepare('SELECT * FROM submissions WHERE submission_id = ?').get(req.params.submissionId) });
  });

  router.delete('/:submissionId', (req, res) => {
    const result = db.prepare('DELETE FROM submissions WHERE submission_id = ?').run(req.params.submissionId);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Submission not found' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  return router;
}
