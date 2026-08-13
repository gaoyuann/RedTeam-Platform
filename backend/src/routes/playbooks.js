import { Router } from 'express';
import { chatGeneratePlaybook } from '../services/playbookAiChat.js';

export default function (db) {
  const router = Router();

  // ── AI Playbook Generation Chat ──────────────────────────────────────
  router.post('/ai/chat', async (req, res) => {
    const { messages, scanResults } = req.body;
    if (!messages || !Array.isArray(messages) || messages.length === 0) {
      return res.status(400).json({ status: 'error', error: { message: 'messages array is required' } });
    }

    try {
      const result = await chatGeneratePlaybook({ messages, scanResults, db });
      if (!result.ok) {
        return res.status(500).json({ status: 'error', error: { message: result.response } });
      }
      res.json({
        status: 'ok',
        data: {
          response: result.response,
          playbook: result.playbook,
        },
      });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  router.get('/', (req, res) => {
    const { baselineGroup, targetType, category, includeGenerated } = req.query;
    let sql = 'SELECT * FROM playbooks WHERE 1=1';
    const params = [];
    if (baselineGroup) { sql += ' AND baseline_group = ?'; params.push(baselineGroup); }
    if (targetType) { sql += ' AND target_type LIKE ?'; params.push(`%"${targetType}"%`); }
    if (category) { sql += ' AND category = ?'; params.push(category); }
    if (!includeGenerated || includeGenerated === 'false') { sql += ' AND is_generated = 0'; }
    sql += ' ORDER BY name';
    const rows = db.prepare(sql).all(...params);
    // Attach step count to each playbook
    const stepCountStmt = db.prepare('SELECT COUNT(*) as cnt FROM playbook_steps WHERE playbook_id = ?');
    for (const row of rows) {
      row.steps_count = stepCountStmt.get(row.playbook_id).cnt;
    }
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  router.get('/:playbookId', (req, res) => {
    const row = db.prepare('SELECT * FROM playbooks WHERE playbook_id = ?').get(req.params.playbookId);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'Playbook not found' } });
    row.steps = db.prepare('SELECT * FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index').all(req.params.playbookId);
    res.json({ status: 'ok', data: row });
  });

  router.post('/', (req, res) => {
    const pb = req.body;
    if (!pb.playbook_id || !pb.name) return res.status(400).json({ status: 'error', error: { message: 'playbook_id, name are required' } });
    try {
      db.prepare(`INSERT INTO playbooks (playbook_id, name, description, author, difficulty, category,
        estimated_time, target_type, not_suitable_for, baseline_group, expected_output_policy,
        teaching_objective, roles_allowed, disable_auto_insert, enable_kg_context,
        requires_teacher_review, mitre_techniques, metadata, is_generated, generated_from, generated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        pb.playbook_id, pb.name, pb.description || null, pb.author || null,
        pb.difficulty || null, pb.category || null, pb.estimated_time || null,
        pb.target_type ? JSON.stringify(pb.target_type) : null,
        pb.not_suitable_for ? JSON.stringify(pb.not_suitable_for) : null,
        pb.baseline_group || null, pb.expected_output_policy || null,
        pb.teaching_objective || null,
        pb.roles_allowed ? JSON.stringify(pb.roles_allowed) : null,
        pb.disable_auto_insert ? 1 : 0, pb.enable_kg_context ? 1 : 0,
        pb.requires_teacher_review ? 1 : 0,
        pb.mitre_techniques ? JSON.stringify(pb.mitre_techniques) : null,
        pb.metadata ? JSON.stringify(pb.metadata) : null,
        pb.is_generated ? 1 : 0, pb.generated_from || null, pb.generated_at || null
      );

      const steps = pb.steps || [];
      const insertStep = db.prepare(`INSERT INTO playbook_steps (playbook_id, step_index, step_id, name, tool_id,
        args_template, description, score, expected_mitre, payload_id, payload_variables,
        evidence_config, requires_teacher_review, optional) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
      for (let i = 0; i < steps.length; i++) {
        const s = steps[i];
        insertStep.run(pb.playbook_id, i, s.step_id || s.id, s.name, s.tool_id,
          s.args_template ? JSON.stringify(s.args_template) : null,
          s.description || null, s.score || 0,
          s.expected_mitre ? JSON.stringify(s.expected_mitre) : null,
          s.payload_id || null, s.payload_variables ? JSON.stringify(s.payload_variables) : null,
          s.evidence_config ? JSON.stringify(s.evidence_config) : null,
          s.requires_teacher_review ? 1 : 0, s.optional ? 1 : 0);
      }

      const result = db.prepare('SELECT * FROM playbooks WHERE playbook_id = ?').get(pb.playbook_id);
      result.steps = db.prepare('SELECT * FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index').all(pb.playbook_id);
      res.status(201).json({ status: 'ok', data: result });
    } catch (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({ status: 'error', error: { message: 'Playbook ID already exists' } });
      throw err;
    }
  });

  router.put('/:playbookId', (req, res) => {
    const pb = req.body;
    const sets = [], params = [];
    for (const field of ['name', 'description', 'author', 'difficulty', 'category', 'baseline_group', 'expected_output_policy', 'teaching_objective']) {
      if (pb[field] !== undefined) { sets.push(`${field} = ?`); params.push(pb[field]); }
    }
    if (pb.estimated_time !== undefined) { sets.push('estimated_time = ?'); params.push(pb.estimated_time); }
    if (sets.length === 0) return res.status(400).json({ status: 'error', error: { message: 'No fields to update' } });
    sets.push("updated_at = datetime('now')");
    params.push(req.params.playbookId);
    const result = db.prepare(`UPDATE playbooks SET ${sets.join(', ')} WHERE playbook_id = ?`).run(...params);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Playbook not found' } });
    const row = db.prepare('SELECT * FROM playbooks WHERE playbook_id = ?').get(req.params.playbookId);
    row.steps = db.prepare('SELECT * FROM playbook_steps WHERE playbook_id = ? ORDER BY step_index').all(req.params.playbookId);
    res.json({ status: 'ok', data: row });
  });

  router.delete('/:playbookId', (req, res) => {
    const result = db.prepare('DELETE FROM playbooks WHERE playbook_id = ?').run(req.params.playbookId);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'Playbook not found' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  return router;
}
