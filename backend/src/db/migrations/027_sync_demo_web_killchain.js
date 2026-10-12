import { readFileSync } from 'fs';

const KNOWN_COLUMNS = new Set([
  'id', 'name', 'description', 'author', 'difficulty', 'category',
  'estimatedMinutes', 'estimatedTimeMinutes', 'targetType', 'notSuitableFor',
  'baselineGroup', 'expectedOutputPolicy', 'teachingObjective',
  'rolesAllowed', 'disableAutoInsert', 'enableKGContext',
  'requiresTeacherReview', 'mitreTechniques', 'steps',
]);

function definition(name) {
  return JSON.parse(readFileSync(new URL(`../../../../data/playbooks/${name}.json`, import.meta.url), 'utf8'));
}

function extractPlaybookRow(playbook) {
  const metadata = {};
  for (const [key, value] of Object.entries(playbook)) {
    if (!KNOWN_COLUMNS.has(key) && key !== 'steps') metadata[key] = value;
  }
  return {
    playbook_id: playbook.id,
    name: playbook.name,
    description: playbook.description || null,
    author: playbook.author || null,
    difficulty: playbook.difficulty || null,
    category: playbook.category || null,
    estimated_time: playbook.estimatedTimeMinutes || playbook.estimatedMinutes || null,
    target_type: playbook.targetType ? JSON.stringify(playbook.targetType) : null,
    not_suitable_for: playbook.notSuitableFor ? JSON.stringify(playbook.notSuitableFor) : null,
    baseline_group: playbook.baselineGroup || null,
    expected_output_policy: playbook.expectedOutputPolicy || null,
    teaching_objective: playbook.teachingObjective || null,
    roles_allowed: playbook.rolesAllowed ? JSON.stringify(playbook.rolesAllowed) : null,
    disable_auto_insert: playbook.disableAutoInsert ? 1 : 0,
    enable_kg_context: playbook.enableKGContext ? 1 : 0,
    requires_teacher_review: playbook.requiresTeacherReview ? 1 : 0,
    mitre_techniques: playbook.mitreTechniques ? JSON.stringify(playbook.mitreTechniques) : null,
    metadata: Object.keys(metadata).length ? JSON.stringify(metadata) : null,
  };
}

function syncPlaybook(db, playbook) {
  const row = extractPlaybookRow(playbook);
  const update = db.prepare(`UPDATE playbooks SET
    name = ?, description = ?, author = ?, difficulty = ?, category = ?,
    estimated_time = ?, target_type = ?, not_suitable_for = ?, baseline_group = ?,
    expected_output_policy = ?, teaching_objective = ?, roles_allowed = ?,
    disable_auto_insert = ?, enable_kg_context = ?, requires_teacher_review = ?,
    mitre_techniques = ?, metadata = ?, updated_at = datetime('now')
    WHERE playbook_id = ?`);
  const values = [
    row.name, row.description, row.author, row.difficulty, row.category,
    row.estimated_time, row.target_type, row.not_suitable_for, row.baseline_group,
    row.expected_output_policy, row.teaching_objective, row.roles_allowed,
    row.disable_auto_insert, row.enable_kg_context, row.requires_teacher_review,
    row.mitre_techniques, row.metadata, row.playbook_id,
  ];
  const exists = db.prepare('SELECT 1 FROM playbooks WHERE playbook_id = ?').get(row.playbook_id);
  if (exists) {
    update.run(...values);
  } else {
    db.prepare(`INSERT INTO playbooks (
      playbook_id, name, description, author, difficulty, category,
      estimated_time, target_type, not_suitable_for, baseline_group,
      expected_output_policy, teaching_objective, roles_allowed,
      disable_auto_insert, enable_kg_context, requires_teacher_review,
      mitre_techniques, metadata
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        row.playbook_id, row.name, row.description, row.author, row.difficulty, row.category,
        row.estimated_time, row.target_type, row.not_suitable_for, row.baseline_group,
        row.expected_output_policy, row.teaching_objective, row.roles_allowed,
        row.disable_auto_insert, row.enable_kg_context, row.requires_teacher_review,
        row.mitre_techniques, row.metadata,
      );
  }

  db.prepare('DELETE FROM playbook_steps WHERE playbook_id = ?').run(playbook.id);
  const insertStep = db.prepare(`INSERT INTO playbook_steps (
    playbook_id, step_index, step_id, name, tool_id, args_template,
    description, score, expected_mitre, payload_id, payload_variables,
    evidence_config, requires_teacher_review, optional
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
  for (const [index, step] of (playbook.steps || []).entries()) {
    insertStep.run(
      playbook.id, index, step.id, step.name, step.toolId,
      JSON.stringify(step.argsTemplate || []), step.description || null, step.score || 0,
      step.expectedMitre ? JSON.stringify(step.expectedMitre) : null,
      step.payload_id || step.payloadId || null,
      step.payload_variables ? JSON.stringify(step.payload_variables) : null,
      step.evidence ? JSON.stringify(step.evidence) : null,
      step.requiresTeacherReview || step.requires_teacher_review ? 1 : 0,
      step.optional ? 1 : 0,
    );
  }
}

export default function up(db) {
  const playbook = definition('demo_web_full_killchain');
  db.transaction(() => syncPlaybook(db, playbook))();
}
