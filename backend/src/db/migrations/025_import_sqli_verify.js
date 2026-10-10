import { readFileSync } from 'fs';

export default function up(db) {
  const playbook = JSON.parse(readFileSync(new URL('../../../../data/playbooks/web_sqli_verify.json', import.meta.url), 'utf8'));
  db.transaction(() => {
    const inserted = db.prepare(`INSERT OR IGNORE INTO playbooks
      (playbook_id, name, description, author, difficulty, estimated_time, target_type,
       not_suitable_for, baseline_group, disable_auto_insert, mitre_techniques, metadata, is_generated)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`).run(
      playbook.id, playbook.name, playbook.description, playbook.author, playbook.difficulty,
      playbook.estimatedTimeMinutes, JSON.stringify(playbook.targetType), JSON.stringify(playbook.notSuitableFor),
      playbook.baselineGroup, Number(playbook.disableAutoInsert), JSON.stringify(playbook.mitreTechniques),
      JSON.stringify({ target_class: playbook.target_class }));
    if (!inserted.changes) return;
    for (const [index, step] of playbook.steps.entries()) {
      db.prepare(`INSERT INTO playbook_steps
        (playbook_id, step_index, step_id, name, tool_id, args_template, description, score, expected_mitre)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(playbook.id, index, step.id, step.name, step.toolId,
        JSON.stringify(step.argsTemplate), step.description, step.score, JSON.stringify(step.expectedMitre));
    }
  })();
}
