import { readFileSync } from 'node:fs';

export default function up(db) {
  const definition = JSON.parse(readFileSync(new URL('../../../../data/playbooks/recon_dir_enum.json', import.meta.url), 'utf8'));
  const legacy = new Map([
    ['step1_gobuster_course_dict', ['-u', '<target>', '-w', 'config/wordlists/course_web_dirs.txt', '-t', '10', '-q', '-fw']],
    ['step2_gobuster_status_filter', ['-u', '<target>', '-w', 'config/wordlists/course_web_dirs.txt', '-s', '403', '-t', '10', '-q', '-fw']],
  ]);
  db.transaction(() => {
    for (const step of definition.steps) {
      const existing = db.prepare('SELECT args_template FROM playbook_steps WHERE playbook_id = ? AND step_id = ? AND tool_id = ?')
        .get(definition.id, step.id, step.toolId);
      if (!existing) continue;
      let args;
      try { args = JSON.parse(existing.args_template); } catch { continue; }
      if (JSON.stringify(args) !== JSON.stringify(legacy.get(step.id))) continue;
      db.prepare('UPDATE playbook_steps SET args_template = ?, name = ?, description = ? WHERE playbook_id = ? AND step_id = ?')
        .run(JSON.stringify(step.argsTemplate), step.name, step.description, definition.id, step.id);
    }
  })();
}
