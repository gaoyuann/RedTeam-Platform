import { readFileSync } from 'fs';

export default function up(db) {
  const playbook = JSON.parse(readFileSync(new URL('../../../../data/playbooks/golden_dvwa_max_tools.json', import.meta.url), 'utf8'));
  db.transaction(() => {
    db.prepare('UPDATE playbooks SET description = ? WHERE playbook_id = ?').run(playbook.description, playbook.id);
    for (const step of playbook.steps) {
      if (!['step_4_gobuster', 'step_5_curl_login', 'step_6_hydra', 'step_7_sqlmap', 'step_8_ffuf', 'step_9_arjun'].includes(step.id)) continue;
      db.prepare('UPDATE playbook_steps SET args_template = ? WHERE playbook_id = ? AND step_id = ?')
        .run(JSON.stringify(step.argsTemplate), playbook.id, step.id);
    }
  })();
}
