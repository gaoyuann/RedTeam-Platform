import { readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PLAYBOOKS_DIR = join(__dirname, '..', '..', '..', '..', 'data', 'playbooks');

export default function up(db) {
  const playbook = JSON.parse(readFileSync(join(PLAYBOOKS_DIR, 'web_auto_killchain.json'), 'utf8'));
  const nucleiStep = playbook.steps?.find(step => step.toolId === 'nuclei');
  if (!nucleiStep) return;
  db.prepare('UPDATE playbook_steps SET args_template = ? WHERE playbook_id = ? AND step_id = ?')
    .run(JSON.stringify(nucleiStep.argsTemplate || []), playbook.id, nucleiStep.id);
}
