import { readFileSync } from 'fs';

export default function up(db) {
  const definition = db.prepare("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'scan_tasks'").get().sql;
  if (!definition.includes("'PARTIAL'")) {
    const indexes = db.prepare("SELECT sql FROM sqlite_master WHERE tbl_name = 'scan_tasks' AND type IN ('index', 'trigger') AND sql IS NOT NULL").all();
    const foreignKeys = db.pragma('foreign_keys', { simple: true });
    db.pragma('foreign_keys = OFF');
    try {
      db.transaction(() => {
        db.exec(definition.replace(/CREATE TABLE\s+(?:IF NOT EXISTS\s+)?["`]?scan_tasks["`]?/i, 'CREATE TABLE scan_tasks_updated')
          .replace("'COMPLETED'", "'COMPLETED','PARTIAL'"));
        db.exec('INSERT INTO scan_tasks_updated SELECT * FROM scan_tasks');
        db.exec('DROP TABLE scan_tasks');
        db.exec('ALTER TABLE scan_tasks_updated RENAME TO scan_tasks');
        for (const index of indexes) db.exec(index.sql);
        if (db.pragma('foreign_key_check').length) throw new Error('Foreign key validation failed during scan status migration');
      })();
    } finally { db.pragma(`foreign_keys = ${foreignKeys ? 'ON' : 'OFF'}`); }
  }
  const columns = db.prepare('PRAGMA table_info(scan_tasks)').all();
  if (!columns.some(column => column.name === 'target_profile')) db.exec('ALTER TABLE scan_tasks ADD COLUMN target_profile TEXT');
  const stepColumns = db.prepare('PRAGMA table_info(playbook_steps)').all();
  for (const name of ['input_variables', 'output_variables']) {
    if (!stepColumns.some(column => column.name === name)) db.exec(`ALTER TABLE playbook_steps ADD COLUMN ${name} TEXT`);
  }
  const playbook = JSON.parse(readFileSync(new URL('../../../../data/playbooks/golden_dvwa_max_tools.json', import.meta.url), 'utf8'));
  const update = db.prepare('UPDATE playbook_steps SET input_variables = ?, output_variables = ? WHERE playbook_id = ? AND step_id = ?');
  for (const step of playbook.steps) {
    if (step.inputs || step.outputs) update.run(JSON.stringify(step.inputs || []), JSON.stringify(step.outputs || []), playbook.id, step.id);
  }
  for (const step of db.prepare("SELECT s.playbook_id, s.step_id, s.args_template, p.target_type FROM playbook_steps s JOIN playbooks p ON p.playbook_id = s.playbook_id WHERE s.tool_id = 'curl' AND s.output_variables IS NULL").all()) {
    let targetTypes;
    try { targetTypes = JSON.parse(step.target_type || '[]'); } catch { continue; }
    if (!Array.isArray(targetTypes) || !targetTypes.includes('dvwa')) continue;
    if (/login\.php|\{\{(?:dvwa_)?login_url\}\}/.test(step.args_template || '') && /username=/.test(step.args_template || '')) {
      update.run('[]', '["dvwa_cookie","auth_cookie"]', step.playbook_id, step.step_id);
    }
  }
}
