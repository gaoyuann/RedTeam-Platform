import { readFileSync } from 'fs';

function definition(name) {
  return JSON.parse(readFileSync(new URL(`../../../../data/playbooks/${name}.json`, import.meta.url), 'utf8'));
}

function updateStep(db, playbookId, stepId, args) {
  db.prepare('UPDATE playbook_steps SET args_template = ? WHERE playbook_id = ? AND step_id = ?')
    .run(JSON.stringify(args), playbookId, stepId);
}

function syncPlaybook(db, playbook) {
  db.prepare('UPDATE playbooks SET description = ?, teaching_objective = ?, expected_output_policy = ? WHERE playbook_id = ?')
    .run(playbook.description || null, playbook.teachingObjective || null, playbook.expectedOutputPolicy || null, playbook.id);
  for (const step of playbook.steps || []) updateStep(db, playbook.id, step.id, step.argsTemplate || []);
}

export default function up(db) {
  syncPlaybook(db, definition('golden_dvwa_max_tools'));
  const fileTamper = definition('dvwa_file_tamper');
  syncPlaybook(db, fileTamper);
  syncPlaybook(db, definition('web_vuln_exploit'));
  const fileEnum = fileTamper.steps.find(step => step.id === 'step2_dir_enum');
  if (fileEnum) updateStep(db, fileTamper.id, fileEnum.id, fileEnum.argsTemplate);

  // Replace the old GNU grep -P / exit-0 shell with a BusyBox-compatible,
  // fail-closed DVWA login check. The target placeholder is normalized by
  // playbookCompiler before this command is executed.
  const initCommand = [
    "set -eu",
    "echo '=== DVWA Init ==='",
    "BASE_URL=\"http://<target>\"",
    "rm -f /tmp/dvwa_jar.txt /tmp/dvwa_session.txt",
    "TOKEN=$(curl -fsS -c /tmp/dvwa_jar.txt \"$BASE_URL/login.php\" | sed -n \"s/.*name='user_token' value='\\([^']*\\)'.*/\\1/p\")",
    "if [ -z \"$TOKEN\" ]; then echo 'FATAL: Failed to get CSRF token' >&2; exit 1; fi",
    "curl -fsS -L -b /tmp/dvwa_jar.txt -c /tmp/dvwa_jar.txt -d \"username=admin&password=password&Login=Login&user_token=$TOKEN\" \"$BASE_URL/login.php\" -o /dev/null",
    "PHPSESSID=$(awk '$6 == \"PHPSESSID\" {print $7}' /tmp/dvwa_jar.txt | tail -n 1)",
    "if [ -z \"$PHPSESSID\" ]; then echo 'FATAL: Login failed - no session cookie' >&2; exit 1; fi",
    "CHECK=$(curl -fsS -L -b /tmp/dvwa_jar.txt \"$BASE_URL/index.php\")",
    "if ! printf '%s' \"$CHECK\" | grep -q 'Logout'; then echo 'FATAL: Login verification failed' >&2; exit 1; fi",
    "printf '%s\\n' \"$PHPSESSID\" > /tmp/dvwa_session.txt",
    "echo \"DVWA ready (session: $PHPSESSID, login_ok: 1)\"",
  ].join('; ');
  updateStep(db, fileTamper.id, 'step3_dvwa_init', ['-c', initCommand]);

  const verifyCommand = "set -eu; echo '=== Verifying Defacement ==='; HOMEPAGE=$(curl -fsS -L \"http://<target>/\"); if printf '%s' \"$HOMEPAGE\" | grep -q 'SYSTEM COMPROMISED'; then echo 'VERIFIED: Homepage defaced - SYSTEM COMPROMISED'; else echo 'VERIFY_FAILED: Homepage not tampered' >&2; exit 1; fi";
  updateStep(db, fileTamper.id, 'step6_verify_defaced', ['-c', verifyCommand]);
}
