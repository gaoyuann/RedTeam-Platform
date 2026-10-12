import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import BetterSqlite3 from 'better-sqlite3';
import schema from '../src/db/migrations/001_create_tables.js';
import importPlaybooks from '../src/db/migrations/003_import_playbooks.js';
import syncDemoPlaybook from '../src/db/migrations/027_sync_demo_web_killchain.js';
import syncGenericNuclei from '../src/db/migrations/028_sync_generic_web_nuclei.js';
import { discoverTargetProfile } from '../src/services/targetDiscovery.js';
import { normalizeToolArgs, validateToolArgs } from '../src/tools/toolContracts.js';
import { checkTargetTypeCompatibility } from '../src/services/targetProfileResolver.js';
import { BIN_MAP } from '../src/tools/toolRunner.js';
import { getToolTimeout } from '../src/services/executionEngine.js';

const demo = JSON.parse(readFileSync(new URL('../../data/playbooks/demo_web_full_killchain.json', import.meta.url), 'utf8'));
const generic = JSON.parse(readFileSync(new URL('../../data/playbooks/web_auto_killchain.json', import.meta.url), 'utf8'));

test('demo and generic Web playbooks remain separate products', () => {
  assert.deepEqual(demo.targetType, ['dvwa']);
  assert.deepEqual(demo.applicableTargetType, ['dvwa']);
  assert.deepEqual(generic.targetType, ['web_url', 'local_ip']);
  assert.equal(demo.steps.find(step => step.id === 'step_5_brute_force').toolId, 'web-brute');
  assert.equal(demo.steps.find(step => step.id === 'step_5_brute_force').argsTemplate[0], '{{login_url}}');
  assert.equal(BIN_MAP['web-brute'], '/usr/local/bin/web-brute.py');
  assert.deepEqual(
    demo.steps.find(step => step.id === 'step_4_vuln_scan').argsTemplate.slice(-1),
    ['http-missing-security-headers,dvwa-default-login,phpinfo-files,phpmyadmin-panel'],
  );
  const nuclei = generic.steps.find(step => step.toolId === 'nuclei');
  assert.deepEqual(nuclei.argsTemplate.slice(-4), ['-severity', 'medium,high,critical', '-timeout', '5']);
});

test('Nuclei gets a longer per-tool timeout without changing other tools', context => {
  const previous = process.env.NUCLEI_TIMEOUT_MS;
  context.after(() => {
    if (previous === undefined) delete process.env.NUCLEI_TIMEOUT_MS;
    else process.env.NUCLEI_TIMEOUT_MS = previous;
  });
  delete process.env.NUCLEI_TIMEOUT_MS;
  assert.equal(getToolTimeout('nuclei'), 900_000);
  assert.equal(getToolTimeout('nikto'), 300_000);
  process.env.NUCLEI_TIMEOUT_MS = '1200000';
  assert.equal(getToolTimeout('nuclei'), 1_200_000);
  for (const value of ['0', '-1', 'invalid', '900000ms', '2147483648']) {
    process.env.NUCLEI_TIMEOUT_MS = value;
    assert.equal(getToolTimeout('nuclei'), 900_000);
  }
});

test('generic Nuclei migration updates existing steps and is repeatable', () => {
  const db = new BetterSqlite3(':memory:');
  try {
    schema(db);
    importPlaybooks(db);
    const before = db.prepare("SELECT * FROM playbook_steps WHERE playbook_id = 'web_auto_killchain' AND tool_id != 'nuclei'").all();
    db.prepare("UPDATE playbook_steps SET args_template = ? WHERE playbook_id = 'web_auto_killchain' AND tool_id = 'nuclei'")
      .run(JSON.stringify(['-u', '<target>', '-timeout', '5']));
    syncGenericNuclei(db);
    syncGenericNuclei(db);
    const row = db.prepare("SELECT args_template FROM playbook_steps WHERE playbook_id = 'web_auto_killchain' AND tool_id = 'nuclei'").get();
    assert.deepEqual(JSON.parse(row.args_template), generic.steps.find(step => step.toolId === 'nuclei').argsTemplate);
    assert.deepEqual(db.prepare("SELECT * FROM playbook_steps WHERE playbook_id = 'web_auto_killchain' AND tool_id != 'nuclei'").all(), before);
  } finally {
    db.close();
  }
});

test('migration can insert the demo contract when an older database lacks it', () => {
  const db = new BetterSqlite3(':memory:');
  try {
    schema(db);
    syncDemoPlaybook(db);
    const playbook = db.prepare("SELECT target_type FROM playbooks WHERE playbook_id = 'demo_web_full_killchain'").get();
    const steps = db.prepare("SELECT count(*) AS count FROM playbook_steps WHERE playbook_id = 'demo_web_full_killchain'").get();
    assert.deepEqual(JSON.parse(playbook.target_type), ['dvwa']);
    assert.equal(steps.count, demo.steps.length);
  } finally {
    db.close();
  }
});

test('migration synchronizes the complete demo contract into an existing database', () => {
  const db = new BetterSqlite3(':memory:');
  try {
    schema(db);
    importPlaybooks(db);
    db.prepare("UPDATE playbooks SET target_type = ?, metadata = ? WHERE playbook_id = 'demo_web_full_killchain'")
      .run(JSON.stringify(['web_url', 'dvwa']), JSON.stringify({ target_class: 'web_url' }));
    db.prepare("UPDATE playbook_steps SET args_template = ? WHERE playbook_id = 'demo_web_full_killchain' AND step_id = 'step_4_vuln_scan'")
      .run(JSON.stringify(['-u', '<target>', '-id', 'missing-template']));

    syncDemoPlaybook(db);

    const playbook = db.prepare("SELECT target_type, metadata FROM playbooks WHERE playbook_id = 'demo_web_full_killchain'").get();
    const steps = db.prepare("SELECT step_id, tool_id, args_template, requires_teacher_review FROM playbook_steps WHERE playbook_id = 'demo_web_full_killchain' ORDER BY step_index").all();
    assert.deepEqual(JSON.parse(playbook.target_type), ['dvwa']);
    assert.equal(JSON.parse(playbook.metadata).target_class, 'dvwa');
    assert.equal(steps.length, demo.steps.length);
    const brute = steps.find(step => step.step_id === 'step_5_brute_force');
    assert.equal(brute.tool_id, 'web-brute');
    assert.equal(brute.requires_teacher_review, 1);
    assert.deepEqual(JSON.parse(steps.find(step => step.step_id === 'step_4_vuln_scan').args_template), demo.steps[3].argsTemplate);
  } finally {
    db.close();
  }
});

test('DVWA preflight can identify its same-origin login page after a modified homepage', async () => {
  const db = new BetterSqlite3(':memory:');
  try {
    schema(db);
    const requested = [];
    const request = async url => {
      requested.push(url.href);
      if (url.pathname === '/login.php') {
        return new Response('<html><title>DVWA - Damn Vulnerable Web Application</title><body>Damn Vulnerable Web Application<form action="login.php"></form></body></html>', { status: 200 });
      }
      return new Response('<html><title>SYSTEM COMPROMISED</title><body>modified homepage</body></html>', { status: 200 });
    };
    const profile = await discoverTargetProfile(db, 'http://192.0.2.25:4280/', [], { request, probePaths: ['login.php'] });
    assert.equal(profile.target_class, 'dvwa');
    assert.equal(profile.application?.name, 'dvwa');
    assert.deepEqual(requested, ['http://192.0.2.25:4280/', 'http://192.0.2.25:4280/login.php']);
  } finally {
    db.close();
  }
});

test('a generic Web target cannot pass the DVWA-only demo compatibility gate', () => {
  const compatibility = checkTargetTypeCompatibility(['dvwa'], 'web_url');
  assert.equal(compatibility.ok, false);
  assert.match(compatibility.reason, /not compatible/);
});

test('legacy argument forms are normalized before their contracts are checked', () => {
  const gobuster = normalizeToolArgs('gobuster', ['-m', 'dir', '-u', 'http://192.0.2.25:4280', '-w', 'config/wordlists/common_dirs.txt'], {
    projectRoot: process.cwd(), engine: 'docker',
  });
  assert.equal(gobuster[0], 'dir');
  assert.deepEqual(validateToolArgs('gobuster', gobuster), []);

  const hydra = normalizeToolArgs('hydra', ['-l', 'admin', 'http://192.0.2.25:4280', 'http-form-post', '/login.php'], {
    projectRoot: process.cwd(), engine: 'docker',
  });
  assert.ok(hydra.includes('http-post-form'));
  assert.deepEqual(validateToolArgs('hydra', hydra), []);

  const webBrute = normalizeToolArgs('web-brute', ['http://192.0.2.25:4280/login.php', '-P', 'config/wordlists/common_passwords.txt'], {
    projectRoot: process.cwd(), engine: 'docker', target: 'http://192.0.2.25:4280',
  });
  assert.equal(webBrute[0], 'http://192.0.2.25:4280/login.php');
  assert.ok(webBrute.includes('/usr/share/wordlists/common_passwords.txt'));
  const legacyWebBrute = normalizeToolArgs('web-brute', ['/usr/local/bin/web-brute.py', '192.0.2.25:4280/login.php', '-P', 'config/wordlists/common_passwords.txt'], {
    projectRoot: process.cwd(), engine: 'docker', target: 'http://192.0.2.25:4280',
  });
  assert.deepEqual(legacyWebBrute, webBrute);
});
