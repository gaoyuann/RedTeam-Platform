import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import express from 'express';
import { getDb, closeDb } from '../src/db/connection.js';
import schema from '../src/db/migrations/001_create_tables.js';
import importPlaybooks from '../src/db/migrations/003_import_playbooks.js';
import importSqliVerify from '../src/db/migrations/025_import_sqli_verify.js';
import { matchPlaybooks } from '../src/services/playbookMatcher.js';
import { buildDiscoveredProfile } from '../src/services/targetDiscovery.js';
import scanRoutes from '../src/routes/scans.js';
import { recommendForScans } from '../src/services/playbookRecommendations.js';
import scanProfileMigration from '../src/db/migrations/020_scan_target_profile.js';

const db = getDb(':memory:');
schema(db);
importPlaybooks(db);
scanProfileMigration(db);
after(closeDb);

const webProfile = { target_class: 'web_url', application: null };
const dvwaProfile = { target_class: 'dvwa', application: { name: 'dvwa', confidence: 0.95 } };
const finding = (data, overrides = {}) => ({ result_type: 'vulnerability', severity: 'high',
  result_data: JSON.stringify(data), source_tool: 'nuclei', ...overrides });

function insertCandidate(identifier, steps, metadata = {}) {
  db.prepare(`INSERT INTO playbooks (playbook_id, name, target_type, not_suitable_for, metadata, mitre_techniques, baseline_group)
    VALUES (?, ?, '["web_url","dvwa"]', '[]', '{}', ?, ?)`).run(identifier, identifier,
    JSON.stringify(metadata.techniques || []), metadata.baseline || 'web-vuln-scan');
  for (const [index, [tool, args]] of steps.entries()) {
    db.prepare(`INSERT INTO playbook_steps (playbook_id, step_index, step_id, name, tool_id, args_template)
      VALUES (?, ?, ?, ?, ?, ?)`).run(identifier, index, `step-${index}`, tool, tool, JSON.stringify(args));
  }
}

function removeCandidate(identifier) {
  db.prepare('DELETE FROM playbooks WHERE playbook_id=?').run(identifier);
}

test('configuration findings prefer dedicated scans over generic exploitation', () => {
  const results = [finding({ finding: 'The anti-clickjacking X-Frame-Options header is not present.' },
    { result_type: 'web_vuln', severity: 'medium', source_tool: 'nikto' })];
  const ranked = matchPlaybooks(results, webProfile);
  assert.equal(ranked[0].match_stage, 'supplemental_scan');
  assert.match(ranked[0].match_reason, /不代表已验证/);
  assert.ok(ranked.find(item => item.playbook_id === 'web_server_scan_nikto'));
  assert.ok(!ranked.find(item => item.playbook_id === 'web_file_upload_exploit'));
});

test('SQL injection signals use actual parser fields and prefer generic endpoint verification', () => {
  for (const data of [{ template: 'sqli-error-based' }, { finding: 'SQL injection detected' },
    { detail: 'SQL syntax error' }, { vuln_type: 'sql_injection' }, { title: 'SQL 注入' },
    { title: 'SQL injection in HTTP header' }]) {
    for (const result_data of [data, JSON.stringify(data)]) {
      const ranked = matchPlaybooks([finding({}, { result_data })], webProfile);
      assert.equal(ranked[0].playbook_id, 'web_sqli_verify');
      assert.ok(!ranked.some(item => ['sqli_exploit_sqlmap_basic', 'test_payloader_sqli', 'sqli_to_shell'].includes(item.playbook_id)));
      assert.match(ranked[0].match_reason, /SQL 注入/);
    }
  }
});

test('file upload signals prefer upload-specific tests', () => {
  const ranked = matchPlaybooks([finding({ template: 'arbitrary-file-upload' })], webProfile);
  assert.equal(ranked[0].playbook_id, 'web_file_upload_exploit');
  assert.ok(!ranked.some(item => item.playbook_id === 'web_vuln_exploit'));
});

test('XSS detection does not recommend unrelated upload or configuration-only templates', () => {
  insertCandidate('matcher-xss', [['nuclei', ['-u', '<target>', '-tags', 'xss']]]);
  try {
  const ranked = matchPlaybooks([finding({ template: 'reflected-xss' })], webProfile);
  assert.ok(ranked.length);
  assert.equal(ranked[0].playbook_id, 'matcher-xss');
  assert.ok(!ranked.some(item => ['web_file_upload_exploit', 'vuln_template_nuclei'].includes(item.playbook_id)));
  } finally { removeCandidate('matcher-xss'); }
});

test('a product name in the target URL is not proof of a DVWA application', () => {
  const profile = buildDiscoveredProfile('http://192.168.1.111:4280/dvwa', []);
  const ranked = matchPlaybooks([finding({}, { result_type: 'sql_injection' })], profile);
  assert.ok(!ranked.some(item => item.playbook_id === 'sqli_exploit_sqlmap_basic'));
});

test('fingerprints alone recommend reconnaissance, not exploitation', () => {
  const ranked = matchPlaybooks([finding({ url: 'http://192.168.1.111:8765', status_code: 200,
    title: 'Pikachu', technologies: ['PHP'] }, { result_type: 'http_probe', severity: 'info' })], webProfile);
  assert.ok(ranked.length);
  assert.ok(ranked.every(item => item.match_stage !== 'verification'));
  assert.ok(ranked.every(item => item.match_evidence.every(signal => signal.kind === 'web')));
  assert.ok(!ranked.some(item => item.playbook_id === 'web_vuln_exploit'));
});

test('DVWA-specific steps require confirmed application evidence', () => {
  insertCandidate('matcher-dvwa-sqli', [['nuclei', ['-u', '<target>', '-id', 'dvwa-sqli']]]);
  try {
  const results = [finding({}, { result_type: 'sql_injection' })];
  for (const profile of [webProfile, 'dvwa', { ...dvwaProfile, application: { name: 'dvwa', confidence: 0.5 } }]) {
    assert.ok(!matchPlaybooks(results, profile).some(item => item.playbook_id === 'matcher-dvwa-sqli'));
  }
  const ranked = matchPlaybooks(results, dvwaProfile);
  assert.equal(ranked[0].playbook_id, 'matcher-dvwa-sqli');
  assert.match(ranked[0].match_reason, /扫描指纹确认 DVWA/);
  assert.ok(!ranked.some(item => item.playbook_id === 'sqli_exploit_sqlmap_basic'));
  const credentials = matchPlaybooks([finding({}, { result_type: 'credential' })], webProfile);
  assert.ok(!credentials.some(item => item.playbook_id === 'brute_force_hydra'));
  const session = matchPlaybooks([finding({}, { mitre_technique_id: 'T1539' })], webProfile);
  assert.ok(!session.some(item => item.playbook_id === 'session_hijacking_basic'));
  } finally { removeCandidate('matcher-dvwa-sqli'); }
});

test('generic steps are usable despite legacy DVWA metadata', () => {
  const result = finding({ finding: 'Missing HSTS header' }, { severity: 'medium' });
  const ranked = matchPlaybooks([result], webProfile);
  assert.ok(ranked.some(candidate => candidate.playbook_id === 'vuln_template_nuclei'));
  assert.ok(!ranked.some(item => item.playbook_id === 'golden_dvwa_max_tools'));
});

test('repeated low-value findings cannot swamp a specific vulnerability', () => {
  const header = finding({ finding: 'Missing X-Frame-Options header' }, { severity: 'medium' });
  const sql = finding({ template: 'sqli-error-based' });
  assert.deepEqual(matchPlaybooks([header, sql], webProfile), matchPlaybooks([...Array(100).fill(header), sql], webProfile));
  assert.equal(matchPlaybooks([...Array(100).fill(header), sql], webProfile)[0].playbook_id, 'web_sqli_verify');
});

test('errors, raw output, empty scans and failed HTTP probes do not manufacture recommendations', () => {
  for (const results of [[], [finding({}, { result_type: 'scan_error' })],
    [finding({}, { result_type: 'raw_output' })], [finding({ status_code: 500 }, { result_type: 'http_probe' })],
    [finding({}, { result_type: 'unknown_type' })]]) {
    assert.deepEqual(matchPlaybooks(results, webProfile), []);
  }
});

test('incompatible and explicitly excluded playbooks are filtered', () => {
  assert.ok(!matchPlaybooks([finding({ template: 'sqli-error-based' })], 'windows_ad')
    .some(item => item.playbook_id === 'web_sqli_verify'));
  db.prepare("UPDATE playbooks SET not_suitable_for = '[\"web_url\"]' WHERE playbook_id = 'web_sqli_verify'").run();
  try {
    assert.ok(!matchPlaybooks([finding({ template: 'sqli-error-based' })], webProfile)
      .some(item => item.playbook_id === 'web_sqli_verify'));
  } finally {
    db.prepare("UPDATE playbooks SET not_suitable_for = '[\"windows_host\",\"ad_domain\"]' WHERE playbook_id = 'web_sqli_verify'").run();
  }
});

test('legacy baseline aliases match generic web vulnerabilities', () => {
  const ranked = matchPlaybooks([finding({ template: 'cve-2026-example' })], webProfile);
  assert.ok(ranked.some(item => item.playbook_id === 'web_server_scan_nikto'));
  assert.ok(ranked.every(item => item.match_score > 0));
});

test('generic SQL verification migration upgrades existing libraries without duplicates', () => {
  db.prepare("DELETE FROM playbooks WHERE playbook_id = 'web_sqli_verify'").run();
  importSqliVerify(db);
  importSqliVerify(db);
  assert.equal(db.prepare("SELECT COUNT(*) AS count FROM playbooks WHERE playbook_id = 'web_sqli_verify'").get().count, 1);
  const steps = db.prepare("SELECT * FROM playbook_steps WHERE playbook_id = 'web_sqli_verify'").all();
  assert.equal(steps.length, 1);
  assert.doesNotMatch(steps[0].args_template, /dvwa|--dump|--os-shell/);
  assert.match(steps[0].args_template, /<target>/);
});

test('recommendation API uses only selected scan evidence even for historical scans', async () => {
  db.prepare("INSERT INTO users (username, password, role) VALUES ('matcher-user', 'test', 'user')").run();
  db.prepare(`INSERT INTO scan_tasks (scan_task_id, target, scan_type, status, created_by, completed_at)
    VALUES ('matcher-scan', 'http://192.168.1.111:4280', 'app_discovery', 'COMPLETED', 'matcher-user', '2026-01-01T00:00:00Z')`).run();
  const probe = finding({ url: 'http://192.168.1.111:4280/login.php', status_code: 200,
    title: 'DVWA', technologies: ['DVWA'] }, { result_type: 'http_probe', severity: 'info' });
  const injection = finding({}, { result_type: 'sql_injection' });
  for (const result of [probe, injection]) {
    db.prepare('INSERT INTO scan_results (scan_task_id, result_type, result_data, severity) VALUES (?, ?, ?, ?)')
      .run('matcher-scan', result.result_type, result.result_data, result.severity);
  }
  db.prepare(`INSERT INTO scan_tasks (scan_task_id, target, scan_type, status, created_by)
    VALUES ('matcher-other', 'http://192.168.1.111:4280', 'web_scan', 'COMPLETED', 'matcher-user')`).run();
  db.prepare(`INSERT INTO scan_results (scan_task_id, result_type, result_data, severity)
    VALUES ('matcher-other', 'vulnerability', '{"template":"arbitrary-file-upload"}', 'critical')`).run();
  const app = express();
  app.use((req, res, next) => { req.user = { sub: 'matcher-user', role: 'user' }; next(); });
  app.use('/api/scan-tasks', scanRoutes(db));
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/scan-tasks/matcher-scan/recommendations`);
    assert.equal(response.status, 200);
    const { data } = await response.json();
    const selected = db.prepare("SELECT * FROM scan_results WHERE scan_task_id='matcher-scan'").all();
    const expectedProfile = buildDiscoveredProfile('http://192.168.1.111:4280', selected);
    assert.deepEqual(data, matchPlaybooks(selected, expectedProfile));
    assert.equal(data[0].match_stage, 'verification');
    assert.ok(data.some(candidate => candidate.playbook_id === 'web_sqli_verify'));
    assert.ok(data.every(candidate => candidate.match_evidence.every(signal => signal.scan_task_id === 'matcher-scan')));
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test('recommendation table displays numeric scores and defaults to descending score order', () => {
  const source = readFileSync(new URL('../../frontend/src/pages/ScanPage.cpp', import.meta.url), 'utf8');
  assert.match(source, /scoreItem->setData\(Qt::DisplayRole, r\["match_score"\]\.toDouble\(\)\)/);
  assert.match(source, /m_recTable->sortItems\(4, Qt::DescendingOrder\)/);
  assert.match(source, /推荐类型\/条件/);
});

test('security headers and cookie settings never establish SQL injection or XSS', () => {
  const ranked = matchPlaybooks([
    finding({ finding: 'The X-XSS-Protection header is not defined.' }),
    finding({ finding: 'Cookie PHPSESSID created without the httponly flag' }),
  ], webProfile);
  assert.ok(ranked.length);
  assert.ok(ranked.every(candidate => candidate.match_stage !== 'verification'));
  assert.ok(ranked.every(candidate => !candidate.automatic_eligible));
  assert.ok(ranked.some(candidate => candidate.match_evidence.some(signal => signal.kind === 'cookies')));
});

test('equivalent header-check capabilities receive equal scores regardless of tool or id', () => {
  insertCandidate('matcher-header-nuclei', [['nuclei', ['-u', '<target>', '-id', 'http-missing-security-headers']]]);
  insertCandidate('matcher-header-nikto', [['nikto', ['-h', '<target>']]]);
  try {
    const ranked = matchPlaybooks([finding({ finding: 'Missing X-Frame-Options header' })], webProfile);
    const score = identifier => ranked.find(candidate => candidate.playbook_id === identifier).match_score;
    assert.equal(score('matcher-header-nuclei'), score('matcher-header-nikto'));
  } finally {
    removeCandidate('matcher-header-nuclei');
    removeCandidate('matcher-header-nikto');
  }
});

test('directory indexing favors a directory capability rather than header rechecking', () => {
  insertCandidate('matcher-directory', [['gobuster', ['dir', '-u', '<target>', '-w', 'dirs.txt']]]);
  insertCandidate('matcher-headers', [['nuclei', ['-u', '<target>', '-id', 'http-missing-security-headers']]]);
  try {
    const ranked = matchPlaybooks([finding({ finding: 'Directory indexing found.' })], webProfile);
    assert.equal(ranked[0].match_stage, 'reconnaissance');
    assert.ok(ranked.some(candidate => candidate.playbook_id === 'matcher-directory'));
    assert.ok(!ranked.some(candidate => candidate.playbook_id === 'matcher-headers'));
  } finally {
    removeCandidate('matcher-directory');
    removeCandidate('matcher-headers');
  }
});

test('completed checks are retained with explanations but receive lower priority', () => {
  const results = [finding({ finding: 'Missing X-Frame-Options header' })];
  const original = matchPlaybooks(results, webProfile);
  const updated = matchPlaybooks(results, webProfile, { completedActions: ['nikto:web'] });
  const originalNikto = original.find(candidate => candidate.playbook_id === 'web_server_scan_nikto');
  const updatedNikto = updated.find(candidate => candidate.playbook_id === 'web_server_scan_nikto');
  assert.ok(updatedNikto.match_score < originalNikto.match_score);
  assert.equal(updatedNikto.match_status, 'already_checked');
  assert.match(updatedNikto.match_reason, /降低重复检查/);
  assert.equal(updatedNikto.automatic_eligible, false);
});

test('SQL verification requires a concrete parameter entry but never borrows finding URLs', () => {
  const results = [finding({ template: 'sqli-error-based', url: 'http://example.test/Less-1/?id=1' })];
  const homepage = { ...webProfile, target_url: 'http://example.test/' };
  const candidate = matchPlaybooks(results, homepage)[0];
  assert.equal(candidate.playbook_id, 'web_sqli_verify');
  assert.equal(candidate.match_status, 'needs_input');
  assert.equal(candidate.automatic_eligible, false);
  assert.match(candidate.match_conditions.join('; '), /带参数/);
  const selected = matchPlaybooks(results, { ...homepage, target_url: 'http://example.test/Less-1/?id=1' })[0];
  assert.equal(selected.match_status, 'ready');
  assert.equal(selected.automatic_eligible, true);
  for (const target_url of ['http://example.test/?id=', 'http://example.test/#id=1', 'not-a-url']) {
    assert.equal(matchPlaybooks(results, { ...homepage, target_url })[0].match_status, 'needs_input');
  }
});

test('a SQL training-site page title is reconnaissance, not injection evidence', () => {
  const ranked = matchPlaybooks([finding({ url: 'http://example.test/', status_code: 200,
    title: 'SQL Injections' }, { result_type: 'http_probe' })], webProfile);
  assert.ok(ranked.length);
  assert.ok(!ranked.some(candidate => candidate.playbook_id === 'web_sqli_verify'));
  assert.ok(ranked.every(candidate => candidate.match_evidence.every(signal => signal.kind === 'web')));
});

test('impactful, export and unsupported actions do not enter evidence recommendations', () => {
  insertCandidate('matcher-dump', [['sqlmap', ['-u', '<target>', '--dump']]]);
  insertCandidate('matcher-shell', [['sqlmap', ['-u', '<target>', '--os-shell']]]);
  insertCandidate('matcher-impact', [['nuclei', ['-u', '<target>']]], { techniques: ['T1498.001'] });
  try {
    const ranked = matchPlaybooks([finding({ template: 'sqli-error-based' }),
      finding({ finding: 'Missing X-Frame-Options header' }), finding({ template: 'cve-test' })], dvwaProfile);
    assert.ok(ranked.length);
    assert.ok(!ranked.some(candidate => ['matcher-dump', 'matcher-shell', 'matcher-impact',
      'http_flood_dos', 'dvwa_file_tamper', 'sqli_to_shell'].includes(candidate.playbook_id)));
  } finally {
    for (const identifier of ['matcher-dump', 'matcher-shell', 'matcher-impact']) removeCandidate(identifier);
  }
});

test('open ports are not evidence for credential attacks or impact operations', () => {
  const ranked = matchPlaybooks([finding({ port: 22 }, { result_type: 'open_port', source_tool: 'nmap' })], 'local_ip');
  assert.ok(ranked.length);
  assert.ok(ranked.every(candidate => candidate.match_stage === 'reconnaissance'));
});

test('mixed verification selectors require evidence for every intrusive capability', () => {
  insertCandidate('matcher-mixed', [['nuclei', ['-u', '<target>', '-tags', 'sqli,xss']]]);
  try {
    const sql = finding({ template: 'sqli-error-based' });
    assert.ok(!matchPlaybooks([sql], webProfile).some(candidate => candidate.playbook_id === 'matcher-mixed'));
    assert.ok(matchPlaybooks([sql, finding({ template: 'reflected-xss' })], webProfile)
      .some(candidate => candidate.playbook_id === 'matcher-mixed'));
  } finally { removeCandidate('matcher-mixed'); }
});

test('explicit negative and malformed findings do not manufacture matches', () => {
  for (const result of [finding({ template: 'sqli-error-based', vulnerable: false }),
    finding({ finding: 'Target is not vulnerable to SQL injection' }), finding({}),
    finding({}, { result_data: '{broken' }), finding({ status: 'unknown' }, { result_type: 'host_discovery' }),
    finding({ url: 'http://example.test/', status_code: 'invalid' }, { result_type: 'http_probe' })]) {
    assert.deepEqual(matchPlaybooks([result], webProfile), []);
  }
});

test('scoped recommendations ignore other targets, running scans and failed tool checks', () => {
  for (const [identifier, target, status] of [['matcher-scope', 'http://scope.test', 'PARTIAL'],
    ['matcher-foreign', 'http://other.test', 'COMPLETED'], ['matcher-running', 'http://scope.test', 'RUNNING']]) {
    db.prepare('INSERT INTO scan_tasks (scan_task_id, target, scan_type, status) VALUES (?, ?, ?, ?)')
      .run(identifier, target, 'web_scan', status);
  }
  const insert = db.prepare('INSERT INTO scan_results (scan_task_id, result_type, result_data, severity, source_tool) VALUES (?, ?, ?, ?, ?)');
  insert.run('matcher-scope', 'web_vuln', '{"finding":"Missing X-Frame-Options header"}', 'medium', 'nikto');
  insert.run('matcher-scope', 'scan_warning', '{"warning":"timeout"}', 'info', 'nikto');
  for (const identifier of ['matcher-foreign', 'matcher-running']) {
    insert.run(identifier, 'sql_injection', '{}', 'high', 'sqlmap');
  }
  const candidates = recommendForScans(db, 'http://scope.test', ['matcher-scope', 'matcher-foreign', 'matcher-running']);
  assert.ok(candidates.length);
  assert.ok(!candidates.some(candidate => candidate.playbook_id === 'web_sqli_verify'));
  assert.equal(candidates.find(candidate => candidate.playbook_id === 'web_server_scan_nikto').match_status, 'ready');
  assert.ok(candidates.every(candidate => candidate.match_evidence.every(signal => signal.scan_task_id === 'matcher-scope')));
  assert.deepEqual(recommendForScans(db, 'http://scope.test', []), []);
});

test('scoped recommendations reject redirected or foreign-origin findings in the same scan', () => {
  db.prepare('INSERT INTO scan_tasks (scan_task_id, target, scan_type, status) VALUES (?, ?, ?, ?)')
    .run('matcher-redirected', 'http://scope.test', 'web_scan', 'COMPLETED');
  const insert = db.prepare('INSERT INTO scan_results (scan_task_id, result_type, result_data, severity, source_tool) VALUES (?, ?, ?, ?, ?)');
  insert.run('matcher-redirected', 'web_vuln', '{"finding":"Missing X-Frame-Options header","url":"http://scope.test/"}', 'medium', 'nikto');
  for (const url of ['http://other.test/?id=1', 'http://scope.test:8080/?id=1']) {
    insert.run('matcher-redirected', 'sql_injection', JSON.stringify({ url }), 'high', 'sqlmap');
  }
  const ranked = recommendForScans(db, 'http://scope.test', 'matcher-redirected');
  assert.ok(ranked.length);
  assert.ok(ranked.every(candidate => candidate.match_evidence.every(signal => signal.kind !== 'sqli')));
  assert.ok(!ranked.some(candidate => candidate.playbook_id === 'web_sqli_verify'));
});

test('equally relevant candidates with complete inputs rank before blocked candidates', () => {
  insertCandidate('matcher-a-fixed', [['gobuster', ['dir', '-u', 'http://fixed.test/', '-w', '/wordlist']]]);
  insertCandidate('matcher-z-ready', [['gobuster', ['dir', '-u', '<target>', '-w', '/wordlist']]]);
  try {
    const ranked = matchPlaybooks([finding({ finding: 'Directory listing enabled' })], webProfile);
    const ready = ranked.findIndex(candidate => candidate.playbook_id === 'matcher-z-ready');
    const fixed = ranked.findIndex(candidate => candidate.playbook_id === 'matcher-a-fixed');
    assert.ok(ready >= 0 && fixed > ready);
    assert.equal(ranked[ready].match_score, ranked[fixed].match_score);
  } finally {
    removeCandidate('matcher-a-fixed');
    removeCandidate('matcher-z-ready');
  }
});
