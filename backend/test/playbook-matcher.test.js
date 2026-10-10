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

const db = getDb(':memory:');
schema(db);
importPlaybooks(db);
after(closeDb);

const webProfile = { target_class: 'web_url', application: null };
const dvwaProfile = { target_class: 'dvwa', application: { name: 'dvwa', confidence: 0.95 } };
const finding = (data, overrides = {}) => ({ result_type: 'vulnerability', severity: 'high',
  result_data: JSON.stringify(data), source_tool: 'nuclei', ...overrides });

test('configuration findings prefer dedicated scans over generic exploitation', () => {
  const results = [finding({ finding: 'The anti-clickjacking X-Frame-Options header is not present.' },
    { result_type: 'web_vuln', severity: 'medium', source_tool: 'nikto' })];
  const ranked = matchPlaybooks(results, webProfile);
  assert.equal(ranked[0].playbook_id, 'vuln_template_nuclei');
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
  const ranked = matchPlaybooks([finding({ template: 'reflected-xss' })], webProfile);
  assert.ok(ranked.length);
  assert.ok(!ranked.some(item => ['web_file_upload_exploit', 'vuln_template_nuclei'].includes(item.playbook_id)));
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
  assert.ok(ranked.every(item => item.baseline_group === 'recon'));
  assert.ok(!ranked.some(item => item.playbook_id === 'web_vuln_exploit'));
});

test('DVWA-specific steps require confirmed application evidence', () => {
  const results = [finding({}, { result_type: 'sql_injection' })];
  for (const profile of [webProfile, 'dvwa', { ...dvwaProfile, application: { name: 'dvwa', confidence: 0.5 } }]) {
    assert.ok(!matchPlaybooks(results, profile).some(item => item.playbook_id === 'sqli_exploit_sqlmap_basic'));
  }
  const ranked = matchPlaybooks(results, dvwaProfile);
  assert.equal(ranked[0].playbook_id, 'sqli_exploit_sqlmap_basic');
  assert.match(ranked[0].match_reason, /扫描指纹确认 DVWA/);
  const credentials = matchPlaybooks([finding({}, { result_type: 'credential' })], webProfile);
  assert.ok(!credentials.some(item => item.playbook_id === 'brute_force_hydra'));
  const session = matchPlaybooks([finding({}, { mitre_technique_id: 'T1539' })], webProfile);
  assert.ok(!session.some(item => item.playbook_id === 'session_hijacking_basic'));
});

test('generic steps are usable despite legacy DVWA metadata', () => {
  const result = finding({ finding: 'Missing HSTS header' }, { severity: 'medium' });
  const ranked = matchPlaybooks([result], webProfile);
  assert.equal(ranked[0].playbook_id, 'vuln_template_nuclei');
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
    const expectedProfile = buildDiscoveredProfile('http://192.168.1.111:4280', [probe, injection]);
    assert.deepEqual(data, matchPlaybooks([probe, injection], expectedProfile));
    assert.equal(data[0].playbook_id, 'sqli_exploit_sqlmap_basic');
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});

test('recommendation table displays numeric scores and defaults to descending score order', () => {
  const source = readFileSync(new URL('../../frontend/src/pages/ScanPage.cpp', import.meta.url), 'utf8');
  assert.match(source, /scoreItem->setData\(Qt::DisplayRole, r\["match_score"\]\.toDouble\(\)\)/);
  assert.match(source, /m_recTable->sortItems\(4, Qt::DescendingOrder\)/);
});
