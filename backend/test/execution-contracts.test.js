import test from 'node:test';
import assert from 'node:assert/strict';
import { replaceTargetPlaceholder } from '../src/services/commandTemplateRenderer.js';
import { classifyToolResult, normalizeToolArgs } from '../src/tools/toolContracts.js';
import { parseAction, parseReflection } from '../src/services/reactEngine.js';

test('embedded target placeholders use host and port, not a duplicated scheme', () => {
  assert.equal(replaceTargetPlaceholder('<target>', 'http://192.168.1.111:4280'), 'http://192.168.1.111:4280');
  assert.equal(replaceTargetPlaceholder('http://<target>/login.php', 'http://192.168.1.111:4280'), 'http://192.168.1.111:4280/login.php');
});

test('hydra target URL supplies the target port and preserves HTTPS mode', () => {
  const args = normalizeToolArgs('hydra', ['-l', 'admin', '-P', '/usr/share/wordlists/common_passwords.txt', '-s', '80', 'https://192.168.1.111:8443', 'http-post-form', '/login'], {
    projectRoot: process.cwd(), engine: 'docker',
  });
  assert.equal(args[args.indexOf('-s') + 1], '8443');
  assert.ok(args.includes('-S'));
  assert.ok(args.indexOf('-S') < args.indexOf('192.168.1.111'));
});

test('hydra places an inferred port option before the service descriptor', () => {
  const args = normalizeToolArgs('hydra', [
    '-l', 'admin', '-P', '/usr/share/wordlists/common_passwords.txt', '-t', '2', '-f',
    'http://192.168.1.111:4280', 'http-post-form', '/login.php:username=^USER^&password=^PASS^:F=Login failed',
  ], { projectRoot: process.cwd(), engine: 'docker' });
  assert.ok(args.indexOf('-s') < args.indexOf('192.168.1.111'));
  assert.equal(args[args.indexOf('-s') + 1], '4280');
});

test('legacy target URLs are rewritten into the run target scope', () => {
  const args = normalizeToolArgs('gobuster', ['dir', '-u', 'http://172.19.0.3:8088/'], {
    projectRoot: process.cwd(), engine: 'docker', target: 'http://192.168.1.111:8088',
  });
  assert.equal(args[args.indexOf('-u') + 1], 'http://192.168.1.111:8088/');
  assert.equal(replaceTargetPlaceholder('http://target:8765/install.php', 'http://192.168.1.111:8765'), 'http://192.168.1.111:8765/install.php');
});

test('nmap replaces fast scan when a target URL carries a non-default port', () => {
  const args = normalizeToolArgs('nmap', ['-sV', '-F', 'http://192.168.1.111:4280'], {
    projectRoot: process.cwd(), engine: 'docker',
  });
  assert.ok(!args.includes('-F'));
  assert.equal(args[args.indexOf('-p') + 1], '4280');
});

test('system tool business failures are not reported as successful exit 0', () => {
  const result = classifyToolResult('system-tools', { exitCode: 0, stdout: 'VERIFY_FAILED: Homepage not tampered', stderr: '' });
  assert.equal(result.success, false);
  assert.equal(result.error, 'Tool rejected input or requests failed');
});

test('unknown ReAct actions stop instead of silently continuing', () => {
  const result = parseAction('Observation: 收到未知动作\nThought: 控制流不明确\n<action type="manual_review" />');
  assert.equal(result.action, 'stop');
  assert.match(result.reason, /manual_review/);
});

test('review-only ReAct actions do not abort a playbook', () => {
  const result = parseAction('<action type="verify_scope" />');
  assert.equal(result.action, 'continue');
  assert.equal(result.ignoredAction, 'verify_scope');
});

test('reflection ignores review-only or unsupported pseudo-alternatives', () => {
  const result = parseReflection('<verdict>reconsider</verdict><action type="check_authorization" />');
  assert.equal(result.confirmed, true);
  assert.equal(result.alternative, null);
});

test('successful DVWA init output remains successful with exit code zero', () => {
  const result = classifyToolResult('system-tools', {
    exitCode: 0,
    stdout: '=== DVWA Init ===\nDVWA ready (session: session-id, login_ok: 1)',
    stderr: '',
  });
  assert.equal(result.success, true);
});
