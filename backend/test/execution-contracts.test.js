import test from 'node:test';
import assert from 'node:assert/strict';
import { renderCommand, replaceTargetPlaceholder } from '../src/services/commandTemplateRenderer.js';
import { classifyToolResult, normalizeToolArgs } from '../src/tools/toolContracts.js';
import { parseAction, parseReflection } from '../src/services/reactEngine.js';

test('missing local SAST image returns a deployment diagnosis rather than a generic tool exit', () => {
  const result=classifyToolResult('cppcheck',{exitCode:125,stderr:"Error response from daemon: No such image: rt-sast-c:latest"});
  assert.equal(result.success,false);
  assert.match(result.error,/rt-sast-c.*构建或导入/);
  assert.match(result.stderr,/No such image/);
});

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

test('runtime adjusted placeholders are resolved before unresolved-token checks', () => {
  const result = renderCommand(['dir', '-u', 'http://target:8765/.git/config', '-w', '{{wordlist_small}}'], {
    target_url: 'https://authorized.test:9443/', wordlist_small: '/usr/share/wordlists/course_web_dirs.txt',
  });
  assert.equal(result.rendered[2], 'https://authorized.test:9443/.git/config');
  assert.deepEqual(result.unresolvedTokens, []);
  assert.deepEqual(renderCommand(['http://target:8765/'], {}).unresolvedTokens, ['http://target:8765/']);
  assert.deepEqual(renderCommand(['{{unavailable}}'], { target_url: 'https://authorized.test/' }).unresolvedTokens, ['{{unavailable}}']);
  assert.equal(renderCommand(['https://outside.example/path'], { target_url: 'https://authorized.test/' }).rendered[0], 'https://outside.example/path');
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

for (const stdout of [
  'UPLOAD_RESULT: check server response above',
  'DVWA ready (session: fixture-session, login_ok: 0)',
  'FILE_TAMPER_FAILED: cannot write target file',
  'FATAL: Failed to get CSRF token',
  'VERIFIED: earlier check\nVERIFY_FAILED: Homepage not tampered',
]) test(`exit zero does not hide business failure: ${stdout.split(':')[0]}`, () => {
  const result = classifyToolResult('system-tools', { exitCode: 0, stdout, stderr: '' });
  assert.equal(result.success, false);
  assert.ok(result.error);
  assert.equal(result.stdout, stdout);
  assert.equal(result.exitCode, 0);
});

const loginPage = '<html><form action="login.php"><input name="password" type="password"></form></html>';
for (const [stdout, stderr] of [
  ['<html><title>404 Not Found</title><h1>Not Found</h1></html>', ''],
  ['<html><title>403 Forbidden</title></html>', ''],
  [loginPage, ''],
  ['--- request finished ---', 'curl: (7) Failed to connect'],
]) test(`HTTP shell failures survive successful final echo: ${stdout.slice(0, 30)}`, () => {
  const result = classifyToolResult('system-tools', { exitCode: 0, stdout, stderr }, {
    args: ['-c', 'curl -s -L -b /tmp/dvwa_jar.txt http://fixture.invalid/protected; echo done'],
  });
  assert.equal(result.success, false);
  assert.ok(result.error);
});

test('HTTP response checks stay scoped to requests and allow ordinary login-page discovery', () => {
  const errorPage = '<title>404 Not Found</title>';
  assert.equal(classifyToolResult('cat', { exitCode: 0, stdout: errorPage }).success, true);
  assert.equal(classifyToolResult('system-tools', { exitCode: 0, stdout: errorPage }, { args: ['-c', 'cat example.html'] }).success, true);
  assert.equal(classifyToolResult('curl', { exitCode: 0, stdout: loginPage }, { args: ['http://fixture.invalid/login.php'] }).success, true);
  assert.equal(classifyToolResult('curl', { exitCode: 0, stdout: loginPage }, { args: ['-b', '/tmp/jar', 'http://fixture.invalid/protected'] }).success, false);
  for (const url of ['http://fixture.invalid/login.php', '--url=https://fixture.invalid/app/signin?next=account'])
    assert.equal(classifyToolResult('curl', { exitCode: 0, stdout: loginPage }, { args: ['-b', '/tmp/jar', url] }).success, true);
  const passwordChange = '<form action="/change-password"><input name="password" type="password"></form>';
  assert.equal(classifyToolResult('curl', { exitCode: 0, stdout: passwordChange }, { args: ['-b', '/tmp/jar', 'http://fixture.invalid/account'] }).success, true);
  const profile = '<form action="/profile"><input name="username"><input name="password" type="password"></form>';
  assert.equal(classifyToolResult('curl', { exitCode: 0, stdout: profile }, { args: ['-b', '/tmp/jar', 'http://fixture.invalid/account'] }).success, true);
  assert.equal(classifyToolResult('curl', { exitCode: 0, stdout: errorPage }, { args: ['http://fixture.invalid/missing'] }).success, false);
  assert.equal(classifyToolResult('system-tools', { exitCode: 0, stdout: 'FILE_UPLOADED: fixture\nFILE_TAMPERED: fixture\nVERIFIED: fixture' }).success, true);
});
