import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import {
  ensureNucleiTemplates,
  getRequiredNucleiTemplateIds,
  inspectNucleiTemplates,
  normalizeNucleiTemplateArgs,
  validateNucleiTemplates,
} from '../src/services/nucleiTemplates.js';

function createFixture(context) {
  const projectRoot = mkdtempSync(join(tmpdir(), 'redteam-nuclei-test-'));
  const templatesDir = join(projectRoot, 'data', 'nuclei-templates');
  const selectedPath = join(templatesDir, 'http', 'default-logins', 'dvwa.yaml');
  const unrelatedPath = join(templatesDir, 'http', 'unrelated.yaml');
  const binDir = join(projectRoot, 'bin');
  const logPath = join(projectRoot, 'command-log.json');
  const historyPath = `${logPath}.history`;
  mkdirSync(join(templatesDir, 'http', 'default-logins'), { recursive: true });
  mkdirSync(binDir);
  writeFileSync(selectedPath, 'id: dvwa-default-login\ninfo:\n  name: DVWA\n  severity: medium\n');
  writeFileSync(unrelatedPath, 'id: unrelated-broken-template\ninfo:\n  severity: low\ninvalid-required\n');
  const command = [
    `#!${process.execPath}`,
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    'const args = process.argv.slice(2);',
    'fs.writeFileSync(process.env.NUCLEI_TEST_LOG, JSON.stringify(args));',
    "fs.appendFileSync(process.env.NUCLEI_TEST_LOG + '.history', JSON.stringify(args) + '\\n');",
    "const selection = args[args.findIndex(arg => ['-t', '-templates', '-w', '-workflows'].includes(arg)) + 1];",
    "const mount = args.includes('-v') ? args[args.indexOf('-v') + 1].split(':')[0] : null;",
    "const root = mount || process.env.NUCLEI_TEST_ROOT;",
    "if (args.includes('-update-templates')) {",
    "  const directory = path.join(root, 'http', 'default-logins');",
    '  fs.mkdirSync(directory, { recursive: true });',
    "  fs.writeFileSync(path.join(directory, 'dvwa.yaml'), 'id: dvwa-default-login\\ninfo:\\n  severity: medium\\n');",
    '  process.exit(0);',
    '}',
    "const localPath = file => mount && (file === '/root/nuclei-templates' || file.startsWith('/root/nuclei-templates/')) ? path.join(mount, path.relative('/root/nuclei-templates', file)) : file;",
    "const expand = file => fs.statSync(file).isDirectory() ? fs.readdirSync(file).filter(name => !name.startsWith('.')).flatMap(name => expand(path.join(file, name))) : file.endsWith('.txt') ? fs.readFileSync(file, 'utf8').trim().split('\\n').map(localPath) : [file];",
    "let files = selection.split(',').map(localPath).flatMap(file => args.includes('-tl') || file.endsWith('.txt') ? expand(file) : [file]);",
    "if (args.includes('-tl')) {",
    "  const option = names => { const index = args.findIndex(arg => names.includes(arg)); return index < 0 ? null : args[index + 1].split(','); };",
    "  const severity = option(['-s', '-severity']);",
    "  const ids = option(['-id', '-template-id']);",
    "  const tags = option(['-tags']);",
    "  files = files.filter(file => { const text = fs.readFileSync(file, 'utf8'); return /\\.ya?ml$/.test(file) && (!severity || severity.includes(text.match(/severity:\\s*(\\w+)/)?.[1])) && (!ids || ids.includes(text.match(/^id:\\s*(\\S+)/m)?.[1])) && (!tags || tags.some(tag => text.match(/tags:\\s*(.*)/)?.[1].split(',').includes(tag))); });",
    "  console.log('Listing available  nuclei templates for ' + root);",
    "  console.log(files.map(file => path.relative(root, file)).join('\\n'));",
    '  process.exit(0);',
    '}',
    "if (files.some(file => fs.statSync(file).isDirectory() || fs.readFileSync(file, 'utf8').includes('invalid-required'))) {",
    "  console.error('selected template failed validation');",
    '  process.exit(1);',
    '}',
    '',
  ].join('\n');
  for (const engine of ['nuclei', 'docker', 'podman']) {
    writeFileSync(join(binDir, engine), command, { mode: 0o755 });
  }
  const previousPath = process.env.PATH;
  const previousLog = process.env.NUCLEI_TEST_LOG;
  const previousRoot = process.env.NUCLEI_TEST_ROOT;
  process.env.PATH = `${binDir}${delimiter}${previousPath || ''}`;
  process.env.NUCLEI_TEST_LOG = logPath;
  process.env.NUCLEI_TEST_ROOT = templatesDir;
  context.after(() => {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    if (previousLog === undefined) delete process.env.NUCLEI_TEST_LOG;
    else process.env.NUCLEI_TEST_LOG = previousLog;
    if (previousRoot === undefined) delete process.env.NUCLEI_TEST_ROOT;
    else process.env.NUCLEI_TEST_ROOT = previousRoot;
    rmSync(projectRoot, { recursive: true, force: true });
  });
  return { projectRoot, templatesDir, selectedPath, unrelatedPath, logPath, historyPath };
}

test('Nuclei IDs support separate and inline options with deduplication', () => {
  assert.deepEqual(getRequiredNucleiTemplateIds([
    '-id', 'dvwa-default-login,second-template', '--template-id=dvwa-default-login',
  ]), ['dvwa-default-login', 'second-template']);
});

test('template inspection resolves required IDs to concrete files', context => {
  const fixture = createFixture(context);
  const resources = inspectNucleiTemplates(fixture.projectRoot, ['dvwa-default-login']);
  assert.equal(resources.passed, true);
  assert.deepEqual(resources.templatePaths, [fixture.selectedPath]);
  assert.deepEqual(resources.missingIds, []);
});

test('missing required IDs do not silently fall back to unrelated templates', context => {
  const fixture = createFixture(context);
  const resources = inspectNucleiTemplates(fixture.projectRoot, ['missing-template']);
  assert.equal(resources.passed, false);
  assert.deepEqual(resources.templatePaths, []);
  assert.deepEqual(resources.missingIds, ['missing-template']);
});

for (const engine of ['host', 'docker', 'podman']) {
  test(`${engine} validation ignores broken templates outside the required IDs`, async context => {
    const fixture = createFixture(context);
    const resources = await ensureNucleiTemplates({
      projectRoot: fixture.projectRoot, engine, requiredIds: ['dvwa-default-login'],
    });
    assert.equal(resources.passed, true);
    const command = JSON.parse(readFileSync(fixture.logPath, 'utf8'));
    const expectedPath = engine === 'host'
      ? fixture.selectedPath : '/root/nuclei-templates/http/default-logins/dvwa.yaml';
    assert.equal(command[command.indexOf('-t') + 1], expectedPath);
    assert.ok(command.includes('-validate'));
  });
}

test('required template compilation errors still block execution', async context => {
  const fixture = createFixture(context);
  writeFileSync(fixture.selectedPath, 'id: dvwa-default-login\ninvalid-required\n');
  await assert.rejects(ensureNucleiTemplates({
    projectRoot: fixture.projectRoot, engine: 'host', requiredIds: ['dvwa-default-login'],
  }), /Nuclei template validation failed:.*selected template failed validation/);
});

test('all requested template IDs are validated, not just the first', async context => {
  const fixture = createFixture(context);
  await assert.rejects(ensureNucleiTemplates({
    projectRoot: fixture.projectRoot, engine: 'docker',
    requiredIds: ['dvwa-default-login', 'unrelated-broken-template'],
  }), /Nuclei template validation failed/);
  const command = JSON.parse(readFileSync(fixture.logPath, 'utf8'));
  assert.deepEqual(command[command.indexOf('-t') + 1].split(',').sort(), [
    '/root/nuclei-templates/http/default-logins/dvwa.yaml',
    '/root/nuclei-templates/http/unrelated.yaml',
  ]);
});

test('unrestricted scans retain whole-library validation', async context => {
  const fixture = createFixture(context);
  await assert.rejects(validateNucleiTemplates(fixture.templatesDir, 'host'), /Nuclei template validation failed/);
  const command = JSON.parse(readFileSync(fixture.logPath, 'utf8'));
  assert.equal(command[command.indexOf('-t') + 1], fixture.templatesDir);
});

test('execution uses the same concrete template paths as preflight', context => {
  const fixture = createFixture(context);
  const args = ['-u', 'http://192.168.1.111:4280', '-id', 'dvwa-default-login'];
  const normalized = normalizeNucleiTemplateArgs(args, fixture.templatesDir, 'docker', [fixture.selectedPath]);
  assert.equal(normalized[normalized.indexOf('-t') + 1], '/root/nuclei-templates/http/default-logins/dvwa.yaml');
  assert.ok(normalized.includes('-duc'));
  assert.ok(!args.includes('-t'));
  const hostArgs = normalizeNucleiTemplateArgs(args, fixture.templatesDir, 'host', [fixture.selectedPath]);
  assert.equal(hostArgs[hostArgs.indexOf('-t') + 1], fixture.selectedPath);
});

test('explicit template selections and update-check options are preserved', context => {
  const fixture = createFixture(context);
  const args = ['-t', '/root/nuclei-templates/http/custom.yaml', '-duc'];
  assert.deepEqual(normalizeNucleiTemplateArgs(args, fixture.templatesDir, 'docker', [fixture.selectedPath]), args);
  assert.deepEqual(normalizeNucleiTemplateArgs(args, fixture.templatesDir, 'host', [fixture.selectedPath]), [
    '-t', join(fixture.templatesDir, 'http', 'custom.yaml'), '-duc',
  ]);
});

for (const engine of ['host', 'docker', 'podman']) {
  test(`${engine} generic scans validate only templates selected by severity`, async context => {
    const fixture = createFixture(context);
    const args = ['-u', 'http://192.168.1.111:8765', '-severity', 'medium,high,critical'];
    const resources = await ensureNucleiTemplates({ projectRoot: fixture.projectRoot, engine, args });
    assert.deepEqual(resources.templatePaths, [fixture.selectedPath]);
    assert.equal(resources.selectionResolved, true);
    const commands = readFileSync(fixture.historyPath, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    assert.ok(commands[0].includes('-tl'));
    assert.ok(commands[0].includes('-severity'));
    assert.ok(!commands[0].includes('-u'));
    assert.ok(commands[1].includes('-validate'));
    const normalized = normalizeNucleiTemplateArgs(args, resources.templatesDir, engine, resources.templatePaths, resources.selectionResolved);
    assert.equal(normalized[normalized.indexOf('-t') + 1], commands[1][commands[1].indexOf('-t') + 1]);
  });
}

test('inline severity, tags and protocol switches reach template selection', async context => {
  const fixture = createFixture(context);
  writeFileSync(fixture.selectedPath, 'id: dvwa-default-login\ninfo:\n  severity: medium\n  tags: dvwa,login\n');
  await ensureNucleiTemplates({ projectRoot: fixture.projectRoot, engine: 'host', args: [
    '--severity=medium', '-tags', 'dvwa', '-pt', 'http', '-code', '-u', 'http://example.test',
  ] });
  const commands = readFileSync(fixture.historyPath, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(commands[0].includes('medium'));
  assert.ok(commands[0].includes('dvwa'));
  assert.ok(commands[0].includes('http'));
  assert.ok(commands.every(command => command.includes('-code')));
});

test('broken templates inside a generic scan selection remain blocking', async context => {
  const fixture = createFixture(context);
  await assert.rejects(ensureNucleiTemplates({ projectRoot: fixture.projectRoot, engine: 'host', args: ['-severity', 'low'] }), /Nuclei template validation failed/);
});

test('empty selections fail instead of falling back to the whole library', async context => {
  const fixture = createFixture(context);
  await assert.rejects(ensureNucleiTemplates({ projectRoot: fixture.projectRoot, engine: 'host', args: ['-severity', 'critical'] }), /No Nuclei templates match/);
});

test('explicit paths constrain preflight and execution to the same selection', async context => {
  const fixture = createFixture(context);
  const args = ['--templates=/root/nuclei-templates/http/default-logins', '-severity', 'medium'];
  const resources = await ensureNucleiTemplates({ projectRoot: fixture.projectRoot, engine: 'docker', args });
  assert.deepEqual(resources.templatePaths, [fixture.selectedPath]);
  const normalized = normalizeNucleiTemplateArgs(args, resources.templatesDir, 'docker', resources.templatePaths, true);
  assert.ok(!normalized.includes(args[0]));
  assert.equal(normalized[normalized.indexOf('-t') + 1], '/root/nuclei-templates/http/default-logins/dvwa.yaml');
});

test('missing selection option values fail closed', async context => {
  const fixture = createFixture(context);
  await assert.rejects(ensureNucleiTemplates({ projectRoot: fixture.projectRoot, engine: 'host', args: ['-severity'] }), /Missing value/);
});

test('explicit required IDs cannot hide compilation failures behind severity filters', async context => {
  const fixture = createFixture(context);
  await assert.rejects(ensureNucleiTemplates({ projectRoot: fixture.projectRoot, engine: 'host',
    requiredIds: ['unrelated-broken-template'], args: ['-id', 'unrelated-broken-template', '-severity', 'medium'],
  }), /Nuclei template validation failed/);
});

test('resolved empty execution selections cannot fall back to the whole library', context => {
  const fixture = createFixture(context);
  assert.throws(() => normalizeNucleiTemplateArgs([], fixture.templatesDir, 'host', [], true), /cannot be empty/);
});

test('metadata-only listings cannot enable code, headless, file, self-contained or fuzzing templates', async context => {
  const fixture = createFixture(context);
  for (const [name, capability] of [['code', 'code:\n'], ['headless', 'headless:\n'], ['file', 'file:\n'],
    ['self-contained', 'self-contained: true\n'], ['global-matchers', 'global-matchers: true\n'], ['dast', 'http:\n  - fuzzing:\n']]) {
    writeFileSync(join(fixture.templatesDir, 'http', `${name}.yaml`), `id: ${name}\ninfo:\n  severity: medium\n${capability}`);
  }
  const resources = await ensureNucleiTemplates({ projectRoot: fixture.projectRoot, engine: 'host', args: ['-severity', 'medium'] });
  assert.deepEqual(resources.templatePaths, [fixture.selectedPath]);
  const commands = readFileSync(fixture.historyPath, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(commands[0].includes('code,headless,file'));
});

test('explicit capability switches retain opted-in templates and validation flags', async context => {
  const fixture = createFixture(context);
  const codeDirectory = join(fixture.templatesDir, 'code');
  mkdirSync(codeDirectory);
  const selectedPath = join(codeDirectory, 'selected-code.yaml');
  writeFileSync(selectedPath, 'id: selected-code\ninfo:\n  severity: high\nself-contained: true\ncode:\n');
  const resources = await ensureNucleiTemplates({ projectRoot: fixture.projectRoot, engine: 'host',
    args: ['-severity', 'high', '-code', '-esc'] });
  assert.deepEqual(resources.templatePaths, [selectedPath]);
  const commands = readFileSync(fixture.historyPath, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  assert.ok(commands.every(command => command.includes('-code') && command.includes('-esc')));
});

test('container template downloads use the backend UID and writable home', async context => {
  const fixture = createFixture(context);
  rmSync(fixture.selectedPath);
  const resources = await ensureNucleiTemplates({ projectRoot: fixture.projectRoot, engine: 'docker', requiredIds: ['dvwa-default-login'] });
  assert.equal(resources.passed, true);
  const commands = readFileSync(fixture.historyPath, 'utf8').trim().split('\n').map(line => JSON.parse(line));
  const update = commands.find(command => command.includes('-update-templates'));
  assert.equal(update[update.indexOf('--user') + 1], `${process.getuid?.() ?? 0}:${process.getgid?.() ?? 0}`);
  assert.ok(update.includes('HOME=/tmp'));
});

test('large selections use identical manifest paths for validation and execution', async context => {
  const fixture = createFixture(context);
  for (let index = 0; index < 350; index++) {
    writeFileSync(join(fixture.templatesDir, 'http', `template-with-long-name-${index}.yaml`), `id: template-${index}\ninfo:\n  severity: high\n`);
  }
  const args = ['-severity', 'high'];
  const resources = await ensureNucleiTemplates({ projectRoot: fixture.projectRoot, engine: 'docker', args });
  assert.equal(resources.templatePaths.length, 350);
  const command = JSON.parse(readFileSync(fixture.logPath, 'utf8'));
  const selection = command[command.indexOf('-t') + 1];
  assert.match(selection, /\.redteam-selections\/.*\.txt$/);
  const normalized = normalizeNucleiTemplateArgs(args, resources.templatesDir, 'docker', resources.templatePaths, true);
  assert.equal(normalized[normalized.indexOf('-t') + 1], selection);
  const manifest = join(fixture.templatesDir, selection.replace('/root/nuclei-templates/', ''));
  assert.equal(readFileSync(manifest, 'utf8').trim().split('\n').length, 350);
});
