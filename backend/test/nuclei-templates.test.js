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
  mkdirSync(join(templatesDir, 'http', 'default-logins'), { recursive: true });
  mkdirSync(binDir);
  writeFileSync(selectedPath, 'id: dvwa-default-login\ninfo:\n  name: DVWA\n');
  writeFileSync(unrelatedPath, 'id: unrelated-broken-template\ninvalid-required\n');
  const command = [
    `#!${process.execPath}`,
    "const fs = require('node:fs');",
    "const path = require('node:path');",
    'const args = process.argv.slice(2);',
    'fs.writeFileSync(process.env.NUCLEI_TEST_LOG, JSON.stringify(args));',
    "const selection = args[args.indexOf('-t') + 1];",
    "const mount = args.includes('-v') ? args[args.indexOf('-v') + 1].split(':')[0] : null;",
    "const files = selection.split(',').map(file => mount ? path.join(mount, path.relative('/root/nuclei-templates', file)) : file);",
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
  process.env.PATH = `${binDir}${delimiter}${previousPath || ''}`;
  process.env.NUCLEI_TEST_LOG = logPath;
  context.after(() => {
    if (previousPath === undefined) delete process.env.PATH;
    else process.env.PATH = previousPath;
    if (previousLog === undefined) delete process.env.NUCLEI_TEST_LOG;
    else process.env.NUCLEI_TEST_LOG = previousLog;
    rmSync(projectRoot, { recursive: true, force: true });
  });
  return { projectRoot, templatesDir, selectedPath, unrelatedPath, logPath };
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
