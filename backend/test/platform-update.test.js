import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';

const updater = readFileSync(new URL('../../scripts/auto-update-platform.sh', import.meta.url), 'utf8');
const manifestCheck = updater.match(/dependencies_changed=\$\([^\n]*<<'JS'\n([\s\S]*?)\nJS\n  \)/)?.[1];
assert.ok(manifestCheck);

function compareManifests(previous, candidate) {
  const directory = mkdtempSync(join(tmpdir(), 'redteam-updater-test-'));
  try {
    writeFileSync(join(directory, 'previous.json'), JSON.stringify(previous));
    writeFileSync(join(directory, 'candidate.json'), JSON.stringify(candidate));
    writeFileSync(join(directory, 'git'), [
      '#!/bin/sh',
      'case "$2" in',
      '  previous:backend/package.json) cat "$MANIFESTS_DIR/previous.json" ;;',
      '  candidate:backend/package.json) cat "$MANIFESTS_DIR/candidate.json" ;;',
      '  *) exit 1 ;;',
      'esac',
      '',
    ].join('\n'), { mode: 0o755 });
    return execFileSync(process.execPath, ['--input-type=module', '-', 'previous', 'candidate'], {
      input: manifestCheck,
      encoding: 'utf8',
      env: { ...process.env, MANIFESTS_DIR: directory, PATH: `${directory}${delimiter}${process.env.PATH}` },
    }).trim();
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

const manifest = {
  name: 'redteam-backend',
  version: '0.1.0',
  type: 'module',
  scripts: { start: 'node src/server.js' },
  dependencies: { 'better-sqlite3': '^11.7.0', bcrypt: '^6.0.0' },
  engines: { node: '>=18' },
};

test('adding test commands does not reinstall unchanged dependencies', () => {
  assert.equal(compareManifests(manifest, {
    ...manifest,
    scripts: { ...manifest.scripts, 'test:topology': 'node --test test/topology.test.js' },
  }), '0');
});

test('dependency key order does not trigger reinstallation', () => {
  assert.equal(compareManifests(manifest, {
    ...manifest, dependencies: { bcrypt: '^6.0.0', 'better-sqlite3': '^11.7.0' },
  }), '0');
});

test('dependency changes trigger reinstallation', () => {
  assert.equal(compareManifests(manifest, {
    ...manifest, dependencies: { ...manifest.dependencies, bcrypt: '^6.1.0' },
  }), '1');
});

test('installation lifecycle changes trigger reinstallation', () => {
  assert.equal(compareManifests(manifest, {
    ...manifest, scripts: { ...manifest.scripts, postinstall: 'node prepare.js' },
  }), '1');
});

test('engine and package override changes trigger reinstallation', () => {
  assert.equal(compareManifests(manifest, { ...manifest, engines: { node: '>=22' } }), '1');
  assert.equal(compareManifests(manifest, { ...manifest, overrides: { bcrypt: '6.0.0' } }), '1');
});

test('lockfile changes and missing modules still trigger installation', () => {
  assert.match(updater, /git diff --quiet "\$previous" "\$candidate" -- backend\/package-lock\.json; then\n    dependencies_changed=1/);
  assert.match(updater, /"\$dependencies_changed" = 1 \] \|\| \[ ! -d "\$PROJECT_DIR\/backend\/node_modules" \]/);
});

test('installation failure returns before production service changes', () => {
  assert.match(updater, /if ! \(cd "\$stage\/backend" && npm ci[^\n]*\); then\n      log [^\n]*\n      return 1\n    fi/);
});

test('dependency resolution and native bindings are checked before activation', () => {
  const nativeCheck = updater.indexOf("const database = new Database(':memory:')");
  const dependencyCheck = updater.indexOf('require.resolve(dependency)');
  const bcryptCheck = updater.indexOf('bcrypt.compareSync');
  const activate = updater.indexOf('sudo -n systemctl stop "$BACKEND_SERVICE"', updater.indexOf("bcrypt.compareSync"));
  assert.ok(dependencyCheck > 0 && nativeCheck > dependencyCheck);
  assert.ok(bcryptCheck > nativeCheck && activate > bcryptCheck);
});
