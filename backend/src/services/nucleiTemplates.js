import { execFile, spawn } from 'child_process';
import { mkdirSync, readdirSync, readFileSync } from 'fs';
import { join } from 'path';
import { randomUUID } from 'crypto';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);
const pendingUpdates = new Map();
const CONTAINER_TEMPLATES_DIR = '/root/nuclei-templates';
const TEMPLATE_COMMAND_TIMEOUT = 120_000;

export function getRequiredNucleiTemplateIds(args = []) {
  if (!Array.isArray(args)) return [];
  const requiredIds = new Set();
  for (let index = 0; index < args.length; index++) {
    const match = String(args[index]).match(/^--?(?:id|template-id)(?:=(.*))?$/);
    if (!match) continue;
    const value = match[1] ?? args[++index];
    for (const templateId of String(value || '').split(',')) {
      if (/^[\w.-]+$/.test(templateId.trim())) requiredIds.add(templateId.trim());
    }
  }
  return [...requiredIds];
}

export function inspectNucleiTemplates(projectRoot, requiredIds = []) {
  const templatesDir = join(projectRoot, 'data', 'nuclei-templates');
  const directories = [templatesDir];
  const missingIds = new Set(requiredIds);
  let available = false;
  while (directories.length > 0) {
    const directory = directories.pop();
    let entries;
    try {
      entries = readdirSync(directory, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      const filePath = join(directory, entry.name);
      if (entry.isDirectory()) {
        directories.push(filePath);
      } else if (entry.isFile() && /\.ya?ml$/i.test(entry.name)) {
        try {
          const templateId = readFileSync(filePath, 'utf8').match(/^(?:\uFEFF)?id:\s*["']?([\w.-]+)["']?\s*(?:#.*)?$/m)?.[1];
          if (!templateId) continue;
          available = true;
          missingIds.delete(templateId);
          if (missingIds.size === 0) {
            return { passed: true, available, templatesDir, missingIds: [], message: `Readable Nuclei templates available: ${templatesDir}${requiredIds.length ? `; required IDs: ${requiredIds.join(', ')}` : ''}` };
          }
        } catch {}
      }
    }
  }
  return {
    passed: false, available, templatesDir, missingIds: [...missingIds],
    message: available
      ? `Required Nuclei template IDs not found: ${[...missingIds].join(', ')}; directory: ${templatesDir}`
      : `No readable Nuclei YAML templates found: ${templatesDir}`,
  };
}

async function downloadNucleiTemplates(templatesDir, engine) {
  mkdirSync(templatesDir, { recursive: true });
  if (engine === 'host') {
    await execFileAsync('nuclei', ['-update-templates', '-ud', templatesDir], { timeout: TEMPLATE_COMMAND_TIMEOUT });
    return;
  }
  const containerName = `rt-nuclei-templates-${randomUUID()}`;
  try {
    await execFileAsync(engine, [
      'run', '--rm', '--name', containerName,
      '-v', `${templatesDir}:${CONTAINER_TEMPLATES_DIR}`, 'rt-vuln-scan',
      'nuclei', '-update-templates', '-ud', CONTAINER_TEMPLATES_DIR,
    ], { timeout: TEMPLATE_COMMAND_TIMEOUT });
  } catch (error) {
    await execFileAsync(engine, ['rm', '-f', containerName], { timeout: 10_000 }).catch(() => {});
    throw error;
  }
}

function commandErrorMessage(error) {
  return [error?.stderr, error?.stdout, error?.message]
    .filter(Boolean)
    .join('\n')
    .trim()
    .replace(/\s+/g, ' ')
    .slice(0, 2000);
}

function runNucleiValidation(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    let settled = false;
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      settled = true;
      const error = new Error(`command timed out after ${TEMPLATE_COMMAND_TIMEOUT}ms`);
      error.stdout = stdout;
      error.stderr = stderr;
      reject(error);
    }, TEMPLATE_COMMAND_TIMEOUT);
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve();
    };
    child.once('error', finish);
    child.once('close', (code, signal) => {
      if (code === 0) finish();
      else {
        const error = new Error(`process exited with ${signal || `code ${code}`}`);
        error.stdout = stdout;
        error.stderr = stderr;
        finish(error);
      }
    });
  });
}

export async function validateNucleiTemplates(templatesDir, engine) {
  try {
    if (engine === 'host') {
      await runNucleiValidation('nuclei', [
        '-validate', '-duc', '-no-color', '-t', templatesDir,
      ]);
      return;
    }
    if (!['docker', 'podman'].includes(engine)) {
      throw new Error(`Unsupported Nuclei execution engine: ${engine || 'unknown'}`);
    }
    await runNucleiValidation(engine, [
      'run', '--rm',
      '-v', `${templatesDir}:${CONTAINER_TEMPLATES_DIR}`,
      'rt-vuln-scan', 'nuclei',
      '-validate', '-duc', '-no-color', '-t', CONTAINER_TEMPLATES_DIR,
    ]);
  } catch (error) {
    throw new Error(`Nuclei template validation failed: ${commandErrorMessage(error)}`);
  }
}

async function waitForUpdate(update, signal) {
  if (!signal) return update;
  signal.throwIfAborted();
  let onAbort;
  const aborted = new Promise((resolveUpdate, rejectUpdate) => {
    onAbort = () => rejectUpdate(signal.reason || new Error('Nuclei template preparation aborted'));
    signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    return await Promise.race([update, aborted]);
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

export async function ensureNucleiTemplates({ projectRoot, engine, requiredIds = [], signal }) {
  signal?.throwIfAborted();
  let resources = inspectNucleiTemplates(projectRoot, requiredIds);
  if (resources.passed) {
    await validateNucleiTemplates(resources.templatesDir, engine);
    return resources;
  }
  if (!['host', 'docker', 'podman'].includes(engine)) throw new Error(`${resources.message}; execution engine unavailable`);
  let update = pendingUpdates.get(resources.templatesDir);
  if (!update) {
    update = downloadNucleiTemplates(resources.templatesDir, engine);
    pendingUpdates.set(resources.templatesDir, update);
    update.then(() => pendingUpdates.delete(resources.templatesDir), () => pendingUpdates.delete(resources.templatesDir));
  }
  try {
    await waitForUpdate(update, signal);
  } catch (error) {
    throw new Error(`Nuclei template preparation failed: ${error.message}`);
  }
  signal?.throwIfAborted();
  resources = inspectNucleiTemplates(projectRoot, requiredIds);
  if (!resources.passed) throw new Error(resources.message);
  await validateNucleiTemplates(resources.templatesDir, engine);
  return resources;
}

export function normalizeNucleiTemplateArgs(args, templatesDir, engine) {
  const normalized = args.map(argument => engine === 'host' && (argument === CONTAINER_TEMPLATES_DIR || argument.startsWith(`${CONTAINER_TEMPLATES_DIR}/`))
    ? `${templatesDir}${argument.slice(CONTAINER_TEMPLATES_DIR.length)}` : argument);
  if (!normalized.some(argument => /^--?(?:t|templates|w|workflows)(?:=|$)/.test(argument))) {
    normalized.push('-t', engine === 'host' ? templatesDir : CONTAINER_TEMPLATES_DIR);
  }
  if (!normalized.some(argument => /^--?(?:duc|disable-update-check)(?:=|$)/.test(argument))) {
    normalized.push('-duc');
  }
  return normalized;
}
