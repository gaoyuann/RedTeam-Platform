import { execFile, spawn } from 'child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, renameSync, writeFileSync } from 'fs';
import { isAbsolute, join, relative } from 'path';
import { createHash, randomUUID } from 'crypto';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);
const pendingUpdates = new Map();
const CONTAINER_TEMPLATES_DIR = '/root/nuclei-templates';
const TEMPLATE_COMMAND_TIMEOUT = 120_000;
const SELECTION_VALUE_OPTIONS = new Set([
  't', 'templates', 'w', 'workflows', 'a', 'author', 'tags', 'etags', 'exclude-tags',
  'itags', 'include-tags', 'id', 'template-id', 'eid', 'exclude-id',
  'it', 'include-templates', 'et', 'exclude-templates', 's', 'severity',
  'es', 'exclude-severity', 'pt', 'type', 'ept', 'exclude-type', 'tc', 'template-condition',
]);
const SELECTION_SWITCH_OPTIONS = new Set([
  'code', 'headless', 'file', 'esc', 'enable-self-contained', 'egm', 'enable-global-matchers',
  'dut', 'disable-unsigned-templates',
  'dast', 'fuzz',
]);
const PATH_OPTIONS = new Set(['t', 'templates', 'w', 'workflows', 'it', 'include-templates', 'et', 'exclude-templates']);

function selectionOptions(args, templatesDir, engine) {
  const selected = [];
  for (let index = 0; index < args.length; index++) {
    const match = String(args[index]).match(/^--?([^=]+)(?:=(.*))?$/);
    if (!match) continue;
    const [, option, inlineValue] = match;
    if (SELECTION_SWITCH_OPTIONS.has(option)) {
      selected.push(args[index]);
    } else if (SELECTION_VALUE_OPTIONS.has(option)) {
      let value = inlineValue ?? args[++index];
      if (value === undefined || String(value).startsWith('-')) throw new Error(`Missing value for Nuclei option ${option}`);
      if (PATH_OPTIONS.has(option)) {
        value = String(value).split(',').map(filePath => {
          if (engine === 'host' && filePath.startsWith(CONTAINER_TEMPLATES_DIR)) {
            return `${templatesDir}${filePath.slice(CONTAINER_TEMPLATES_DIR.length)}`;
          }
          if (engine !== 'host' && (filePath === templatesDir || filePath.startsWith(`${templatesDir}/`))) {
            return `${CONTAINER_TEMPLATES_DIR}${filePath.slice(templatesDir.length)}`;
          }
          return filePath;
        }).join(',');
      }
      selected.push(`-${option}`, String(value));
    }
  }
  return selected;
}

function nucleiCommand(engine, templatesDir, args) {
  if (engine === 'host') return ['nuclei', args];
  if (!['docker', 'podman'].includes(engine)) throw new Error(`Unsupported Nuclei execution engine: ${engine || 'unknown'}`);
  return [engine, ['run', '--rm', '-v', `${templatesDir}:${CONTAINER_TEMPLATES_DIR}`, 'rt-vuln-scan', 'nuclei', ...args]];
}

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
  const templatePaths = new Map();
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
          if (missingIds.has(templateId)) templatePaths.set(templateId, filePath);
          missingIds.delete(templateId);
          if (missingIds.size === 0) {
            return { passed: true, available, templatesDir, templatePaths: [...templatePaths.values()], missingIds: [], message: `Readable Nuclei templates available: ${templatesDir}${requiredIds.length ? `; required IDs: ${requiredIds.join(', ')}` : ''}` };
          }
        } catch {}
      }
    }
  }
  return {
    passed: false, available, templatesDir, templatePaths: [...templatePaths.values()], missingIds: [...missingIds],
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
      '--user', `${process.getuid?.() ?? 0}:${process.getgid?.() ?? 0}`,
      '-e', 'HOME=/tmp',
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
      else resolve(stdout);
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

function getNucleiTemplateSelection(templatesDir, engine, templatePaths) {
  const selectedPaths = templatePaths.length ? templatePaths : [templatesDir];
  const paths = selectedPaths.map(filePath => engine === 'host'
    ? filePath : join(CONTAINER_TEMPLATES_DIR, relative(templatesDir, filePath)));
  const selection = paths.join(',');
  if (Buffer.byteLength(selection) < 16_000) return selection;
  const digest = createHash('sha256').update(paths.join('\n')).digest('hex');
  const directory = join(templatesDir, '.redteam-selections');
  const manifest = join(directory, `${digest}.txt`);
  mkdirSync(directory, { recursive: true });
  const temporary = `${manifest}.${randomUUID()}.tmp`;
  writeFileSync(temporary, `${paths.join('\n')}\n`);
  renameSync(temporary, manifest);
  return engine === 'host' ? manifest : join(CONTAINER_TEMPLATES_DIR, relative(templatesDir, manifest));
}

async function resolveNucleiTemplatePaths(templatesDir, engine, args) {
  const options = selectionOptions(args, templatesDir, engine);
  const enabled = new Set(options.filter(option => option.startsWith('-') && !/=(?:false|0)$/.test(option)).map(option => option.replace(/^--?/, '').split('=')[0]));
  const disabledProtocols = ['code', 'headless', 'file'].filter(protocol => !enabled.has(protocol));
  if (disabledProtocols.length) options.push('-ept', disabledProtocols.join(','));
  if (!options.some(option => /^-(?:t|templates|w|workflows)$/.test(option))) {
    options.push('-t', engine === 'host' ? templatesDir : CONTAINER_TEMPLATES_DIR);
  }
  try {
    const [command, commandArgs] = nucleiCommand(engine, templatesDir, ['-tl', '-silent', '-duc', '-no-color', ...options]);
    const output = await runNucleiValidation(command, commandArgs);
    const paths = [...new Set(output.split(/\r?\n/).map(line => line.trim())
      .filter(line => line && !/^Listing available\s+nuclei templates for /.test(line)).map(filePath => {
      const hostPath = filePath.startsWith(`${CONTAINER_TEMPLATES_DIR}/`)
        ? join(templatesDir, relative(CONTAINER_TEMPLATES_DIR, filePath))
        : isAbsolute(filePath) ? filePath : join(templatesDir, filePath);
      const location = relative(templatesDir, hostPath);
      if (location.startsWith('../') || isAbsolute(location) || !/\.ya?ml$/i.test(hostPath)) {
        throw new Error(`Selected Nuclei template is outside the mounted library or unavailable: ${filePath}`);
      }
      const category = location.split('/')[0];
      if (disabledProtocols.includes(category)) return null;
      if (category === 'dast' && !enabled.has('dast') && !enabled.has('fuzz')) return null;
      if (category === 'cloud' && !enabled.has('esc') && !enabled.has('enable-self-contained')) return null;
      if (!existsSync(hostPath)) throw new Error(`Selected Nuclei template is unavailable: ${filePath}`);
      return hostPath;
    }).filter(Boolean))].filter(filePath => {
      const content = readFileSync(filePath, 'utf8');
      if (disabledProtocols.some(protocol => new RegExp(`^${protocol}:`, 'm').test(content))) return false;
      if (!enabled.has('esc') && !enabled.has('enable-self-contained') && /^\s*(?:-\s*)?self-contained:\s*true\b/im.test(content)) return false;
      if (!enabled.has('egm') && !enabled.has('enable-global-matchers') && /^\s*(?:-\s*)?global-matchers:\s*true\b/im.test(content)) return false;
      return enabled.has('dast') || enabled.has('fuzz') || !/^\s+(?:-\s*)?fuzzing:/m.test(content);
    }).sort();
    if (paths.length === 0) throw new Error('No Nuclei templates match the requested selection');
    return paths;
  } catch (error) {
    throw new Error(`Nuclei template selection failed: ${commandErrorMessage(error)}`);
  }
}

export async function validateNucleiTemplates(templatesDir, engine, templatePaths = [], args = []) {
  const selection = getNucleiTemplateSelection(templatesDir, engine, templatePaths);
  try {
    const switches = selectionOptions(args, templatesDir, engine).filter(option => SELECTION_SWITCH_OPTIONS.has(option.replace(/^--?/, '').split('=')[0]));
    const [command, commandArgs] = nucleiCommand(engine, templatesDir, ['-validate', '-duc', '-no-color', '-t', selection, ...switches]);
    await runNucleiValidation(command, commandArgs);
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

export async function ensureNucleiTemplates({ projectRoot, engine, requiredIds = [], args, signal }) {
  signal?.throwIfAborted();
  let resources = inspectNucleiTemplates(projectRoot, requiredIds);
  if (resources.passed) {
    return prepareNucleiSelection(resources, engine, args, signal);
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
  return prepareNucleiSelection(resources, engine, args, signal);
}

async function prepareNucleiSelection(resources, engine, args, signal) {
  if (args !== undefined && resources.templatePaths.length > 0) {
    await validateNucleiTemplates(resources.templatesDir, engine, resources.templatePaths, args);
    signal?.throwIfAborted();
  }
  const templatePaths = args === undefined ? resources.templatePaths : await resolveNucleiTemplatePaths(resources.templatesDir, engine, args);
  signal?.throwIfAborted();
  await validateNucleiTemplates(resources.templatesDir, engine, templatePaths, args);
  signal?.throwIfAborted();
  return { ...resources, templatePaths, selectionResolved: args !== undefined,
    message: `${resources.message}; validated templates: ${templatePaths.length || 'whole library'}` };
}

export function normalizeNucleiTemplateArgs(args, templatesDir, engine, templatePaths = [], selectionResolved = false) {
  if (selectionResolved && templatePaths.length === 0) throw new Error('Resolved Nuclei template selection cannot be empty');
  const selectedArgs = selectionResolved ? args.filter((argument, index) => {
    if (/^--?(?:t|templates|w|workflows)(?:=|$)/.test(argument)) return false;
    return index === 0 || !/^--?(?:t|templates|w|workflows)$/.test(args[index - 1]);
  }) : args;
  const normalized = selectedArgs.map(argument => engine === 'host' && (argument === CONTAINER_TEMPLATES_DIR || argument.startsWith(`${CONTAINER_TEMPLATES_DIR}/`))
    ? `${templatesDir}${argument.slice(CONTAINER_TEMPLATES_DIR.length)}` : argument);
  if (!normalized.some(argument => /^--?(?:t|templates|w|workflows)(?:=|$)/.test(argument))) {
    normalized.push('-t', getNucleiTemplateSelection(templatesDir, engine, templatePaths));
  }
  if (!normalized.some(argument => /^--?(?:duc|disable-update-check)(?:=|$)/.test(argument))) {
    normalized.push('-duc');
  }
  return normalized;
}
