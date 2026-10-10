import { spawn } from 'child_process';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getEngine } from './containerEngine.js';
import { mkdirSync } from 'fs';
import { randomUUID } from 'crypto';
import { classifyToolResult, normalizeToolArgs, inspectToolWordlists } from './toolContracts.js';
import { ensureNucleiTemplates, getRequiredNucleiTemplateIds, normalizeNucleiTemplateArgs } from '../services/nucleiTemplates.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..', '..');

// ── Tool → Image mapping ────────────────────────────────────────────────
const IMAGE_MAP = {
  nmap: 'rt-recon', whatweb: 'rt-recon', gobuster: 'rt-recon',
  ffuf: 'rt-recon', httpx: 'rt-recon', amass: 'rt-recon', curl: 'rt-recon',
  nuclei: 'rt-vuln-scan', nikto: 'rt-vuln-scan', sqlmap: 'rt-vuln-scan',
  hydra: 'rt-brute', john: 'rt-brute', hashcat: 'rt-brute',
  netexec: 'rt-exploit', 'evil-winrm': 'rt-exploit', 'ssh-exec': 'rt-exploit', rpcclient: 'rt-exploit',
  msfvenom: 'rt-exploit', shellnoob: 'rt-exploit',
  arjun: 'rt-web', python3: 'rt-web', 'web-brute': 'rt-web',
  responder: 'rt-credential', mitm6: 'rt-credential',
  cloudmapper: 'rt-cloud', pacu: 'rt-cloud',
  'system-tools': 'rt-system',
  cat: 'rt-system', whoami: 'rt-system', id: 'rt-system',
  uname: 'rt-system', ping: 'rt-system', netstat: 'rt-system',
  // ── Network capture tools ────────────────────────────────────────────
  tcpdump: 'rt-capture', tshark: 'rt-capture',
};

// ── Tool → Binary name inside container ─────────────────────────────────
const BIN_MAP = {
  httpx: 'httpx',
  'system-tools': 'sh',
  nikto: 'nikto.pl',
  'web-brute': 'python3',
  netexec: '/opt/redteam/scripts/netexec-wrapper.sh',
  'evil-winrm': '/opt/redteam/scripts/evil-winrm-basic.rb',
  'ssh-exec': '/opt/redteam/scripts/ssh-exec.sh',
  responder: '/opt/redteam/scripts/responder-noroot.py',
  cloudmapper: '/opt/redteam/scripts/cloudmapper-local.sh',
  pacu: '/opt/redteam/scripts/pacu-local.sh',
};

// ── Tools requiring privileged container ────────────────────────────────
const PRIVILEGED_TOOLS = new Set(['nmap', 'mitm6', 'tcpdump']);

// ── Tools needing wordlist volume mount ─────────────────────────────────
const WORDLIST_TOOLS = new Set(['hydra', 'gobuster', 'ffuf', 'john', 'nikto', 'web-brute']);

// ── Tools needing nuclei-templates volume mount ─────────────────────────
const NUCLEI_TOOLS = new Set(['nuclei']);

// ── Tools needing capture directory volume mount ────────────────────────
const CAPTURE_TOOLS = new Set(['tcpdump', 'tshark']);

// ── Virtual tools (no container needed, handled in JS) ─────────────────
const VIRTUAL_TOOLS = new Set(['upload_shell', 'webshell', 'webshell_health']);

function getVolumeMounts(toolId) {
  const mounts = [];
  const wordlistsDir = resolve(PROJECT_ROOT, 'data', 'wordlists');
  const nucleiTemplatesDir = resolve(PROJECT_ROOT, 'data', 'nuclei-templates');
  const outputDir = resolve(PROJECT_ROOT, 'data', 'output');
  const capturesDir = resolve(PROJECT_ROOT, 'data', 'captures');

  if (WORDLIST_TOOLS.has(toolId)) {
    mounts.push('-v', `${wordlistsDir}:/usr/share/wordlists:ro`);
  }
  if (NUCLEI_TOOLS.has(toolId)) {
    mounts.push('-v', `${nucleiTemplatesDir}:/root/nuclei-templates`);
  }
  mounts.push('-v', `${outputDir}:/tmp/redteam-output`);

  // Capture tools need access to the captures directory for PCAP read/write
  if (CAPTURE_TOOLS.has(toolId)) {
    mounts.push('-v', `${capturesDir}:/tmp/captures`);
  }

  return mounts;
}

function ensureOutputDir() {
  mkdirSync(resolve(PROJECT_ROOT, 'data', 'output'), { recursive: true });
}

function runProcess(bin, args, options, executionMode, stopContainer) {
  return new Promise((resolveResult) => {
    const timeout = options.timeout || 300_000;
    const maxBytes = (options.maxOutputKB || 2048) * 1024;
    let stdout = '', stderr = '';
    let outputBytes = 0;
    let timedOut = false, aborted = false, outputLimitExceeded = false;
    let settled = false, killed = false;
    let sigkillTimer;
    let timer, hardTimer;
    const started = Date.now();
    const child = spawn(bin, args, { shell: false });
    function settle(result) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(hardTimer);
      clearTimeout(sigkillTimer);
      options.signal?.removeEventListener('abort', onAbort);
      resolveResult(classifyToolResult(options.toolId, {
        ...result, stdout: stdout.trim(), stderr: stderr.trim(), executionMode,
        timedOut, aborted, outputLimitExceeded, durationMs: Date.now() - started,
      }));
    }
    function forceKill() {
      if (killed) return;
      killed = true;
      stopContainer?.();
      child.kill('SIGTERM');
      sigkillTimer = setTimeout(() => child.kill('SIGKILL'), 5000);
      hardTimer = setTimeout(() => settle({ exitCode: -1 }), 15000);
    }
    function onAbort() {
      aborted = true;
      forceKill();
    }
    function collect(data, isError) {
      const remaining = Math.max(0, maxBytes - outputBytes);
      const text = Buffer.from(data).subarray(0, remaining).toString('utf8');
      if (isError) stderr += text; else stdout += text;
      outputBytes += Buffer.byteLength(data);
      if (outputBytes > maxBytes) { outputLimitExceeded = true; forceKill(); }
    }
    child.stdout.on('data', data => collect(data, false));
    child.stderr.on('data', data => collect(data, true));
    child.on('close', code => settle({ exitCode: code ?? -1 }));
    child.on('error', error => { stderr += error.message; settle({ exitCode: -1 }); });
    timer = setTimeout(() => { timedOut = true; forceKill(); }, timeout);
    options.signal?.addEventListener('abort', onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
  });
}

// ── Main entry: runTool ─────────────────────────────────────────────────
export async function runTool(toolId, args, options = {}) {
  if (VIRTUAL_TOOLS.has(toolId)) {
    return { success: false, exitCode: -1, stdout: '', stderr: `Tool ${toolId} is virtual (HTTP-based), use dedicated handler`, executionMode: 'virtual' };
  }

  const engine = await getEngine();
  const image = IMAGE_MAP[toolId];
  const bin = BIN_MAP[toolId] || toolId;

  try {
    args = normalizeToolArgs(toolId, args, { projectRoot: PROJECT_ROOT, engine });
    const resources = inspectToolWordlists(toolId, args, PROJECT_ROOT, engine);
    if (!resources.passed) throw new Error(resources.issues.join('; '));
    if (NUCLEI_TOOLS.has(toolId)) {
      const templates = await ensureNucleiTemplates({ projectRoot: PROJECT_ROOT, engine, requiredIds: getRequiredNucleiTemplateIds(args), signal: options.signal });
      args = normalizeNucleiTemplateArgs(args, templates.templatesDir, engine);
    }
  } catch (error) {
    return { success: false, exitCode: -1, stdout: '', stderr: error.message, error: error.message, executionMode: engine };
  }

  if (engine === 'host' || !image) {
    return runProcess(bin, args, { ...options, toolId }, 'host');
  }

  ensureOutputDir();
  const name = `rt-tool-${randomUUID()}`;
  const containerArgs = ['run', '--rm', '--name', name, '--network', 'host',
    ...getVolumeMounts(toolId), ...(PRIVILEGED_TOOLS.has(toolId) ? ['--privileged'] : []), image, bin, ...args];
  return runProcess(engine, containerArgs, { ...options, toolId }, engine, () => {
    const cleanup = spawn(engine, ['rm', '-f', name], { stdio: 'ignore' });
    cleanup.on('error', () => {});
    const cleanupTimer = setTimeout(() => cleanup.kill('SIGKILL'), 10000);
    cleanup.on('close', () => clearTimeout(cleanupTimer));
  });
}

export { IMAGE_MAP, BIN_MAP, PRIVILEGED_TOOLS, VIRTUAL_TOOLS, CAPTURE_TOOLS };
