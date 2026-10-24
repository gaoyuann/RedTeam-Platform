import { StringDecoder } from 'node:string_decoder';
import { spawn } from 'child_process';
import { runTargetRequest } from './targetRequest.js';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getEngine } from './containerEngine.js';
import { mkdirSync } from 'fs';
import { randomUUID } from 'crypto';
import { classifyToolResult, normalizeToolArgs, inspectToolWordlists, validateToolArgs } from './toolContracts.js';
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
  // ── Source code audit (C/C++) ────────────────────────────────────────
  cppcheck: 'rt-sast-c', flawfinder: 'rt-sast-c',
  'target-request': 'builtin',
};

// ── Tool → Binary name inside container ─────────────────────────────────
const BIN_MAP = {
  httpx: 'httpx',
  'system-tools': 'sh',
  nikto: 'nikto.pl',
  'web-brute': '/usr/local/bin/web-brute.py',
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
// 源码工具只挂载当前任务快照。
const SAST_TOOLS = new Set(['cppcheck', 'flawfinder']);

// ── Virtual tools (no container needed, handled in JS) ─────────────────
const VIRTUAL_TOOLS = new Set(['upload_shell', 'webshell', 'webshell_health']);

function getVolumeMounts(toolId, options = {}) {
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
  if (SAST_TOOLS.has(toolId)) {
    if (!options.sourceDir) throw new Error('源码工具必须指定任务快照目录');
    mounts.push('-v', `${resolve(options.sourceDir)}:/src/project:ro`);
  }
  if (options.privateOutputDir) mounts.push('-v', `${resolve(options.privateOutputDir)}:/tmp/redteam-private`);
  else mounts.push('-v', `${outputDir}:/tmp/redteam-output`);

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
    const stdoutDecoder = new StringDecoder('utf8'), stderrDecoder = new StringDecoder('utf8');
    let outputBytes = 0;
    let timedOut = false, aborted = false, outputLimitExceeded = false;
    let settled = false, killed = false;
    let sigkillTimer;
    let cleanupResult = Promise.resolve(true);
    let outputConsumerError = null;
    let timer, hardTimer;
    const started = Date.now();
    const child = spawn(bin, args, { shell: false });
    function settle(result) {
      if (settled) return;
      settled = true;
      stdout += stdoutDecoder.end(); stderr += stderrDecoder.end();
      clearTimeout(timer);
      clearTimeout(hardTimer);
      clearTimeout(sigkillTimer);
      options.signal?.removeEventListener('abort', onAbort);
      cleanupResult.then(stopped => resolveResult(classifyToolResult(options.toolId, {
        ...result, toolStarted:!!child.pid, stdout: stdout.trim(), stderr: stderr.trim(), executionMode,
        ...(options.privateOutputDir ? {processRef:options.privateContainerName || child.pid || null} : {}),
        timedOut, aborted, outputLimitExceeded, outputBytes, durationMs: Date.now() - started,
        processStopped: result.processStopped !== false && stopped !== false,
        ...(outputConsumerError ? {exitCode:-1,error:'Output collection failed: '+outputConsumerError} : {}),
      })));
    }
    function forceKill() {
      if (killed) return;
      killed = true;
      if (stopContainer) cleanupResult = Promise.resolve().then(stopContainer).catch(() => false);
      child.kill('SIGTERM');
      sigkillTimer = setTimeout(() => child.kill('SIGKILL'), 5000);
      hardTimer = setTimeout(() => settle({ exitCode: -1, processStopped: false }), 15000);
    }
    function onAbort() {
      aborted = true;
      forceKill();
    }
    function collect(data, isError) {
      if (settled) return;
      try { options.onOutput?.(data, isError ? 'stderr' : 'stdout'); }
      catch (error) { outputConsumerError=error.message; forceKill(); }
      const remaining = Math.max(0, maxBytes - outputBytes);
      const text = (isError ? stderrDecoder : stdoutDecoder).write(Buffer.from(data).subarray(0, remaining));
      if (isError) stderr += text; else stdout += text;
      outputBytes += Buffer.byteLength(data);
      if (outputBytes > maxBytes) { outputLimitExceeded = true; forceKill(); }
    }
    child.stdout.on('data', data => collect(data, false));
    child.stderr.on('data', data => collect(data, true));
    child.on('close', code => settle({ exitCode: code ?? -1, processStopped: true }));
    child.on('error', error => { stderr += error.message; settle({ exitCode: -1 }); });
    timer = setTimeout(() => { timedOut = true; forceKill(); }, timeout);
    options.signal?.addEventListener('abort', onAbort, { once: true });
    if (options.signal?.aborted) onAbort();
  });
}

// ── Main entry: runTool ─────────────────────────────────────────────────
export async function runTool(toolId, args, options = {}) {
  const cancelled=()=>({success:false,exitCode:-1,stdout:'',stderr:'操作员手动中止',aborted:true,processStopped:true,toolStarted:false});
  if(options.signal?.aborted) return cancelled();
  if (toolId === 'target-request') return runTargetRequest(args, options);
  if (SAST_TOOLS.has(toolId) && !options.sourceDir) return {success:false,exitCode:1,stdout:'',stderr:'源码工具必须从源码审计任务运行',error:'缺少任务源码快照',toolStarted:false};
  if (VIRTUAL_TOOLS.has(toolId)) {
    return { success: false, exitCode: -1, stdout: '', stderr: `Tool ${toolId} is virtual (HTTP-based), use dedicated handler`, executionMode: 'virtual',toolStarted:false };
  }

  const engine = await getEngine();
  const image = IMAGE_MAP[toolId];
  const bin = BIN_MAP[toolId] || toolId;

  try {
    args = normalizeToolArgs(toolId, args, { projectRoot: PROJECT_ROOT, engine });
    const contractIssues = validateToolArgs(toolId, args);
    if (contractIssues.length > 0) throw new Error(contractIssues.join('; '));
    const resources = inspectToolWordlists(toolId, args, PROJECT_ROOT, engine);
    if (!resources.passed) throw new Error(resources.issues.join('; '));
    if (NUCLEI_TOOLS.has(toolId)) {
      const templates = await ensureNucleiTemplates({ projectRoot: PROJECT_ROOT, engine, requiredIds: getRequiredNucleiTemplateIds(args), args, signal: options.signal });
      args = normalizeNucleiTemplateArgs(args, templates.templatesDir, engine, templates.templatePaths, templates.selectionResolved);
    }
  } catch (error) {
    return { success: false, exitCode: -1, stdout: '', stderr: error.message, error: error.message, executionMode: engine,toolStarted:false };
  }

  if(options.signal?.aborted) return cancelled();
  if (engine === 'host' || !image) {
    if (options.privateOutputDir) args = args.map(arg => arg.replace('/tmp/redteam-private/', resolve(options.privateOutputDir) + '/'));
    if (SAST_TOOLS.has(toolId)) args = args.map(arg => arg === '--project=/src/project/.rt-compile-commands.json'
      ? '--project='+resolve(options.sourceDir,'.rt-host-compile-commands.json')
      : arg === '/src/project' ? resolve(options.sourceDir) : arg);
    return runProcess(bin, args, { ...options, toolId }, 'host');
  }

  if(!options.privateOutputDir)ensureOutputDir();
  const name = `rt-tool-${randomUUID()}`;
  const containerArgs = ['run', '--rm', ...(SAST_TOOLS.has(toolId) || options.privateOutputDir ? ['--pull=never'] : []), '--name', name, ...(options.privateOutputDir && engine==='podman' ? ['--userns=keep-id'] : []), ...(options.privateOutputDir && process.getuid ? ['--user', `${process.getuid()}:${process.getgid()}`] : []), '--network', SAST_TOOLS.has(toolId) ? 'none' : 'host',
    ...getVolumeMounts(toolId, options), ...(PRIVILEGED_TOOLS.has(toolId) ? ['--privileged'] : []), image, bin, ...args];
  return runProcess(engine, containerArgs, { ...options, toolId,privateContainerName:name }, engine, () => new Promise(resolveCleanup => {
    const cleanup = spawn(engine, ['rm', '-f', name], { stdio: 'ignore' });
    cleanup.on('error', () => resolveCleanup(false));
    const cleanupTimer = setTimeout(() => { cleanup.kill('SIGKILL'); resolveCleanup(false); }, 10000);
    cleanup.on('close', code => { clearTimeout(cleanupTimer); resolveCleanup(code === 0); });
  }));
}

export { IMAGE_MAP, BIN_MAP, PRIVILEGED_TOOLS, VIRTUAL_TOOLS, CAPTURE_TOOLS };
