import { spawn } from 'child_process';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getEngine } from './containerEngine.js';

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
const PRIVILEGED_TOOLS = new Set(['nmap', 'mitm6']);

// ── Tools needing wordlist volume mount ─────────────────────────────────
const WORDLIST_TOOLS = new Set(['hydra', 'gobuster', 'ffuf', 'john', 'nikto', 'web-brute']);

// ── Tools needing nuclei-templates volume mount ─────────────────────────
const NUCLEI_TOOLS = new Set(['nuclei']);

// ── Virtual tools (no container needed, handled in JS) ─────────────────
const VIRTUAL_TOOLS = new Set(['upload_shell', 'webshell', 'webshell_health']);

function getVolumeMounts(toolId) {
  const mounts = [];
  const wordlistsDir = resolve(PROJECT_ROOT, 'data', 'wordlists');
  const nucleiTemplatesDir = resolve(PROJECT_ROOT, 'data', 'nuclei-templates');
  const outputDir = resolve(PROJECT_ROOT, 'data', 'output');

  if (WORDLIST_TOOLS.has(toolId)) {
    mounts.push('-v', `${wordlistsDir}:/usr/share/wordlists:ro`);
  }
  if (NUCLEI_TOOLS.has(toolId)) {
    mounts.push('-v', `${nucleiTemplatesDir}:/root/nuclei-templates`);
  }
  mounts.push('-v', `${outputDir}:/tmp/redteam-output`);

  return mounts;
}

function ensureOutputDir() {
  import('fs').then(fs => {
    const dir = resolve(PROJECT_ROOT, 'data', 'output');
    fs.mkdirSync(dir, { recursive: true });
  });
}

// ── Run tool directly on host (fallback) ────────────────────────────────
function runDirect(bin, args, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 300_000;
    const maxOutputKB = options.maxOutputKB || 2048;

    const child = spawn(bin, args, { shell: false });
    let stdout = '', stderr = '';
    let outputBytes = 0;
    const maxBytes = maxOutputKB * 1024;
    let killed = false;

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d) => { stdout += d; outputBytes += Buffer.byteLength(d); if (outputBytes > maxBytes && !killed) { killed = true; child.kill('SIGTERM'); } });
    child.stderr.on('data', (d) => { stderr += d; outputBytes += Buffer.byteLength(d); if (outputBytes > maxBytes && !killed) { killed = true; child.kill('SIGTERM'); } });

    const timer = setTimeout(() => { if (!killed) { killed = true; child.kill('SIGTERM'); } }, timeout);

    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({
        success: code === 0 || stdout.length > 0,
        exitCode: code,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        executionMode: 'host',
      });
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ success: false, exitCode: -1, stdout: '', stderr: err.message, executionMode: 'host' });
    });
  });
}

// ── Run tool in container ───────────────────────────────────────────────
function runInContainer(engine, image, bin, args, options = {}) {
  return new Promise((resolve, reject) => {
    const timeout = options.timeout || 300_000;
    const maxOutputKB = options.maxOutputKB || 2048;
    const toolId = options.toolId || '';

    ensureOutputDir();

    const cmdArgs = [
      'run', '--rm',
      '--network', 'host',
      ...getVolumeMounts(toolId),
      ...(PRIVILEGED_TOOLS.has(toolId) ? ['--privileged'] : []),
      image, bin, ...args,
    ];

    const child = spawn(engine, cmdArgs, { shell: false });
    let stdout = '', stderr = '';
    let outputBytes = 0;
    const maxBytes = maxOutputKB * 1024;
    let killed = false;

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (d) => { stdout += d; outputBytes += Buffer.byteLength(d); if (outputBytes > maxBytes && !killed) { killed = true; child.kill('SIGTERM'); } });
    child.stderr.on('data', (d) => { stderr += d; outputBytes += Buffer.byteLength(d); if (outputBytes > maxBytes && !killed) { killed = true; child.kill('SIGTERM'); } });

    const timer = setTimeout(() => { if (!killed) { killed = true; child.kill('SIGTERM'); } }, timeout);

    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({
        success: code === 0 || stdout.length > 0,
        exitCode: code,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        executionMode: engine,
      });
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      resolve({ success: false, exitCode: -1, stdout: '', stderr: err.message, executionMode: engine });
    });
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

  if (engine === 'host' || !image) {
    return runDirect(bin, args, options);
  }

  return runInContainer(engine, image, bin, args, { ...options, toolId });
}

export { IMAGE_MAP, BIN_MAP, PRIVILEGED_TOOLS, VIRTUAL_TOOLS };
