import { getDb } from '../db/connection.js';
import { runTool } from '../tools/toolRunner.js';
import { getWsManager } from './wsManager.js';
import { existsSync, readdirSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..', '..');
const NUCLEI_TEMPLATES_DIR = resolve(PROJECT_ROOT, 'data', 'nuclei-templates');

const MAX_OUTPUT_LENGTH = 8192;

// Track running scans to prevent duplicates
const runningScans = new Set();

// ── Ensure nuclei templates are available ──────────────────────────────
let nucleiTemplatesChecked = false;

async function ensureNucleiTemplates() {
  if (nucleiTemplatesChecked) return;

  // Check if templates directory has content
  try {
    if (existsSync(NUCLEI_TEMPLATES_DIR)) {
      const files = readdirSync(NUCLEI_TEMPLATES_DIR);
      if (files.length > 0) {
        nucleiTemplatesChecked = true;
        return;
      }
    }
  } catch {}

  // Download templates
  console.log('[Nuclei] Templates not found, downloading...');
  try {
    const { getEngine } = await import('../tools/containerEngine.js');
    const engine = await getEngine();
    const { execFile } = await import('child_process');
    const { promisify } = await import('util');
    const execFileAsync = promisify(execFile);

    if (engine === 'host') {
      // Run nuclei -update-templates directly
      await execFileAsync('nuclei', ['-update-templates', '-td', NUCLEI_TEMPLATES_DIR], { timeout: 120_000 });
    } else {
      // Run in container, mount templates dir
      await execFileAsync(engine, [
        'run', '--rm',
        '-v', `${NUCLEI_TEMPLATES_DIR}:/root/nuclei-templates`,
        'rt-vuln-scan',
        'nuclei', '-update-templates', '-td', '/root/nuclei-templates',
      ], { timeout: 120_000 });
    }
    console.log('[Nuclei] Templates downloaded successfully');
  } catch (err) {
    console.warn('[Nuclei] Failed to download templates:', err.message);
  }
  nucleiTemplatesChecked = true;
}

// ── Scan type → tool mapping ──────────────────────────────────────────
const SCAN_TOOL_MAP = {
  port_scan: 'nmap',
  vuln_scan: 'nuclei',
  // web_scan is handled specially: runs nikto then sqlmap (dual-step)
  brute_force: 'hydra',
  ad_scan: 'netexec',        // Active Directory domain enumeration
  cloud_scan: 'cloudmapper', // Cloud security audit
};

// ── Build tool arguments from scan parameters ─────────────────────────
function buildArgs(scanType, target, parameters = {}) {
  const args = [];
  const { ports, timeout, extra_args, threads } = parameters;

  switch (scanType) {
    case 'port_scan': // nmap
      args.push('-Pn');  // skip host discovery — ICMP ping often fails in container networks
      if (ports) args.push('-p', String(ports));
      if (threads && threads > 1) args.push('--min-parallelism', String(threads));
      args.push('-sV'); // version detection
      args.push(target);
      break;

    case 'vuln_scan': // nuclei
      args.push('-no-color');  // disable ANSI color codes in output
      args.push('-u', target);
      args.push('-t', '/root/nuclei-templates');  // explicit template path matching volume mount
      if (ports) args.push('-p', String(ports));
      break;

    case 'web_scan_nikto': // nikto — general web vulnerability scan
      args.push('-h', target);
      args.push('-maxtime', '60');   // limit scan time
      if (ports) args.push('-port', String(ports));
      if (parameters.cookie) args.push('-C', String(parameters.cookie));
      break;

    case 'web_scan_sqlmap': // sqlmap — SQL injection specialist
      args.push('-u', target);
      if (ports) args.push('--port', String(ports));
      args.push('--batch');          // non-interactive
      args.push('--level', '3');     // test level 3 (forms, cookies, headers)
      args.push('--risk', '2');      // medium risk (OR-based payloads)
      args.push('--random-agent');   // random User-Agent
      if (parameters.cookie) args.push('--cookie', String(parameters.cookie));
      break;

    case 'brute_force': // hydra or web-brute
      // For http-post-form: use web-brute.py (handles CSRF tokens)
      // For other services: use hydra directly
      const service = parameters.service || 'http-post-form';
      if (service === 'http-post-form') {
        // web-brute.py: script path + full target URL as positional args
        // Build full URL: if target is just IP/hostname, prepend http://
        // If form_definition contains a path (e.g. /login.php:...), extract and append it
        let bruteUrl = target;
        if (!bruteUrl.startsWith('http://') && !bruteUrl.startsWith('https://')) {
          bruteUrl = 'http://' + bruteUrl;
        }
        // Extract path from form_definition if present (format: /path:body:condition)
        const formDef = parameters.form_definition || '';
        const pathMatch = formDef.match(/^([^:]+)/);
        if (pathMatch && pathMatch[1].startsWith('/')) {
          // Append path to URL (avoid double slash)
          const path = pathMatch[1];
          if (!bruteUrl.endsWith('/')) {
            bruteUrl += path;
          } else {
            bruteUrl += path.slice(1);
          }
        } else if (!bruteUrl.includes('.php') && !bruteUrl.includes('.html') && !bruteUrl.includes('/login')) {
          // Default: try /login.php if no path specified
          bruteUrl += '/login.php';
        }
        args.push('/usr/local/bin/web-brute.py');
        args.push(bruteUrl);
        args.push('-L', parameters.user_list || '/usr/share/wordlists/common_users.txt');
        args.push('-P', parameters.pass_list || '/usr/share/wordlists/common_passwords.txt');
        args.push('--threads', String(threads || 4));
        if (parameters.form_action) args.push('--form-action', parameters.form_action);
        if (parameters.user_field) args.push('--user-field', parameters.user_field);
        if (parameters.pass_field) args.push('--pass-field', parameters.pass_field);
        if (parameters.fail_string) args.push('--fail-string', parameters.fail_string);
        if (parameters.success_string) args.push('--success-string', parameters.success_string);
        if (parameters.csrf_field) args.push('--csrf-field', parameters.csrf_field);
      } else {
        // Standard hydra for SSH/FTP/SMB/MySQL etc.
        const userList = parameters.user_list || '/usr/share/wordlists/common_users.txt';
        const passList = parameters.pass_list || '/usr/share/wordlists/common_passwords.txt';
        args.push('-L', userList);
        args.push('-P', passList);
        if (threads) args.push('-t', String(threads));
        args.push(target);
        args.push(service);
      }
      break;

    case 'ad_scan': // netexec SMB enumeration
      args.push('smb');
      args.push(target);
      if (parameters.username) args.push('-u', parameters.username);
      else args.push('-u', 'administrator');
      if (parameters.password) args.push('-p', parameters.password);
      else args.push('-p', 'Password123!');  // 教学默认值
      if (parameters.domain) args.push('-d', parameters.domain);
      break;

    case 'cloud_scan': // cloudmapper audit
      args.push('audit');
      args.push('--json');  // JSON output for parsing
      if (parameters.account_id) args.push('--account', parameters.account_id);
      if (parameters.region) args.push('--region', parameters.region);
      break;
  }

  // Append extra args (split by whitespace)
  if (extra_args) {
    const extra = typeof extra_args === 'string'
      ? extra_args.split(/\s+/).filter(Boolean)
      : [];
    args.push(...extra);
  }

  return args;
}

// ── Simple result parsers per scan type ────────────────────────────────
function parseResults(scanType, stdout) {
  const results = [];
  const lines = stdout.split('\n').filter(l => l.trim());

  switch (scanType) {
    case 'port_scan':
      // Parse nmap output for open ports: "22/tcp  open  ssh"
      for (const line of lines) {
        const match = line.match(/^(\d+)\/(tcp|udp)\s+(open|filtered|closed)\s+(.+)/);
        if (match) {
          results.push({
            result_type: 'open_port',
            result_data: { port: Number(match[1]), protocol: match[2], state: match[3], service: match[4] },
            severity: match[3] === 'open' ? 'medium' : 'info',
            source_tool: 'nmap',
          });
        }
      }
      break;

    case 'vuln_scan': {
      // Parse nuclei v3 output: [template-id] [protocol] [severity] URL [extra]
      // Strip ANSI escape codes as safety net
      const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');
      // nuclei v3 -no-color format: [template-id] [protocol] [severity] URL [extra]
      const nucleiV3 = /^\[([^\]]+)\]\s+\[(\w+)\]\s+\[(\w+)\]\s+(.+)/;
      // nuclei v2 legacy format: [severity] [template-id] detail
      const nucleiV2 = /^\[(\w+)\]\s+\[([^\]]+)\]\s+(.+)/;
      for (const line of lines) {
        const clean = stripAnsi(line);
        let match = clean.match(nucleiV3);
        if (match) {
          // [template-id] [protocol] [severity] detail
          const templateId = match[1];
          const protocol = match[2];
          const sev = match[3].toLowerCase();
          const detail = match[4];
          if (sev === 'inf' || sev === 'info') continue;
          results.push({
            result_type: 'vulnerability',
            result_data: { template: templateId, protocol, detail },
            severity: sev,
            source_tool: 'nuclei',
          });
        } else {
          // Try legacy format: [severity] [template-id] detail
          match = clean.match(nucleiV2);
          if (match) {
            const sev = match[1].toLowerCase();
            if (sev === 'inf' || sev === 'info') continue;
            results.push({
              result_type: 'vulnerability',
              result_data: { template: match[2], detail: match[3] },
              severity: sev,
              source_tool: 'nuclei',
            });
          }
        }
      }
      break;
    }

    case 'web_scan_nikto': {
      // Parse nikto text output:
      //   + OSVDB-3268: /config/: Directory indexing found.
      //   + /config/: Configuration information may be available remotely.
      //   + The anti-clickjacking X-Frame-Options header is not present.
      // Skip: lines starting with "-", "-----", "Nikto v", "Target", "Start", "End", "requests"
      const osvdbLine = /^\+\s+(OSVDB-\d+):\s+(\S+)\s+(.+)/;   // + OSVDB-XXX: /path/: finding
      const pathLine  = /^\+\s+(\/\S+):\s+(.+)/;                 // + /path: finding
      const infoLine  = /^\+\s+(The\s+.+|Cookie\s+.+|Allowed\s+.+|Server\s+.+)/i;  // + The X-Frame...

      for (const line of lines) {
        // Skip header/footer lines
        if (line.startsWith('-') || line.startsWith('---') || line.includes('Nikto v') ||
            line.includes('Target IP') || line.includes('Start Time') || line.includes('End Time') ||
            line.includes('requests:') || line.includes('host(s) tested') ||
            line.includes('submit this') || line.includes('CIRT.net')) continue;

        let osvdbId = '', path = '', finding = '';

        // Pattern 1: + OSVDB-XXXX: /path/: finding
        const m1 = line.match(osvdbLine);
        if (m1) {
          osvdbId = m1[1];
          path = m1[2];
          finding = m1[3].trim();
        } else {
          // Pattern 2: + /path: finding
          const m2 = line.match(pathLine);
          if (m2) {
            path = m2[1];
            finding = m2[2].trim();
          } else {
            // Pattern 3: + The X-Frame... / + Cookie ... / + Allowed ...
            const m3 = line.match(infoLine);
            if (m3) {
              finding = m3[1].trim();
            } else {
              continue; // skip unrecognized lines
            }
          }
        }

        if (!finding) continue;

        // Determine severity from finding content
        let sev = 'low';
        const fl = finding.toLowerCase();
        if (fl.includes('admin') || fl.includes('login') || fl.includes('config')) sev = 'medium';
        if (fl.includes('x-frame') || fl.includes('x-xss') || fl.includes('x-content-type')) sev = 'medium';
        if (fl.includes('httponly') || fl.includes('directory indexing') || fl.includes('default file')) sev = 'medium';
        if (fl.includes('sql') || fl.includes('inject') || fl.includes('exec') || fl.includes('vulnerable')) sev = 'high';
        if (fl.includes('leak') || fl.includes('expos')) sev = 'medium';

        results.push({
          result_type: 'web_vuln',
          result_data: { finding, ...(path && { path }), ...(osvdbId && { osvdb_id: osvdbId }) },
          severity: sev,
          source_tool: 'nikto',
        });
      }
      break;
    }

    case 'web_scan_sqlmap': {
      // Enhanced sqlmap output parsing
      // Pattern 1: "is vulnerable"
      if (stdout.includes('is vulnerable')) {
        // Try to extract more detail
        let param = '', technique = '', dbms = '';
        const paramMatch = stdout.match(/Parameter:\s*(\S+)/i);
        if (paramMatch) param = paramMatch[1];
        const techMatch = stdout.match(/Type:\s*(.+)/i);
        if (techMatch) technique = techMatch[1].trim();
        const dbmsMatch = stdout.match(/back-end DBMS:\s*(.+)/i);
        if (dbmsMatch) dbms = dbmsMatch[1].trim();

        results.push({
          result_type: 'sql_injection',
          result_data: {
            detail: 'Target is vulnerable to SQL injection',
            ...(param && { parameter: param }),
            ...(technique && { technique }),
            ...(dbms && { dbms }),
          },
          severity: 'critical',
          source_tool: 'sqlmap',
        });
      }
      // Pattern 2: "Parameter: X appears to be injectable"
      const injectablePattern = /Parameter:\s*'([^']+)'.*appears to be ('[^']+' )?injectable/gi;
      let injectMatch;
      while ((injectMatch = injectablePattern.exec(stdout)) !== null) {
        const param = injectMatch[1];
        // Avoid duplicate if already captured by "is vulnerable"
        if (!results.some(r => r.result_data?.parameter === param)) {
          results.push({
            result_type: 'sql_injection',
            result_data: { detail: `Parameter '${param}' is injectable`, parameter: param },
            severity: 'critical',
            source_tool: 'sqlmap',
          });
        }
      }
      break;
    }

    case 'brute_force': {
      // Parse hydra output:
      //   [80][http-post-form] host: 172.17.0.2   login: admin   password: password
      //   [22][ssh] host: 192.168.1.1   login: root   password: toor
      const hydraLine = /\[(\d+)\]\[([^\]]+)\]\s+host:\s*(\S+)\s+login:\s*(\S+)\s+password:\s*(\S+)/;
      for (const line of lines) {
        const match = line.match(hydraLine);
        if (match) {
          const [, port, service, host, login, password] = match;
          results.push({
            result_type: 'credential',
            result_data: { login, password, host, port: Number(port), service },
            severity: 'critical',
            source_tool: 'hydra',
          });
        }
      }
      break;
    }

    case 'ad_scan': {
      // Parse netexec SMB output
      // Patterns:
      //   [+] 192.168.1.10    445    HOSTNAME   Windows Server 2019 ...
      //   SMB    192.168.1.10    445    HOSTNAME   ...
      const netexecLine = /(?:\[?\+?\]?\s*)?(\S+)\s+(\d+)\s+(\S+)\s+(.+)/;
      for (const line of lines) {
        const match = line.match(netexecLine);
        if (match && (line.startsWith('[+]') || !line.startsWith('['))) {
          const [, host, portStr, hostname, detail] = match;
          if (host && portStr && hostname) {
            results.push({
              result_type: 'service_info',
              result_data: { host, port: Number(portStr), hostname, os: detail.trim() },
              severity: 'medium',
              source_tool: 'netexec',
            });
          }
        }
      }
      break;
    }

    case 'cloud_scan': {
      // Parse cloudmapper audit output (may be JSON or text)
      try {
        const auditResults = JSON.parse(stdout);
        const findings = Array.isArray(auditResults) ? auditResults : (auditResults.findings || []);
        for (const finding of findings) {
          results.push({
            result_type: 'misconfiguration',
            result_data: { ...finding },
            severity: finding.severity || 'medium',
            source_tool: 'cloudmapper',
          });
        }
      } catch {
        // Fallback: parse line-by-line for text output
        for (const line of lines) {
          if (line.includes('S3') || line.includes('EC2') || line.includes('IAM') ||
              line.includes('RDS') || line.includes('Lambda') || line.includes('finding')) {
            results.push({
              result_type: 'misconfiguration',
              result_data: { detail: line.trim() },
              severity: 'medium',
              source_tool: 'cloudmapper',
            });
          }
        }
      }
      break;
    }
  }

  if (results.length === 0 && stdout.length > 0) {
    results.push({
      result_type: 'raw_output',
      result_data: { output: stdout.slice(0, MAX_OUTPUT_LENGTH) },
      severity: 'info',
      source_tool: SCAN_TOOL_MAP[scanType] || 'unknown',
    });
  }

  return results;
}

// ── Main entry: executeScan ───────────────────────────────────────────
export async function executeScan(scanTaskId) {
  if (runningScans.has(scanTaskId)) {
    return { ok: false, error: 'Scan is already executing' };
  }

  const db = getDb();

  const task = db.prepare(
    'SELECT scan_task_id, target, scan_type, parameters, status FROM scan_tasks WHERE scan_task_id = ?'
  ).get(scanTaskId);
  if (!task) return { ok: false, error: 'Scan task not found' };
  if (task.status === 'RUNNING') return { ok: false, error: 'Scan is already running' };

  // Reset to PENDING if needed (for re-execution of COMPLETED/FAILED/CANCELLED)
  if (task.status !== 'PENDING') {
    db.prepare('DELETE FROM scan_results WHERE scan_task_id = ?').run(scanTaskId);
    db.prepare("UPDATE scan_tasks SET status = 'PENDING', started_at = NULL, completed_at = NULL, error_message = NULL WHERE scan_task_id = ?")
      .run(scanTaskId);
  }

  runningScans.add(scanTaskId);

  // Mark as RUNNING
  const now = new Date().toISOString();
  db.prepare("UPDATE scan_tasks SET status = 'RUNNING', started_at = ? WHERE scan_task_id = ?")
    .run(now, scanTaskId);

  try {
    let parameters = {};
    try { parameters = JSON.parse(task.parameters || '{}'); } catch {}
    const timeoutSec = parameters.timeout || 300;
    const timeoutMs = timeoutSec * 1000;

    // Helper: run one tool, parse results, store them
    const insertResult = db.prepare(`
      INSERT INTO scan_results (scan_task_id, result_type, result_data, severity, confidence, mitre_technique_id, source_tool, captured_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    async function runAndStore(scanType, toolId, target, params, timeout) {
      const args = buildArgs(scanType, target, params);
      const result = await runTool(toolId, args, { timeout });
      const output = (result.stdout || '') + (result.stderr ? '\n' + result.stderr : '');
      const results = parseResults(scanType, output);
      for (const r of results) {
        insertResult.run(
          scanTaskId, r.result_type,
          r.result_data ? JSON.stringify(r.result_data) : null,
          r.severity || null, null, null,
          r.source_tool || null, new Date().toISOString()
        );
      }
      return results.length;
    }

    let totalResults = 0;

    // Ensure nuclei templates are available before running vuln_scan
    if (task.scan_type === 'vuln_scan') {
      await ensureNucleiTemplates();
    }

    if (task.scan_type === 'web_scan') {
      // ── Dual-step: nikto (general web scan) → sqlmap (SQL injection) ──
      console.log(`[Scan] web_scan step 1/2: nikto for ${task.target}`);
      try {
        totalResults += await runAndStore('web_scan_nikto', 'nikto', task.target, parameters, 120_000);
      } catch (err) {
        console.warn(`[Scan] nikto failed: ${err.message}`);
      }

      console.log(`[Scan] web_scan step 2/2: sqlmap for ${task.target}`);
      try {
        totalResults += await runAndStore('web_scan_sqlmap', 'sqlmap', task.target, parameters, timeoutMs);
      } catch (err) {
        console.warn(`[Scan] sqlmap failed: ${err.message}`);
      }
    } else if (task.scan_type === 'brute_force') {
      // ── Brute force: http-post-form → web-brute.py, others → hydra ──
      const service = parameters.service || 'http-post-form';
      if (service === 'http-post-form') {
        console.log(`[Scan] brute_force http-post-form: web-brute.py for ${task.target}`);
        totalResults = await runAndStore('brute_force', 'web-brute', task.target, parameters, timeoutMs);
      } else {
        console.log(`[Scan] brute_force ${service}: hydra for ${task.target}`);
        totalResults = await runAndStore('brute_force', 'hydra', task.target, parameters, timeoutMs);
      }
    } else if (task.scan_type === 'ad_scan') {
      // ── AD scan: netexec SMB enumeration ──
      console.log(`[Scan] ad_scan: netexec SMB for ${task.target}`);
      totalResults = await runAndStore('ad_scan', 'netexec', task.target, parameters, timeoutMs);
    } else if (task.scan_type === 'cloud_scan') {
      // ── Cloud scan: cloudmapper audit (optional: + pacu) ──
      console.log(`[Scan] cloud_scan step 1: cloudmapper for ${task.target}`);
      try {
        totalResults += await runAndStore('cloud_scan', 'cloudmapper', task.target, parameters, 120_000);
      } catch (err) {
        console.warn(`[Scan] cloudmapper failed: ${err.message}`);
      }
      // Optional: run pacu for AWS exploitation if credentials provided
      if (parameters.pacu_profile) {
        console.log(`[Scan] cloud_scan step 2: pacu for ${task.target}`);
        try {
          totalResults += await runAndStore('cloud_scan', 'pacu', task.target, parameters, timeoutMs);
        } catch (err) {
          console.warn(`[Scan] pacu failed: ${err.message}`);
        }
      }
    } else {
      // ── Single-tool scan types ──
      const toolId = SCAN_TOOL_MAP[task.scan_type];
      if (!toolId) throw new Error(`Unknown scan type: ${task.scan_type}`);
      totalResults = await runAndStore(task.scan_type, toolId, task.target, parameters, timeoutMs);
    }

    // Mark as COMPLETED
    const completedAt = new Date().toISOString();
    db.prepare("UPDATE scan_tasks SET status = 'COMPLETED', completed_at = ? WHERE scan_task_id = ?")
      .run(completedAt, scanTaskId);
    // WebSocket: notify scan completed (include operator info)
    const ws = getWsManager();
    const taskInfo = db.prepare('SELECT created_by FROM scan_tasks WHERE scan_task_id = ?').get(scanTaskId);
    if (ws) ws.broadcast('scan:completed', {
      scanTaskId, status: 'COMPLETED', resultsCount: totalResults,
      userId: taskInfo?.created_by || null,
      username: taskInfo?.created_by || null,
    });

    return { ok: true, scanTaskId, status: 'COMPLETED', resultsCount: totalResults };

  } catch (err) {
    const completedAt = new Date().toISOString();
    db.prepare("UPDATE scan_tasks SET status = 'FAILED', completed_at = ?, error_message = ? WHERE scan_task_id = ?")
      .run(completedAt, err.message, scanTaskId);
    // WebSocket: notify scan failed (include operator info)
    const ws = getWsManager();
    const taskInfo = db.prepare('SELECT created_by FROM scan_tasks WHERE scan_task_id = ?').get(scanTaskId);
    if (ws) ws.broadcast('scan:completed', {
      scanTaskId, status: 'FAILED', error: err.message,
      userId: taskInfo?.created_by || null,
      username: taskInfo?.created_by || null,
    });

    return { ok: false, error: err.message };
  } finally {
    runningScans.delete(scanTaskId);
  }
}
