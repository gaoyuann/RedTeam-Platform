import { parseNmapResults, parseNmapInterfaces, topologyScanArgs, selectLanDiscoveryScope } from './nmapTopology.js';
import { getDb } from '../db/connection.js';
import { runTool } from '../tools/toolRunner.js';
import { getWsManager } from './wsManager.js';
import { normalizeTarget, probeTarget, buildDiscoveredProfile } from './targetDiscovery.js';
import { classifyToolResult } from '../tools/toolContracts.js';

const MAX_OUTPUT_LENGTH = 8192;

// Track running scans to prevent duplicates
const runningScans = new Set();

// ── Module-level abort flags ───────────────────────────────────────────
// Allows external API (POST /api/scan-tasks/:scanTaskId/abort) to cancel a running scan.
const scanAbortFlags = new Map();

export function requestScanAbort(scanTaskId) {
  scanAbortFlags.set(scanTaskId, true);
}

// Race a tool promise against an abort signal so operator abort is honoured
// even while a scan tool is mid-execution.
function raceScanWithAbort(toolPromise, scanTaskId, controller) {
  return new Promise((resolve) => {
    let done = false;
    const interval = setInterval(() => {
      if (scanAbortFlags.get(scanTaskId)) {
        if (!done) {
          done = true;
          clearInterval(interval);
          controller?.abort();
          resolve({ success: false, exitCode: -2, stdout: '', stderr: '扫描被操作员中止', executionMode: 'aborted' });
        }
      }
    }, 500);
    toolPromise.then((r) => {
      if (!done) {
        done = true;
        clearInterval(interval);
        resolve(r);
      }
    }).catch((err) => {
      if (!done) {
        done = true;
        clearInterval(interval);
        resolve({ success: false, exitCode: -1, stdout: '', stderr: err.message, executionMode: 'error' });
      }
    });
  });
}

// ── Scan type → tool mapping ──────────────────────────────────────────
const SCAN_TOOL_MAP = {
  port_scan: 'nmap',
  topology_scan: 'nmap',
  vuln_scan: 'nuclei',
  // web_scan is handled specially: runs nikto then sqlmap (dual-step)
  brute_force: 'hydra',
  ad_scan: 'netexec',        // Active Directory domain enumeration
  cloud_scan: 'cloudmapper', // Cloud security audit
  // app_discovery and api_fuzz are handled specially (dual-step)
  auth_audit: 'nuclei',      // Nuclei with auth templates
};

// ── Build tool arguments from scan parameters ─────────────────────────
export function buildArgs(scanType, target, parameters = {}) {
  if (scanType === 'topology_scan') return topologyScanArgs(target);
  const args = [];
  const { ports, timeout, extra_args, threads } = parameters;

  switch (scanType) {
    case 'port_scan': // nmap
      args.push('-Pn');  // skip host discovery — ICMP ping often fails in container networks
      if (ports || /^https?:\/\//i.test(target) || /^[^/]+:\d+$/.test(target)) args.push('-p', String(ports || normalizeTarget(target).port));
      if (threads && threads > 1) args.push('--min-parallelism', String(threads));
      args.push('-sV'); // version detection
      if (parameters.discover_topology) args.push('--traceroute');
      args.push(/^https?:\/\//i.test(target) || /^[^/]+:\d+$/.test(target) ? normalizeTarget(target).host.replace(/^\[|\]$/g, '') : target);
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
          // Default: try common login paths (generic, not DVWA-specific)
          bruteUrl += '/login';
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

    // ── Application target scan types ────────────────────────────────

    case 'app_discovery_whatweb': // whatweb — technology fingerprinting
      args.push(target);
      args.push('--no-errors');   // suppress error output
      break;

    case 'app_discovery_httpx': // httpx — HTTP probe
      args.push('-u', target);
      args.push('-sc');           // show status code
      args.push('-title');        // show page title
      args.push('-tech-detect'); // technology detection
      args.push('-sr');           // save response
      args.push('-json');
      break;

    case 'api_fuzz_arjun': // arjun — URL parameter discovery
      args.push('-u', target);
      args.push('-t', String(threads || 5));  // threads
      args.push('--passive');                  // passive + active discovery
      break;

    case 'api_fuzz_ffuf': // ffuf — API endpoint fuzzing
      // Use FUZZ keyword in URL path; default to /api/FUZZ
      const ffufWordlist = parameters.wordlist || '/usr/share/wordlists/dirb/common.txt';
      const ffufUrl = target.endsWith('/') ? `${target}api/FUZZ` : `${target}/api/FUZZ`;
      args.push('-u', ffufUrl);
      args.push('-w', ffufWordlist);
      args.push('-mc', '200,201,204,301,302,307,401,403');
      args.push('-ac');          // auto-calibrate filtering
      if (threads) args.push('-t', String(threads));
      break;

    case 'auth_audit': // nuclei — authentication security templates
      args.push('-no-color');
      args.push('-u', target);
      args.push('-t', '/root/nuclei-templates/technologies/');
      args.push('-t', '/root/nuclei-templates/vulnerabilities/generic/');
      // Include auth-related templates if they exist
      args.push('-include-templates', '/root/nuclei-templates/vulnerabilities/');
      args.push('-severity', 'low,medium,high,critical');
      if (parameters.auth_template) args.push('-t', parameters.auth_template);
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
    case 'topology_scan':
      results.push(...parseNmapResults(stdout, { assumedUp: scanType === 'port_scan' }));
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

    // ── Application target scan type parsers ─────────────────────────

    case 'app_discovery_whatweb': {
      // Parse whatweb output: "URL [Title] ..."
      // Lines: "http://host.domain.com [200 OK] Apache[2.4.41], PHP[7.4], HTML5"
      const whatwebLine = /^(\S+)\s+(.+)$/;
      for (const line of lines) {
        const match = line.match(whatwebLine);
        if (!match) continue;
        const [, url, techStr] = match;
        const status = techStr.match(/^\[(\d{3})(?:\s[^\]]*)?\]/);
        if (!/^https?:\/\//i.test(url) || !status) continue;
        // Extract individual technologies: "Apache[2.4.41]" or just "PHP"
        const techs = [];
        const techPattern = /([A-Za-z0-9_/.-]+)(?:\[([^\]]*)\])?/g;
        let techMatch;
        while ((techMatch = techPattern.exec(techStr.slice(status[0].length))) !== null) {
          const name = techMatch[1].trim();
          const version = techMatch[2] || '';
          if (name && name !== url) {
            techs.push({ name, version });
          }
        }
        if (techs.length > 0) {
          results.push({
            result_type: 'technology_detection',
            result_data: { url, status_code: Number(status[1]), technologies: techs, raw: techStr },
            severity: 'info',
            source_tool: 'whatweb',
          });
        }
      }
      break;
    }

    case 'app_discovery_httpx': {
      // Parse httpx output:
      // "http://host.domain.com [200] [Page Title] [Apache/PHP]"
      // or JSON output if -json flag used
      for (const line of lines) {
        // Try JSON first
        try {
          const json = JSON.parse(line);
          if (json.url) {
            results.push({
              result_type: 'http_probe',
              result_data: {
                url: json.url,
                status_code: json.status_code || json['status-code'],
                title: json.title,
                technologies: json.tech || json.technologies,
                content_length: json.content_length || json['content-length'],
                webserver: json.webserver,
              },
              severity: 'info',
              source_tool: 'httpx',
            });
          }
          continue;
        } catch { /* not JSON, try text parsing */ }

        // Text format: URL [status] [title] [technologies]
        const textMatch = line.match(/^(\S+)\s+\[(\d+)\]\s+\[([^\]]*)\]\s+\[([^\]]*)\]/);
        if (textMatch) {
          const [, url, statusCode, title, technologies] = textMatch;
          results.push({
            result_type: 'http_probe',
            result_data: { url, status_code: parseInt(statusCode), title, technologies: technologies || '' },
            severity: 'info',
            source_tool: 'httpx',
          });
        }
      }
      break;
    }

    case 'api_fuzz_arjun': {
      // Parse arjun output for discovered parameters
      // arjun shows: [+] Parameter: id found in URL query
      //              [+] Parameter: token found in POST body
      const paramPattern = /\[\+\]\s*Parameter:\s*(\S+)\s+found\s+in\s+(.+)/i;
      for (const line of lines) {
        const match = line.match(paramPattern);
        if (match) {
          const [, paramName, location] = match;
          results.push({
            result_type: 'api_parameter',
            result_data: { parameter: paramName, location: location.trim() },
            severity: 'low',
            source_tool: 'arjun',
          });
        }
      }
      break;
    }

    case 'api_fuzz_ffuf': {
      // Parse ffuf JSON output lines (when using -json flag)
      // Otherwise parse text lines: "200 123 http://host/api/FUZZ"
      for (const line of lines) {
        // Try JSON format first
        try {
          const json = JSON.parse(line);
          if (json.url) {
            results.push({
              result_type: 'api_endpoint',
              result_data: {
                url: json.url,
                status_code: json.status || json.status_code,
                length: json.length || json.content_length,
                words: json.words,
              },
              severity: 'info',
              source_tool: 'ffuf',
            });
          }
          continue;
        } catch { /* not JSON */ }

        // Text format: status_code size url
        const textMatch = line.match(/^(\d+)\s+(\d+)\s+(\S+)/);
        if (textMatch) {
          const [, statusCode, size, url] = textMatch;
          results.push({
            result_type: 'api_endpoint',
            result_data: { url, status_code: parseInt(statusCode), length: parseInt(size) },
            severity: 'info',
            source_tool: 'ffuf',
          });
        }
      }
      break;
    }

    case 'auth_audit': {
      // Parse nuclei auth template output (same JSON-lines format as vuln_scan)
      for (const line of lines) {
        try {
          const finding = JSON.parse(line);
          if (finding.type === 'finding' || finding.templateID) {
            results.push({
              result_type: 'auth_finding',
              result_data: {
                template_id: finding.templateID || finding.template_id || '',
                template_name: finding.info?.name || finding.name || '',
                severity: finding.info?.severity || finding.severity || 'info',
                host: finding.host || finding.matched || '',
                type: finding.type || '',
                extracted: finding.extracted || finding.matcher_name || '',
              },
              severity: finding.info?.severity || finding.severity || 'info',
              source_tool: 'nuclei',
            });
          }
        } catch {
          // Non-JSON line — try text format: "[template] http://host"
          const textMatch = line.match(/\[([^\]]+)\]\s+(https?:\/\/\S+)/);
          if (textMatch) {
            results.push({
              result_type: 'auth_finding',
              result_data: { template: textMatch[1], host: textMatch[2] },
              severity: 'info',
              source_tool: 'nuclei',
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
  db.prepare("UPDATE scan_tasks SET status = 'RUNNING', started_at = ?, target_profile = NULL, target_class = ? WHERE scan_task_id = ?")
    .run(now, normalizeTarget(task.target).target_class, scanTaskId);

  try {
    let parameters = {};
    try { parameters = JSON.parse(task.parameters || '{}'); } catch {}
    const timeoutSec = parameters.timeout || 300;
    const timeoutMs = timeoutSec * 1000;

    const runAbortableTool = (toolId, args, options) => {
      const controller = new AbortController();
      return raceScanWithAbort(runTool(toolId, args, { ...options, signal: controller.signal }), scanTaskId, controller);
    };

    // Helper: run one tool, parse results, store them
    const insertResult = db.prepare(`
      INSERT INTO scan_results (scan_task_id, result_type, result_data, severity, confidence, mitre_technique_id, source_tool, captured_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const outcomes = [];

    function recordFailure(toolId, error, result = {}) {
      const details = { error, exit_code: result.exitCode ?? null, timed_out: !!result.timedOut };
      insertResult.run(scanTaskId, 'scan_error', JSON.stringify(details), 'info', null, null, toolId, new Date().toISOString());
      outcomes.push({ tool_id: toolId, success: false, ...details });
    }

    async function runAndStore(scanType, toolId, target, params, timeout) {
      if (scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');
      let args = buildArgs(scanType, target, params);
      let result;
      try {
        result = classifyToolResult(toolId, await runAbortableTool(toolId, args, { timeout }));
      } catch (error) {
        recordFailure(toolId, error.message);
        throw error;
      }
      if (result.executionMode === 'aborted') throw new Error('扫描被操作员中止');
      if (!result.success && scanType === 'port_scan' && params.discover_topology
          && !result.timedOut && /traceroute|root|privileg|raw socket/i.test((result.stderr || '') + (result.error || ''))) {
        // A missing traceroute capability must not break the original scan.
        insertResult.run(scanTaskId, 'scan_warning', JSON.stringify({ message: '路由探测不可用，已回退到原端口扫描' }), 'info', null, null, toolId, new Date().toISOString());
        args = buildArgs(scanType, target, { ...params, discover_topology: false });
        result = classifyToolResult(toolId, await runAbortableTool(toolId, args, { timeout }));
        if (result.executionMode === 'aborted') throw new Error('扫描被操作员中止');
      }
      const output = (result.stdout || '') + (result.stderr ? '\n' + result.stderr : '');
      if (!result.success) {
        recordFailure(toolId, result.error || `${toolId} failed`, result);
        throw new Error(result.error || `${toolId} failed`);
      }
      outcomes.push({ tool_id: toolId, success: true, exit_code: result.exitCode, timed_out: false });
      const results = parseResults(scanType, output);
      if (toolId === 'nmap' && (scanType === 'topology_scan' || params.discover_topology)) {
        results.push({ result_type: 'scan_evidence', source_tool: toolId, severity: 'info',
          result_data: { output, args, executionMode: result.executionMode } });
      }
      if (['app_discovery_httpx', 'app_discovery_whatweb'].includes(scanType) && !results.some(result => ['http_probe', 'technology_detection'].includes(result.result_type))) {
        outcomes.pop();
        recordFailure(toolId, 'HTTP probe returned no reachable endpoints', result);
        throw new Error('HTTP probe returned no reachable endpoints');
      }
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
    let contextResults = 0;
    let networkContext = null;
    // Capture the scan source before probing, so failed targets do not erase it.
    if (task.scan_type === 'topology_scan' || (task.scan_type === 'port_scan' && parameters.discover_topology)) {
      // Inspect the same tool/container networking context; the backend's host
      // interfaces may belong to a different network namespace.
      const context = await runAbortableTool('nmap', ['--iflist'], { timeout: 15000 });
      if (context.success) {
        const data = { ...parseNmapInterfaces(context.stdout), executionMode: context.executionMode };
        networkContext = data;
        insertResult.run(scanTaskId, 'network_context', JSON.stringify(data), 'info', null, null, 'nmap', new Date().toISOString());
        contextResults++;
      } else if (context.executionMode !== 'aborted') {
        insertResult.run(scanTaskId, 'scan_warning', JSON.stringify({ message: '未能读取扫描环境路由，仅展示探测结果' }), 'info', null, null, 'nmap', new Date().toISOString());
      }
    }

    if (scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');

    if (task.scan_type === 'topology_scan') {
      totalResults = await runAndStore('topology_scan', 'nmap', task.target, parameters, timeoutMs);
    } else if (task.scan_type === 'web_scan') {
      // ── General web scan with optional explicit injection endpoint ──
      console.log(`[Scan] web_scan: nikto for ${task.target}`);
      try {
        totalResults += await runAndStore('web_scan_nikto', 'nikto', task.target, parameters, 120_000);
      } catch (err) {
        console.warn(`[Scan] nikto failed: ${err.message}`);
      }

      if (parameters.sqli_url) {
        console.log(`[Scan] web_scan SQL injection verification: ${parameters.sqli_url}`);
        try {
          const endpoint = new URL(parameters.sqli_url);
          if (endpoint.origin !== normalizeTarget(task.target).origin) throw new Error('SQL injection endpoint is outside the selected target');
          totalResults += await runAndStore('web_scan_sqlmap', 'sqlmap', endpoint.href, parameters, timeoutMs);
        } catch (err) {
          console.warn(`[Scan] sqlmap failed: ${err.message}`);
          if (!outcomes.some(outcome => outcome.tool_id === 'sqlmap')) recordFailure('sqlmap', err.message);
        }
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

    // ── Application target scan types ─────────────────────────────────
    } else if (task.scan_type === 'app_discovery') {
      try {
        const probes = await probeTarget(task.target);
        if (scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');
        for (const probe of probes) insertResult.run(scanTaskId, probe.result_type, JSON.stringify(probe.result_data), 'info', null, null, probe.source_tool, new Date().toISOString());
        totalResults += probes.length;
        outcomes.push({ tool_id: 'http-discovery', success: true, exit_code: 0, timed_out: false });
      } catch (err) {
        recordFailure('http-discovery', err.message);
      }
      // ── Dual-step: whatweb (tech fingerprint) + httpx (HTTP probe) ──
      console.log(`[Scan] app_discovery step 1/2: whatweb for ${task.target}`);
      try {
        totalResults += await runAndStore('app_discovery_whatweb', 'whatweb', task.target, parameters, 120_000);
      } catch (err) {
        console.warn(`[Scan] whatweb failed: ${err.message}`);
      }

      console.log(`[Scan] app_discovery step 2/2: httpx for ${task.target}`);
      try {
        totalResults += await runAndStore('app_discovery_httpx', 'httpx', task.target, parameters, 120_000);
      } catch (err) {
        console.warn(`[Scan] httpx failed: ${err.message}`);
      }

    } else if (task.scan_type === 'api_fuzz') {
      // ── Dual-step: arjun (param discovery) + ffuf (endpoint fuzzing) ──
      console.log(`[Scan] api_fuzz step 1/2: arjun for ${task.target}`);
      try {
        totalResults += await runAndStore('api_fuzz_arjun', 'arjun', task.target, parameters, timeoutMs);
      } catch (err) {
        console.warn(`[Scan] arjun failed: ${err.message}`);
      }

      console.log(`[Scan] api_fuzz step 2/2: ffuf for ${task.target}`);
      try {
        totalResults += await runAndStore('api_fuzz_ffuf', 'ffuf', task.target, parameters, timeoutMs);
      } catch (err) {
        console.warn(`[Scan] ffuf failed: ${err.message}`);
      }

    } else if (task.scan_type === 'auth_audit') {
      // ── Single-step: nuclei with auth/vuln templates ──
      console.log(`[Scan] auth_audit: nuclei for ${task.target}`);
      totalResults = await runAndStore('auth_audit', 'nuclei', task.target, parameters, timeoutMs);

    } else {
      // ── Single-tool scan types ──
      const toolId = SCAN_TOOL_MAP[task.scan_type];
      if (!toolId) throw new Error(`Unknown scan type: ${task.scan_type}`);
      totalResults = await runAndStore(task.scan_type, toolId, task.target, parameters, timeoutMs);
    }

    if (scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');
    if (networkContext) {
      const targetHosts = db.prepare("SELECT result_data FROM scan_results WHERE scan_task_id = ? AND result_type = 'host_discovery'")
        .all(scanTaskId).map(r => JSON.parse(r.result_data)).filter(d => !d.traceTarget).map(d => d.host);
      const scope = selectLanDiscoveryScope(task.target, networkContext, targetHosts);
      const storeLanResult = (type, data) => {
        insertResult.run(scanTaskId, type, JSON.stringify(data), 'info', null, null, 'nmap', new Date().toISOString());
        contextResults++;
      };
      if (!scope.cidr) storeLanResult('scan_warning', { phase: 'lan-discovery', message: scope.reason });
      else {
        const args = ['-sn', '-n', '--reason', '-e', scope.device, '--max-retries', '1', scope.cidr];
        try {
          const discovery = await runAbortableTool('nmap', args, { timeout: Math.min(timeoutMs, 120000) });
          if (discovery.executionMode === 'aborted' || scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');
          storeLanResult('scan_evidence', { phase: 'lan-discovery', args, output: discovery.stdout || '',
            error: discovery.stderr || discovery.error || '', executionMode: discovery.executionMode });
          const hosts = parseNmapResults(discovery.stdout || '').filter(r => r.result_type === 'host_discovery' && r.result_data.status === 'up');
          storeLanResult('lan_scope', { ...scope, complete: discovery.success === true && !discovery.timedOut });
          // A separate result type keeps neighboring assets out of target attack analysis.
          for (const host of hosts) storeLanResult('lan_host_discovery', { ...host.result_data, scope: scope.cidr });
          if (!discovery.success || discovery.timedOut) storeLanResult('scan_warning', { phase: 'lan-discovery',
            message: '局域网发现未完成，仅展示已响应主机；' + (discovery.error || discovery.stderr || '探测超时或失败') });
        } catch (error) {
          if (scanAbortFlags.get(scanTaskId)) throw error;
          storeLanResult('scan_warning', { phase: 'lan-discovery', message: '局域网发现失败：' + error.message });
        }
      }
    }
    totalResults += contextResults;

    if (scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');
    if (!outcomes.some(outcome => outcome.success)) throw new Error(outcomes.map(outcome => `${outcome.tool_id}: ${outcome.error}`).join('; ') || 'No scan tool succeeded');
    const finalStatus = outcomes.some(outcome => !outcome.success) ? 'PARTIAL' : 'COMPLETED';
    const warnings = outcomes.filter(outcome => !outcome.success).map(outcome => `${outcome.tool_id}: ${outcome.error}`).join('; ');
    const completedAt = new Date().toISOString();
    const findings = db.prepare('SELECT * FROM scan_results WHERE scan_task_id = ?').all(scanTaskId);
    const discovered = buildDiscoveredProfile(task.target, findings);
    db.prepare('UPDATE scan_tasks SET status = ?, completed_at = ?, error_message = ?, target_class = ?, target_profile = ? WHERE scan_task_id = ?')
      .run(finalStatus, completedAt, warnings || null, discovered.target_class, JSON.stringify(discovered), scanTaskId);
    // WebSocket: notify scan completed (include operator info)
    const ws = getWsManager();
    const taskInfo = db.prepare('SELECT created_by FROM scan_tasks WHERE scan_task_id = ?').get(scanTaskId);
    if (ws) ws.broadcast('scan:completed', {
      scanTaskId, status: finalStatus, resultsCount: totalResults, error: warnings || null,
      scanType: task.scan_type, target: task.target,
      userId: taskInfo?.created_by || null,
      username: taskInfo?.created_by || null,
    });

    return { ok: true, scanTaskId, status: finalStatus, resultsCount: totalResults, outcomes, targetProfile: discovered };

  } catch (err) {
    const isAbort = scanAbortFlags.get(scanTaskId);
    const finalStatus = isAbort ? 'CANCELLED' : 'FAILED';
    const completedAt = new Date().toISOString();
    db.prepare("UPDATE scan_tasks SET status = ?, completed_at = ?, error_message = ? WHERE scan_task_id = ?")
      .run(finalStatus, completedAt, err.message, scanTaskId);
    // WebSocket: notify scan failed/cancelled (include operator info)
    const ws = getWsManager();
    const taskInfo = db.prepare('SELECT created_by FROM scan_tasks WHERE scan_task_id = ?').get(scanTaskId);
    if (ws) ws.broadcast('scan:completed', {
      scanTaskId, status: finalStatus, error: err.message,
      scanType: task.scan_type, target: task.target,
      userId: taskInfo?.created_by || null,
      username: taskInfo?.created_by || null,
    });

    return { ok: false, scanTaskId, status: finalStatus, error: err.message };
  } finally {
    scanAbortFlags.delete(scanTaskId);
    runningScans.delete(scanTaskId);
  }
}
