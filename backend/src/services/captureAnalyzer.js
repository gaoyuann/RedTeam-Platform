// ── Capture Analyzer ────────────────────────────────────────────────────
// Analyzes captured PCAP files using tshark for protocol statistics,
// conversation tracking, credential detection, and anomaly identification.
import { getDb } from '../db/connection.js';
import { runTool } from '../tools/toolRunner.js';
import { getEngine } from '../tools/containerEngine.js';
import { getWsManager } from './wsManager.js';
import { existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..', '..');
const CAPTURES_DIR = resolve(PROJECT_ROOT, 'data', 'captures');

// ── Convert host PCAP path to container path ───────────────────────────
// Container mounts CAPTURES_DIR → /tmp/captures, so we need to translate
// host paths like /home/user/.../data/captures/cap_xxx.pcap → /tmp/captures/cap_xxx.pcap
function toContainerPcapPath(hostPath) {
  if (!hostPath) return hostPath;
  const basename = hostPath.split('/').pop();
  return `/tmp/captures/${basename}`;
}

// ── MITRE ATT&CK mapping rules ─────────────────────────────────────────
const MITRE_MAP = {
  'credential_ntlm':     { id: 'T1040',    name: 'Network Sniffing' },
  'credential_http':     { id: 'T1040',    name: 'Network Sniffing' },
  'credential_cookie':   { id: 'T1539',    name: 'Session Hijacking' },
  'exfil_large_upload':  { id: 'T1048',    name: 'Exfiltration Over Alternative Protocol' },
  'exfil_icmp_tunnel':   { id: 'T1048.003', name: 'Exfiltration Over Non-Standard Protocol: ICMP' },
  'exfil_dns_tunnel':    { id: 'T1048.003', name: 'Exfiltration Over Non-Standard Protocol: DNS' },
  'port_scan':           { id: 'T1046',    name: 'Network Service Discovery' },
};

// ── Main entry: analyzeCapture ──────────────────────────────────────────
export async function analyzeCapture(captureTaskId) {
  const db = getDb();
  const task = db.prepare(
    'SELECT capture_task_id, pcap_path, status FROM capture_tasks WHERE capture_task_id = ?'
  ).get(captureTaskId);

  if (!task) return { ok: false, error: 'Capture task not found' };
  if (!task.pcap_path || !existsSync(task.pcap_path)) {
    return { ok: false, error: 'PCAP file not found' };
  }

  // Determine PCAP path: container-mount path for tshark in container, host path for direct execution
  const engine = await getEngine();
  const pcapPath = engine === 'host' ? task.pcap_path : toContainerPcapPath(task.pcap_path);

  const ws = getWsManager();
  const insertAnalysis = db.prepare(`
    INSERT INTO capture_analysis (capture_task_id, analysis_type, analysis_data, severity, created_at)
    VALUES (?, ?, ?, ?, ?)
  `);

  // Clear old analysis results
  db.prepare('DELETE FROM capture_analysis WHERE capture_task_id = ?').run(captureTaskId);

  const results = [];

  // ── Step 1: Protocol breakdown ──────────────────────────────────────
  try {
    const protoResult = await runTool('tshark', [
      '-r', pcapPath,
      '-q', '-z', 'io,phs',
    ], { timeout: 60_000 });

    if (protoResult.stdout) {
      const protocols = parseProtocolHierarchy(protoResult.stdout);
      insertAnalysis.run(captureTaskId, 'protocol_breakdown', JSON.stringify(protocols), null, new Date().toISOString());
      results.push({ analysis_type: 'protocol_breakdown', data: protocols });
    }
  } catch (err) {
    console.warn(`[Analyze] Protocol breakdown failed: ${err.message}`);
  }

  // ── Step 2: Conversation tracking ───────────────────────────────────
  try {
    const convResult = await runTool('tshark', [
      '-r', pcapPath,
      '-q', '-z', 'conv,ip',
    ], { timeout: 60_000 });

    if (convResult.stdout) {
      const conversations = parseConversations(convResult.stdout);
      insertAnalysis.run(captureTaskId, 'conversation', JSON.stringify(conversations), null, new Date().toISOString());
      results.push({ analysis_type: 'conversation', data: conversations });
    }
  } catch (err) {
    console.warn(`[Analyze] Conversation tracking failed: ${err.message}`);
  }

  // ── Step 3: Credential detection ────────────────────────────────────
  try {
    const credentials = [];

    // HTTP Authorization headers
    const httpAuthResult = await runTool('tshark', [
      '-r', pcapPath,
      '-Y', 'http.authorization',
      '-T', 'fields',
      '-e', 'frame.time',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-e', 'http.authorization',
    ], { timeout: 30_000 });

    if (httpAuthResult.stdout) {
      for (const line of httpAuthResult.stdout.split('\n').filter(l => l.trim())) {
        const parts = line.split('\t');
        if (parts.length >= 4 && parts[3]) {
          credentials.push({
            type: 'http_basic',
            timestamp: parts[0],
            src_ip: parts[1],
            dst_ip: parts[2],
            detail: parts[3].length > 100 ? parts[3].substring(0, 100) + '...' : parts[3],
          });
        }
      }
    }

    // NTLM SSP authentication
    const ntlmResult = await runTool('tshark', [
      '-r', pcapPath,
      '-Y', 'ntlmssp',
      '-T', 'fields',
      '-e', 'frame.time',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-e', 'ntlmssp.messagetype',
    ], { timeout: 30_000 });

    if (ntlmResult.stdout) {
      for (const line of ntlmResult.stdout.split('\n').filter(l => l.trim())) {
        const parts = line.split('\t');
        if (parts.length >= 3) {
          credentials.push({
            type: 'ntlm',
            timestamp: parts[0],
            src_ip: parts[1],
            dst_ip: parts[2],
            detail: `NTLM ${parts[3] || 'auth'}`,
          });
        }
      }
    }

    // HTTP cookies (session hijacking evidence)
    const cookieResult = await runTool('tshark', [
      '-r', pcapPath,
      '-Y', 'http.cookie',
      '-T', 'fields',
      '-e', 'frame.time',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-e', 'http.cookie',
    ], { timeout: 30_000 });

    if (cookieResult.stdout) {
      for (const line of cookieResult.stdout.split('\n').filter(l => l.trim())) {
        const parts = line.split('\t');
        if (parts.length >= 4 && parts[3]) {
          credentials.push({
            type: 'cookie',
            timestamp: parts[0],
            src_ip: parts[1],
            dst_ip: parts[2],
            detail: parts[3].length > 100 ? parts[3].substring(0, 100) + '...' : parts[3],
          });
        }
      }
    }

    if (credentials.length > 0) {
      const severity = credentials.some(c => c.type === 'ntlm') ? 'critical' : 'high';
      insertAnalysis.run(captureTaskId, 'credential', JSON.stringify({ credentials }), severity, new Date().toISOString());
      results.push({ analysis_type: 'credential', data: { credentials }, severity });
    }
  } catch (err) {
    console.warn(`[Analyze] Credential detection failed: ${err.message}`);
  }

  // ── Step 4: Anomaly detection + MITRE mapping ───────────────────────
  try {
    const anomalies = [];
    const mitreMappings = [];

    // Check for ICMP tunnel indicators (large ICMP payloads)
    const icmpResult = await runTool('tshark', [
      '-r', pcapPath,
      '-Y', 'icmp',
      '-T', 'fields',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-e', 'frame.len',
    ], { timeout: 30_000 });

    if (icmpResult.stdout) {
      const icmpLines = icmpResult.stdout.split('\n').filter(l => l.trim());
      const largeIcmp = icmpLines.filter(l => {
        const parts = l.split('\t');
        return parts.length >= 3 && parseInt(parts[2], 10) > 100;
      });
      if (largeIcmp.length > 10) {
        anomalies.push({
          type: 'exfil_icmp_tunnel',
          severity: 'high',
          description: `检测到 ${largeIcmp.length} 个大尺寸 ICMP 包 (>100字节)，可能为 ICMP 隧道/隐蔽信道`,
        });
        const m = MITRE_MAP['exfil_icmp_tunnel'];
        mitreMappings.push({ ...m, matched_by: 'icmp_tunnel_detection', confidence: 'medium' });
      }
    }

    // Check for DNS tunnel indicators (long DNS queries)
    const dnsResult = await runTool('tshark', [
      '-r', pcapPath,
      '-Y', 'dns.qry.name',
      '-T', 'fields',
      '-e', 'dns.qry.name',
      '-e', 'frame.len',
    ], { timeout: 30_000 });

    if (dnsResult.stdout) {
      const dnsLines = dnsResult.stdout.split('\n').filter(l => l.trim());
      const longDns = dnsLines.filter(l => {
        const parts = l.split('\t');
        return parts.length >= 1 && parts[0].length > 50;
      });
      if (longDns.length > 5) {
        anomalies.push({
          type: 'exfil_dns_tunnel',
          severity: 'high',
          description: `检测到 ${longDns.length} 个超长 DNS 查询 (>50字符)，可能为 DNS 隧道`,
        });
        const m = MITRE_MAP['exfil_dns_tunnel'];
        mitreMappings.push({ ...m, matched_by: 'dns_tunnel_detection', confidence: 'medium' });
      }
    }

    // Map credentials to MITRE
    const credAnalysis = results.find(r => r.analysis_type === 'credential');
    if (credAnalysis) {
      const creds = credAnalysis.data.credentials || [];
      const ntlmCreds = creds.filter(c => c.type === 'ntlm');
      const httpCreds = creds.filter(c => c.type === 'http_basic');
      const cookieCreds = creds.filter(c => c.type === 'cookie');

      if (ntlmCreds.length > 0) {
        const m = MITRE_MAP['credential_ntlm'];
        mitreMappings.push({ ...m, matched_by: 'ntlm_credential_capture', confidence: 'high' });
      }
      if (httpCreds.length > 0) {
        const m = MITRE_MAP['credential_http'];
        mitreMappings.push({ ...m, matched_by: 'http_credential_capture', confidence: 'high' });
      }
      if (cookieCreds.length > 0) {
        const m = MITRE_MAP['credential_cookie'];
        mitreMappings.push({ ...m, matched_by: 'cookie_capture', confidence: 'medium' });
      }
    }

    // Store anomalies
    if (anomalies.length > 0) {
      const maxSeverity = anomalies.some(a => a.severity === 'high') ? 'high' : 'medium';
      insertAnalysis.run(captureTaskId, 'anomaly', JSON.stringify({ anomalies }), maxSeverity, new Date().toISOString());
      results.push({ analysis_type: 'anomaly', data: { anomalies }, severity: maxSeverity });
    }

    // Store MITRE mappings
    if (mitreMappings.length > 0) {
      insertAnalysis.run(captureTaskId, 'mitre_mapping', JSON.stringify({ mappings: mitreMappings }), null, new Date().toISOString());
      results.push({ analysis_type: 'mitre_mapping', data: { mappings: mitreMappings } });
    }
  } catch (err) {
    console.warn(`[Analyze] Anomaly detection failed: ${err.message}`);
  }

  // WebSocket: notify analysis completed
  if (ws) ws.broadcast('capture:analyzed', { captureTaskId, resultCount: results.length });

  return { ok: true, captureTaskId, resultCount: results.length, results };
}

// ── Parser: Protocol hierarchy statistics ───────────────────────────────
function parseProtocolHierarchy(stdout) {
  const protocols = [];
  const lines = stdout.split('\n').filter(l => l.trim());

  for (const line of lines) {
    // tshark io,phs output formats:
    //   With labels:  "  tcp                                  frames:2198 bytes:2863946"
    //   Bare numbers: "  tcp                                       2198          2863946"
    //   With |- prefix (some versions): "  |-tcp                              frames:2198 bytes:2863946"
    // Strip leading hierarchy markers (|, |-) then match protocol name + counts
    const match = line.match(/^\s*(?:\|?-+)?(\w[\w.-]*)\s+(?:frames:)?(\d+)\s+(?:bytes:)?(\d+)/);
    if (match) {
      const name = match[1];
      const packets = parseInt(match[2], 10);
      const bytes = parseInt(match[3], 10);
      // Only include major protocols (skip internal layers like sll, data, tcp.segments)
      if (['ip', 'tcp', 'udp', 'icmp', 'http', 'dns', 'tls', 'ssh', 'ftp', 'smb', 'arp', 'ipv6', 'http2', 'ntp'].includes(name.toLowerCase())) {
        protocols.push({ name, packets, bytes });
      }
    }
  }

  return { protocols, total_packets: protocols.reduce((s, p) => s + p.packets, 0) };
}

// ── Parser: IP conversations ───────────────────────────────────────────
function parseConversations(stdout) {
  const conversations = [];
  const lines = stdout.split('\n').filter(l => l.trim());

  // Helper: parse tshark number with optional unit suffix (e.g. "2861 kB", "0 bytes", plain "30000")
  function parseNumWithUnit(str) {
    if (!str) return 0;
    const m = str.match(/^(\d+(?:\.\d+)?)/);
    if (!m) return 0;
    let val = parseFloat(m[1]);
    const lower = str.toLowerCase();
    if (lower.includes('kb') || lower.includes('kbyte')) val *= 1024;
    else if (lower.includes('mb') || lower.includes('mbyte')) val *= 1024 * 1024;
    else if (lower.includes('gb') || lower.includes('gbyte')) val *= 1024 * 1024 * 1024;
    else if (lower.includes('bytes') || lower.includes('byte')) { /* already in bytes */ }
    return Math.round(val);
  }

  for (const line of lines) {
    // tshark conv,ip output format (numbers may have unit suffixes like "kB", "bytes"):
    //   127.0.0.1  <-> 127.0.0.1    0 0 bytes    2171 2861 kB    2171 2861 kB    0.000    58.2073
    //   10.0.0.1   <-> 10.0.0.2     150 30000    200 40000       350 70000       0.000    30.5
    // Split on "<->" first, then parse each side
    const arrowIdx = line.indexOf('<->');
    if (arrowIdx === -1) continue;

    const leftPart = line.substring(0, arrowIdx).trim();
    const rightPart = line.substring(arrowIdx + 3).trim();
    const srcIp = leftPart;

    // rightPart: "10.0.0.2    0 0 bytes    2171 2861 kB    2171 2861 kB    0.000    58.2073"
    // Tokenize and parse
    const tokens = rightPart.split(/\s+/);
    if (tokens.length < 2) continue;
    const dstIp = tokens[0];
    const rest = tokens.slice(1).join(' ');

    // Match 6 number groups (possibly with unit suffixes) + 2 time fields at end
    // Groups: tx_packets tx_bytes rx_packets rx_bytes total_packets total_bytes [start_time] [duration]
    // Use a regex that captures number+unit pairs
    const numPattern = /(\d+(?:\.\d+)?\s*(?:bytes|kB|KB|MB|GB|kbyte|mbyte|gbyte)?)/gi;
    const numMatches = [...rest.matchAll(numPattern)].map(m => parseNumWithUnit(m[1]));

    if (numMatches.length >= 6) {
      conversations.push({
        src_ip: srcIp,
        dst_ip: dstIp,
        tx_packets: numMatches[0],
        tx_bytes: numMatches[1],
        rx_packets: numMatches[2],
        rx_bytes: numMatches[3],
        total_packets: numMatches[4],
        total_bytes: numMatches[5],
      });
    }
  }

  // Sort by total bytes descending, keep top 20
  conversations.sort((a, b) => b.total_bytes - a.total_bytes);
  return { conversations: conversations.slice(0, 20) };
}
