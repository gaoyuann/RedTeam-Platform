import { buildDiscoveredProfile } from './targetDiscovery.js';
import { matchPlaybooks } from './playbookMatcher.js';

export function recommendForScans(db, target, scanTaskIds) {
  const identifiers = [...new Set((Array.isArray(scanTaskIds) ? scanTaskIds : [scanTaskIds])
    .filter(identifier => typeof identifier === 'string' && identifier))];
  if (!identifiers.length) return [];
  const scans = db.prepare(`SELECT scan_task_id, scan_type, status FROM scan_tasks
    WHERE scan_task_id IN (${identifiers.map(() => '?').join(',')}) AND target = ? AND status IN ('COMPLETED', 'PARTIAL')`)
    .all(...identifiers, target);
  const results = scans.flatMap(scan => db.prepare('SELECT * FROM scan_results WHERE scan_task_id = ?').all(scan.scan_task_id))
    .filter(result => matchesTarget(result, target));
  const completedActions = new Set();
  for (const scan of scans) {
    const findings = results.filter(result => result.scan_task_id === scan.scan_task_id);
    const failedTools = new Set(findings.filter(result => ['scan_error', 'scan_warning'].includes(result.result_type)).map(result => result.source_tool));
    for (const finding of findings) {
      if (failedTools.has(finding.source_tool)) continue;
      if (finding.result_type === 'open_port' && finding.source_tool === 'nmap') completedActions.add('nmap:ports');
      if (['http_probe', 'technology_detection'].includes(finding.result_type) && ['whatweb', 'httpx'].includes(finding.source_tool)) {
        completedActions.add(`${finding.source_tool}:fingerprint`);
      }
      if (scan.scan_type === 'web_scan' && finding.result_type === 'web_vuln' && finding.source_tool === 'nikto') completedActions.add('nikto:web');
    }
  }
  return matchPlaybooks(results, buildDiscoveredProfile(target, results), { completedActions: [...completedActions], target });
}

function matchesTarget(result, target) {
  let data;
  try { data = JSON.parse(result.result_data); } catch { return false; }
  const address = data?.url || data?.matched_at || data?.['matched-at'];
  if (!address) return true;
  try {
    const targetUrl = new URL(/^https?:\/\//i.test(target) ? target : `http://${target}`);
    const findingUrl = new URL(address, targetUrl);
    return /^https?:\/\//i.test(target) ? findingUrl.origin === targetUrl.origin
      : findingUrl.hostname === targetUrl.hostname;
  } catch { return false; }
}
