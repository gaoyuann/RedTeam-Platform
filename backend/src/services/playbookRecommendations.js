import { buildDiscoveredProfile } from './targetDiscovery.js';
import { matchPlaybooks } from './playbookMatcher.js';
import { planScanSources, planObservationTypesExcluded } from './planScanSources.js';

export function recommendForScans(db, target, scanTaskIds) {
  const identifiers = [...new Set((Array.isArray(scanTaskIds) ? scanTaskIds : [scanTaskIds])
    .filter(identifier => typeof identifier === 'string' && identifier))];
  if (!identifiers.length) return [];
  const scans = planScanSources(db, target, identifiers);
  const scopedResults = scans.flatMap(scan => db.prepare('SELECT * FROM scan_results WHERE scan_task_id = ?').all(scan.scan_task_id))
    .filter(result => matchesTarget(result, target));
  const results = scopedResults.filter(result => !planObservationTypesExcluded.includes(result.result_type));
  const completedActions = new Set();
  for (const scan of scans) {
    // Diagnostics do not supply matching evidence, but must still prevent a
    // failed/partial tool check from being labelled as already completed.
    const findings = scopedResults.filter(result => result.scan_task_id === scan.scan_task_id);
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
