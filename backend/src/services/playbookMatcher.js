import { getDb } from '../db/connection.js';
import { resolveTargetProfile, checkTargetTypeCompatibility } from './targetProfileResolver.js';

// result_type → baseline_group mapping
const RESULT_TYPE_MAP = {
  open_port: 'recon',
  vulnerability: 'vuln_scan',
  web_vuln: 'vuln_scan',        // nikto findings
  sql_injection: 'exploit',     // sqlmap findings
  credential: 'brute',          // hydra findings
  weak_credential: 'brute',
  service_info: 'recon',
  misconfiguration: 'vuln_scan',
};

// Port-based overrides for open_port results
const PORT_GROUP_MAP = {
  445: 'brute', 139: 'brute',       // SMB
  22: 'brute',                       // SSH
  3389: 'brute',                     // RDP
  80: 'vuln_scan', 443: 'vuln_scan', // Web
  3306: 'exploit', 5432: 'exploit',  // DB
};

// Port + target_class → preferred baseline_group (stronger than port-only)
const PORT_CLASS_GROUP_MAP = {
  '22:local_ip': 'impact-demonstration',   // SSH to Linux → kylin playbooks
  '22:linux_host': 'impact-demonstration',
  '80:local_ip': 'web-vuln-scan',          // Web on Linux → DVWA/web playbooks
  '8080:local_ip': 'web-vuln-scan',
  '5080:local_ip': 'web-vuln-scan',
  '445:windows_ad': 'windows-exploitation', // SMB to AD → Windows playbooks
  '3389:windows_ad': 'windows-exploitation',
};

// Severity weight
const SEVERITY_WEIGHT = { critical: 4, high: 3, medium: 2, low: 1, info: 0.5 };

export function matchPlaybooks(scanResults, targetClass = null) {
  const db = getDb();

  // Load all non-generated playbooks
  const playbooks = db.prepare(
    `SELECT playbook_id, name, difficulty, baseline_group, mitre_techniques, target_type
     FROM playbooks WHERE is_generated = 0`
  ).all();

  // Parse mitre_techniques JSON for each playbook
  const pbParsed = playbooks.map(pb => ({
    ...pb,
    mitreSet: new Set(tryJson(pb.mitre_techniques)),
    targetTypes: tryJson(pb.target_type),
  }));

  // Score each playbook
  const scores = new Map();
  const reasons = new Map();

  for (const result of scanResults) {
    const sev = SEVERITY_WEIGHT[result.severity] || 1;

    // 1) MITRE exact match (highest priority)
    if (result.mitre_technique_id) {
      for (const pb of pbParsed) {
        if (pb.mitreSet.has(result.mitre_technique_id)) {
          addScore(pb.playbook_id, sev * 3, `MITRE ${result.mitre_technique_id}`);
        }
      }
    }

    // 2) Severity-driven: result_type → baseline_group
    let group = RESULT_TYPE_MAP[result.result_type] || 'recon';

    // Port override for open_port results
    if (result.result_type === 'open_port') {
      try {
        const data = JSON.parse(result.result_data || '{}');
        const port = data.port || data.port_number;
        if (port && PORT_GROUP_MAP[port]) group = PORT_GROUP_MAP[port];
        // Port + target_class specific override (stronger signal)
        if (port && targetClass) {
          const key = `${port}:${targetClass}`;
          if (PORT_CLASS_GROUP_MAP[key]) group = PORT_CLASS_GROUP_MAP[key];
        }
      } catch {}
    }

    // Vulnerability subtype override
    if (result.result_type === 'vulnerability') {
      try {
        const data = JSON.parse(result.result_data || '{}');
        if (data.vuln_type?.includes('sql') || data.title?.toLowerCase().includes('sql')) group = 'exploit';
        if (data.vuln_type?.includes('xss') || data.title?.toLowerCase().includes('xss')) group = 'exploit';
      } catch {}
    }

    for (const pb of pbParsed) {
      if (pb.baseline_group === group) {
        addScore(pb.playbook_id, sev * 2, `${result.result_type} → ${group}`);
      }
    }

    // 3) Fallback: recon for medium/low
    if ((result.severity === 'medium' || result.severity === 'low') && group !== 'recon') {
      for (const pb of pbParsed) {
        if (pb.baseline_group === 'recon') {
          addScore(pb.playbook_id, sev * 0.5, 'low-severity fallback → recon');
        }
      }
    }
  }

  // ── Target type compatibility scoring ──────────────────────────────
  if (targetClass) {
    for (const pb of pbParsed) {
      if (pb.targetTypes && pb.targetTypes.length > 0 && !pb.targetTypes.includes('any')) {
        const compat = checkTargetTypeCompatibility(pb.targetTypes, targetClass);
        if (!compat.ok) {
          // Incompatible playbook: heavy penalty (but don't fully exclude)
          addScore(pb.playbook_id, -5, `target_type mismatch: [${pb.targetTypes.join(',')}] vs ${targetClass}`);
        } else {
          // Compatible: bonus
          addScore(pb.playbook_id, 1, `target_type match: ${targetClass}`);
        }
        // Extra penalty: DVWA-only playbooks recommended for non-DVWA local_ip targets
        // (e.g. don't recommend golden_dvwa_max_tools for a Linux SSH host)
        if (targetClass === 'local_ip' && pb.targetTypes.includes('dvwa') && !pb.targetTypes.includes('local_ip')) {
          addScore(pb.playbook_id, -3, `DVWA-only playbook for non-DVWA local_ip target`);
        }
        // Extra bonus: playbooks that explicitly list local_ip for local_ip targets
        if (targetClass === 'local_ip' && pb.targetTypes.includes('local_ip')) {
          addScore(pb.playbook_id, 3, `explicit local_ip match`);
        }
      }
    }
  }

  // Build ranked result
  const ranked = [];
  for (const [id, score] of scores) {
    const pb = pbParsed.find(p => p.playbook_id === id);
    if (!pb) continue;
    ranked.push({
      playbook_id: pb.playbook_id,
      name: pb.name,
      difficulty: pb.difficulty,
      baseline_group: pb.baseline_group,
      match_reason: [...new Set(reasons.get(id))].slice(0, 3).join('; '),
      match_score: Math.round(score * 10) / 10,
    });
  }

  ranked.sort((a, b) => b.match_score - a.match_score);
  return ranked.slice(0, 10);

  function addScore(pbId, delta, reason) {
    scores.set(pbId, (scores.get(pbId) || 0) + delta);
    if (!reasons.has(pbId)) reasons.set(pbId, []);
    reasons.get(pbId).push(reason);
  }
}

function tryJson(str) {
  try { return JSON.parse(str || '[]'); } catch { return []; }
}
