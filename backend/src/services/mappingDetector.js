/**
 * RuntimeMappingDetector - Detects candidate tool-to-technique mappings from tool output
 * Ported from RedTeam-Edu: backend/src/knowledge/runtimeMappingDetector.js
 */

// 18 signal patterns for runtime mapping detection
const SIGNAL_LIBRARY = [
  { toolPattern: /nmap/i, technique: 'T1046', triggerKeywords: ['port', 'open', 'service', 'tcp'], confidence: 0.85 },
  { toolPattern: /nmap/i, technique: 'T1595', triggerKeywords: ['scan report', 'host is up'], confidence: 0.80 },
  { toolPattern: /whatweb/i, technique: 'T1592', triggerKeywords: ['httpserver', 'x-powered-by', 'php', 'apache', 'nginx'], confidence: 0.80 },
  { toolPattern: /(gobuster|ffuf)/i, technique: 'T1595.003', triggerKeywords: ['status: 200', 'status: 301', 'status: 403'], confidence: 0.85 },
  { toolPattern: /amass/i, technique: 'T1596', triggerKeywords: ['fqdn', 'subdomain', 'a record'], confidence: 0.80 },
  { toolPattern: /nuclei/i, technique: 'T1190', triggerKeywords: ['critical', 'high', 'cve-', 'vulnerability'], confidence: 0.80 },
  { toolPattern: /nikto/i, technique: 'T1595', triggerKeywords: ['osvdb-', 'cve-', 'server:'], confidence: 0.80 },
  { toolPattern: /hydra/i, technique: 'T1110', triggerKeywords: ['login:', 'password:', 'success', 'valid password'], confidence: 0.85 },
  { toolPattern: /(hashcat|john)/i, technique: 'T1110.002', triggerKeywords: ['cracked', 'password', 'hash', 'recovered'], confidence: 0.85 },
  { toolPattern: /responder/i, technique: 'T1557.001', triggerKeywords: ['ntlm', 'ntlmv2', 'hash captured'], confidence: 0.85 },
  { toolPattern: /sqlmap/i, technique: 'T1190', triggerKeywords: ['injectable', 'vulnerable', 'payload', 'back-end dbms'], confidence: 0.85 },
  { toolPattern: /(netexec|crackmapexec)/i, technique: 'T1021.002', triggerKeywords: ['smb', 'admin$', 'pwn3d', 'login successful'], confidence: 0.85 },
  { toolPattern: /evil-winrm/i, technique: 'T1021.006', triggerKeywords: ['winrm', 'ps c:', 'evil-winrm'], confidence: 0.85 },
  { toolPattern: /(smbmap|smbclient)/i, technique: 'T1021.002', triggerKeywords: ['disk', 'permissions', 'share'], confidence: 0.80 },
  { toolPattern: /(linpeas|winpeas)/i, technique: 'T1068', triggerKeywords: ['vulnerable', 'cve-', 'suid', 'sudo'], confidence: 0.75 },
  { toolPattern: /cloudmapper/i, technique: 'T1526', triggerKeywords: ['ec2', 's3', 'iam', 'vpc'], confidence: 0.80 },
  { toolPattern: /pacu/i, technique: 'T1526', triggerKeywords: ['privilegeescalation', 'enumeration', 'iam'], confidence: 0.80 },
  { toolPattern: /arjun/i, technique: 'T1595', triggerKeywords: ['parameter', 'reflected', 'discovered'], confidence: 0.70 },
];

/**
 * Detect candidate tool-to-technique mappings from successful tool output.
 *
 * @param {object} params
 * @param {string} params.toolId - the tool ID (e.g. 'nmap', 'nuclei')
 * @param {string} params.stdout - stdout from tool execution
 * @param {boolean} params.success - whether the tool execution succeeded
 * @returns {{ candidates: Array<{toolId, techniqueId, confidence, signal, snippet}> }}
 */
export function detectMappings({ toolId, stdout, success }) {
  if (!success || !stdout) return { candidates: [] };

  const candidates = [];
  const output = stdout.toLowerCase();

  for (const signal of SIGNAL_LIBRARY) {
    // Check if tool matches this signal's pattern
    if (!signal.toolPattern.test(toolId)) continue;

    // Count matching keywords in the output
    const matchedKeywords = signal.triggerKeywords.filter(kw => output.includes(kw.toLowerCase()));
    if (matchedKeywords.length === 0) continue;

    // Adjust confidence based on how many keywords matched
    const matchRatio = matchedKeywords.length / signal.triggerKeywords.length;
    const adjustedConfidence = Math.min(0.95, signal.confidence * (0.7 + 0.3 * matchRatio));

    // Skip very low confidence matches
    if (adjustedConfidence < 0.5) continue;

    candidates.push({
      toolId,
      techniqueId: signal.technique,
      confidence: Math.round(adjustedConfidence * 100) / 100,
      signal: signal.toolPattern.source,
      snippet: matchedKeywords.slice(0, 3).join(', '),
    });
  }

  // Deduplicate by techniqueId, keeping highest confidence
  const deduped = [];
  const seen = new Set();
  for (const c of candidates.sort((a, b) => b.confidence - a.confidence)) {
    if (!seen.has(c.techniqueId)) {
      seen.add(c.techniqueId);
      deduped.push(c);
    }
  }

  return { candidates: deduped };
}

/**
 * Batch detect mappings across multiple tool executions.
 *
 * @param {Array<{toolId: string, stdout: string, success: boolean}>} results
 * @returns {{ allCandidates: Array, summary: object }}
 */
export function batchDetectMappings(results) {
  const allCandidates = [];
  const toolCounts = {};

  for (const r of results) {
    const { candidates } = detectMappings(r);
    for (const c of candidates) {
      allCandidates.push(c);
      toolCounts[c.techniqueId] = (toolCounts[c.techniqueId] || 0) + 1;
    }
  }

  return {
    allCandidates,
    summary: {
      totalCandidates: allCandidates.length,
      uniqueTechniques: Object.keys(toolCounts).length,
      techniqueCounts: toolCounts,
    },
  };
}

/**
 * Get the full signal library (for testing/inspection).
 */
export function getSignalLibrary() {
  return SIGNAL_LIBRARY.map(s => ({
    toolPattern: s.toolPattern.source,
    technique: s.technique,
    triggerKeywords: s.triggerKeywords,
    baseConfidence: s.confidence,
  }));
}

export { SIGNAL_LIBRARY };
