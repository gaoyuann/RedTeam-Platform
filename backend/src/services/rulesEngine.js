/**
 * Rules Engine
 *
 * Matches tool output against rulespecs (regex on stdout/stderr) to produce
 * MITRE hits + tool recommendations.
 *
 * Ported from RedTeam-Edu: backend/src/hexstrike/rulesEngine.js
 * Adapted: uses specLoader from ./specLoader.js, parsers from ./parsers.js
 */

import { loadRuleSpecs, getRuleSpec } from './specLoader.js';
import { parseNmap, parseWhatweb, parseGobuster, parseSqlmap, parseHttpx,
         parseAmass, parseNetexec, parseArjun, parseResponder,
         parseJohn, parseEvilWinrm, parseCurl } from './parsers.js';

function testRegex(pattern, text) {
  if (!pattern) return true;
  try {
    const re = new RegExp(pattern, 'i');
    return re.test(text || '');
  } catch {
    return false;
  }
}

export function extractEvidence({ toolId, stdout = '', stderr = '', target = null }) {
  // Defensive: ensure stdout/stderr are strings (tool results may be null)
  stdout = stdout || '';
  stderr = stderr || '';
  const raw = { stdout, stderr };

  try {
    if (toolId === 'nmap') {
      const base = parseNmap(stdout) || {};
      const ports = (base.openPorts || []).map(p => {
        const vRe = new RegExp(`${p.port}\\/${p.proto}\\s+open\\s+\\S+\\s+([^\\n\\r]+)`, 'im');
        const vMatch = stdout.match(vRe);
        return {
          port: p.port,
          proto: p.proto,
          service: p.service,
          version: vMatch ? vMatch[1].trim() : ''
        };
      });

      const osMatch = stdout.match(/OS details: (.+)/i) || stdout.match(/OS: (.+)/i);
      const os = osMatch ? osMatch[1].trim() : null;

      return {
        type: 'port_scan',
        data: { ports, openPorts: base.openPorts || [], os, hostUp: /Host is up/i.test(stdout) },
        raw, target
      };
    }

    if (toolId === 'whatweb') {
      const technologies = [];
      const matches = stdout.match(/\[([^\]]+)\]/g) || [];
      for (const m of matches) {
        const name = m.replace(/[\[\]]/g, '').trim();
        if (name && !/^(HTTP|Status|IP|Country)/i.test(name)) {
          technologies.push(name);
        }
      }
      const base = parseWhatweb(stdout) || {};
      const titleMatch = stdout.match(/Title\[(.*?)\]/i);
      return {
        type: 'web_fingerprint',
        data: { technologies: Array.from(new Set([...(base.tech || []), ...technologies])), title: titleMatch ? titleMatch[1] : null },
        raw, target
      };
    }

    if (toolId === 'gobuster' || toolId === 'dirb' || toolId === 'ffuf') {
      const discovered = [];
      const lines = stdout.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed.startsWith('/')) continue;
        if (trimmed.includes('Status: 200') || trimmed.includes('(CODE:200)') ||
            trimmed.includes('Status: 301') || trimmed.includes('(CODE:301)') ||
            trimmed.includes('Status: 403') || trimmed.includes('(CODE:403)')) {
          const path = trimmed.split(/\s+/)[0].trim();
          discovered.push(path);
        }
      }
      const base = parseGobuster(stdout) || {};
      return {
        type: 'dir_enum',
        data: { discovered: Array.from(new Set([...(base.hits || []).map(h => h.path), ...discovered])) },
        raw, target
      };
    }

    if (toolId === 'sqlmap') {
      const parsed = parseSqlmap(stdout);
      const findings = [];
      if (parsed.injectable) findings.push({ type: 'sqli_injectable', value: parsed.injectionTypes });
      if (parsed.databases.length > 0) findings.push({ type: 'sqli_databases', value: parsed.databases });
      if (parsed.dumpedTables.length > 0) findings.push({ type: 'sqli_dump', value: parsed.dumpedTables.map(t => `${t.db}.${t.table}`) });
      if (parsed.crackedPasswords.length > 0) findings.push({ type: 'sqli_cracked', value: parsed.crackedPasswords.map(p => p.plaintext) });
      if (parsed.tamperUsed) findings.push({ type: 'sqli_tamper', value: true });

      const markdownReport = parsed.dumpedTables.length > 0
        ? parsed.dumpedTables.map(t =>
            `**Database:** \`${t.db}\`  **Table:** \`${t.table}\`  (${t.entryCount} rows)\n\n${t.markdownTable}`
          ).join('\n\n---\n\n')
        : null;

      return {
        type: 'sqli_attack',
        data: { injectable: parsed.injectable, injectionTypes: parsed.injectionTypes, databases: parsed.databases,
                dumpedTables: parsed.dumpedTables.map(t => ({ db: t.db, table: t.table, entryCount: t.entryCount, columns: t.columns, markdownTable: t.markdownTable })),
                crackedPasswords: parsed.crackedPasswords, tamperUsed: parsed.tamperUsed, wafBypassed: parsed.wafBypassed,
                summary: parsed.summary, markdownReport, findings },
        raw, target
      };
    }

    if (toolId === 'amass') {
      const results = parseAmass(stdout);
      return { type: 'subdomain_enum', data: { subdomains: results.subdomains }, raw, target };
    }

    if (toolId === 'httpx') {
      const results = parseHttpx(stdout);
      return {
        type: 'web_recon_httpx',
        data: { liveUrls: results.map(r => r.url), technologies: Array.from(new Set(results.flatMap(r => r.tech || []))),
                titles: results.map(r => r.title).filter(Boolean), fullResults: results },
        raw, target
      };
    }

    if (toolId === 'netexec') {
      const results = parseNetexec(stdout);
      return { type: 'ad_enum', data: { shares: results.shares, users: results.users }, raw, target };
    }

    if (toolId === 'arjun') {
      const results = parseArjun(stdout || stderr);
      return { type: 'web_param_enum', data: { params: results.params, noParamsFound: results.noParamsFound }, raw, target };
    }

    if (toolId === 'responder') {
      const results = parseResponder(stdout);
      return { type: 'ntlm_hash_capture', data: { capturedHashes: results.capturedHashes }, raw, target };
    }

    if (toolId === 'john') {
      const results = parseJohn(stdout);
      return { type: 'cracked_password', data: { cracked: results.crackedPasswords }, raw, target };
    }

    if (toolId === 'evil-winrm') {
      const results = parseEvilWinrm(stdout);
      return { type: 'remote_shell', data: { user: results.user, cwd: results.cwd }, raw, target };
    }

    const ansiRegex = /[][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g;

    if (toolId === 'nuclei') {
      const cleanOutput = stdout.replace(ansiRegex, '');
      const vulnerabilities = [];
      const lines = cleanOutput.split(/\r?\n/);
      const nucleiRegex = /\[(.*?)\] \[(.*?)\] \[(.*?)\] (http\S+)(?: \[(.*?)\])?/;
      for (const line of lines) {
        const match = line.match(nucleiRegex);
        if (match) {
          vulnerabilities.push({ ruleId: match[1], protocol: match[2], severity: match[3], url: match[4], extracted_data: match[5] || null });
        }
      }
      return { type: 'vulnerability_scan', data: { vulnerabilities }, raw, target };
    }

    if (toolId === 'hydra') {
      const cleanOutput = stdout.replace(ansiRegex, '');
      const credentials = [];
      const lines = cleanOutput.split(/\r?\n/);
      const hydraRegex = /login:\s*([^\s]+)\s*password:\s*([^\s]+)/i;
      for (const line of lines) {
        const match = line.match(hydraRegex);
        if (match) credentials.push({ username: match[1], password: match[2] });
      }
      const summaryMatch = cleanOutput.match(/(\d+)\s+valid\s+password[s]?\s+found/i);
      const count = summaryMatch ? parseInt(summaryMatch[1], 10) : credentials.length;
      let message = count > 0
        ? `爆破完成：提取到 ${count} 个密码`
        : `爆破受阻：未发现有效凭据`;
      return { type: 'credential_brute_force', data: { credentials, message }, raw, target };
    }

    if (toolId === 'nikto') {
      const cleanOutput = stdout.replace(ansiRegex, '');
      const findings = [];
      const lines = cleanOutput.split(/\r?\n/);
      for (const line of lines) {
        if (/OSVDB|CVE-/i.test(line)) findings.push(line.trim());
      }
      return { type: 'vulnerability_scan', data: { findings, source: 'nikto' }, raw, target };
    }

    if (toolId === 'curl') {
      const parsed = parseCurl(stdout || stderr);
      return { type: 'http_request', data: { statusCode: parsed.statusCode, title: parsed.title, server: parsed.server, contentType: parsed.contentType, location: parsed.location, cookies: parsed.cookies, contentLength: parsed.contentLength }, raw, target };
    }

    if (toolId === 'http_webshell' || toolId === 'webshell' || toolId === 'webshell_health') {
      const output = (stdout || '').trim();
      const userMatch = output.match(/(www-data|apache|nobody|daemon|root)/i);
      const uidMatch = output.match(/uid=(\d+)\(/);
      const pwdMatch = output.match(/^((?:\/[^\/\n\r\t ]+)+)$/m);
      return {
        type: 'rce_shell',
        data: { user: userMatch ? userMatch[1] : null, uid: uidMatch ? parseInt(uidMatch[1], 10) : null,
                isRoot: /uid=0\(root\)/i.test(output) || /\broot\b/i.test(output), cwd: pwdMatch ? pwdMatch[1] : null, rawOutput: output },
        raw, target
      };
    }

    return { type: 'unknown', data: {}, raw, target };
  } catch (e) {
    console.error(`[rulesEngine] extractEvidence failed for ${toolId}:`, e?.message || e);
    return { type: 'parse_error', data: {}, raw, target, error: e?.message || String(e) };
  }
}

export function evalRule(rule, { toolId, stdout = '', stderr = '', target = null }) {
  if (!rule) return { matched: false, reason: 'rule not found' };

  const when = rule.when || {};
  if (when.toolId && when.toolId !== toolId) return { matched: false, reason: 'toolId mismatch' };
  if (!testRegex(when.stdoutRegex, stdout)) return { matched: false, reason: 'stdoutRegex not matched' };
  if (!testRegex(when.stderrRegex, stderr)) return { matched: false, reason: 'stderrRegex not matched' };

  const evidence = extractEvidence({ toolId, stdout, stderr, target });
  return { matched: true, ruleId: rule.id, name: rule.name, target, evidence, then: rule.then || {} };
}

export function evalAllRules({ toolId, stdout = '', stderr = '', target = null }) {
  const rules = loadRuleSpecs();
  const matches = [];
  for (const r of rules) {
    const out = evalRule(r, { toolId, stdout, stderr, target });
    if (out.matched) matches.push(out);
  }
  return { count: matches.length, matches };
}

export function getRule(ruleId) {
  return getRuleSpec(ruleId);
}
