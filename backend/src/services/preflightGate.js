/**
 * PreflightGate - Pre-execution validation checks
 * Ported from RedTeam-Edu: backend/src/runtime/preflightGate.js
 * Adapted: uses SQLite DB + containerEngine + toolRunner IMAGE_MAP
 */

import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getEngine } from '../tools/containerEngine.js';
import { IMAGE_MAP } from '../tools/toolRunner.js';
import { resolveTargetProfile, derivePreferredClass, checkTargetTypeCompatibility } from './targetProfileResolver.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const PROJECT_ROOT = join(__dirname, '..', '..', '..');

// ── Target pattern validation ─────────────────────────────────────────
const IP_PATTERN     = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d{1,5})?$/;
const HOSTNAME_REGEX = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
const URL_PATTERN    = /^https?:\/\/[^\s/$.?#].[^\s]*$/i;
const CIDR_PATTERN   = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/;

function isValidTarget(target) {
  if (!target || typeof target !== 'string') return false;
  return IP_PATTERN.test(target) ||
         CIDR_PATTERN.test(target) ||
         URL_PATTERN.test(target) ||
         HOSTNAME_REGEX.test(target);
}

// ── Template variable pattern ─────────────────────────────────────────
// Detect any {{...}} that is NOT exactly <target>
const TEMPLATE_VAR_PATTERN = /\{\{([^}]+)\}\}/g;

/**
 * Run all preflight checks for a playbook execution.
 * @param {object} params
 * @param {string} params.playbookId
 * @param {string} params.target
 * @param {object} params.db - better-sqlite3 Database
 * @returns {{ passed: boolean, checks: Array<{name, passed, message}> }}
 */
export async function runPreflightChecks({ playbookId, target, db }) {
  const checks = [];

  // ── Check 1: target_fit ────────────────────────────────────────────
  {
    const valid = isValidTarget(target);
    checks.push({
      name: 'target_fit',
      passed: valid,
      message: valid
        ? `Target format valid: ${target}`
        : `Invalid target format: "${target}". Expected IP, hostname, or URL.`,
    });
  }

  // ── Check 1.5: target_class_compatibility ───────────────────────────
  {
    // Fetch playbook metadata for target type info
    const pb = db.prepare('SELECT target_type, not_suitable_for FROM playbooks WHERE playbook_id = ?').get(playbookId);
    let targetProfile = null;
    let compatOk = true;
    let compatMsg = 'No target type restriction';

    if (pb) {
      const playbookTargetTypes = tryJson(pb.target_type);
      const notSuitableFor = tryJson(pb.not_suitable_for);
      const preferredClass = derivePreferredClass(playbookTargetTypes);
      targetProfile = resolveTargetProfile(target, { preferredTargetClass: preferredClass });

      // Check notSuitableFor (priority exclusion)
      if (notSuitableFor.length > 0 && notSuitableFor.includes(targetProfile.target_class)) {
        compatOk = false;
        compatMsg = `Target class '${targetProfile.target_class}' is in notSuitableFor [${notSuitableFor.join(', ')}]`;
      } else if (playbookTargetTypes.length > 0 && !playbookTargetTypes.includes('any')) {
        // Check targetType compatibility
        const compat = checkTargetTypeCompatibility(playbookTargetTypes, targetProfile.target_class);
        compatOk = compat.ok;
        compatMsg = compat.ok
          ? `target_class=${targetProfile.target_class} compatible with targetType=[${playbookTargetTypes.join(', ')}]`
          : compat.reason;
      } else {
        compatMsg = `target_class=${targetProfile.target_class} (no target_type restriction)`;
      }
    } else {
      // No playbook metadata — just resolve profile for info
      targetProfile = resolveTargetProfile(target);
      compatMsg = `target_class=${targetProfile.target_class} (playbook metadata not found, skipping compat check)`;
    }

    checks.push({
      name: 'target_class_compatibility',
      passed: compatOk,
      message: compatOk ? `Target class compatible: ${compatMsg}` : `Target class incompatible: ${compatMsg}`,
      target_profile: targetProfile,
    });
  }

  // ── Fetch playbook steps from DB ───────────────────────────────────
  const steps = db.prepare(
    `SELECT step_index, tool_id, args_template FROM playbook_steps
     WHERE playbook_id = ? ORDER BY step_index`
  ).all(playbookId);

  // ── Check 2: tool_specs ────────────────────────────────────────────
  {
    const missingTools = [];
    const seenToolIds = new Set();
    for (const step of steps) {
      if (!seenToolIds.has(step.tool_id)) {
        seenToolIds.add(step.tool_id);
        if (!IMAGE_MAP[step.tool_id]) {
          missingTools.push(step.tool_id);
        }
      }
    }
    const ok = missingTools.length === 0;
    checks.push({
      name: 'tool_specs',
      passed: ok,
      message: ok
        ? `All ${seenToolIds.size} tool(s) found in IMAGE_MAP`
        : `Missing tool(s) in IMAGE_MAP: ${missingTools.join(', ')}`,
    });
  }

  // ── Check 2.5: target_tool_compat ──────────────────────────────────
  {
    // Check if each step's tool is appropriate for the resolved target_class
    const TARGET_CLASS_TOOL_COMPAT = {
      dvwa:       new Set(['nmap','gobuster','ffuf','nuclei','nikto','whatweb','hydra','sqlmap','arjun','httpx','curl','python3','system-tools','web-brute']),
      local_ip:   new Set(['nmap','gobuster','ffuf','nuclei','nikto','whatweb','hydra','sqlmap','arjun','httpx','curl','python3','system-tools','web-brute']),
      web_url:    new Set(['nmap','gobuster','ffuf','nuclei','nikto','whatweb','hydra','sqlmap','arjun','httpx','curl','python3','system-tools','web-brute']),
      windows_ad: new Set(['netexec','evil-winrm','rpcclient','responder','mitm6','hashcat','john','nmap','system-tools']),
      cloud:      new Set(['cloudmapper','pacu','nmap','system-tools']),
      local_hash: new Set(['hashcat','john','system-tools']),
      subdomain:  new Set(['amass','gobuster','ffuf','httpx','system-tools']),
    };

    // Get target_class from the previous check
    const targetClassCheck = checks.find(c => c.name === 'target_class_compatibility');
    const resolvedClass = targetClassCheck?.target_profile?.target_class || 'unknown';
    const compatSet = TARGET_CLASS_TOOL_COMPAT[resolvedClass];

    const warnings = [];
    if (compatSet) {
      for (const step of steps) {
        if (!compatSet.has(step.tool_id)) {
          warnings.push(`Tool '${step.tool_id}' (step ${step.step_index}) may not be suitable for target_class '${resolvedClass}'`);
        }
      }
    }
    // This is a warning-level check — doesn't block execution
    checks.push({
      name: 'target_tool_compat',
      passed: true, // always passes (warning only)
      message: warnings.length > 0
        ? `${warnings.length} tool(s) may not suit target_class '${resolvedClass}': ${warnings.slice(0, 3).join('; ')}`
        : `All tools compatible with target_class '${resolvedClass}'`,
    });
  }

  // ── Check 3: tool_binaries (container engine available) ────────────
  {
    let engine;
    try {
      engine = await getEngine();
    } catch (err) {
      engine = null;
    }
    const ok = !!engine;
    checks.push({
      name: 'tool_binaries',
      passed: ok,
      message: ok
        ? `Container engine available: ${engine}`
        : 'No container engine (podman/docker) detected and no fallback available',
    });
  }

  // ── Check 4: template_vars ─────────────────────────────────────────
  {
    // Known context variables provided by targetAdapters at runtime
    const KNOWN_CONTEXT_VARS = new Set([
      'host', 'port', 'scheme', 'base_url', 'target_url', 'target_class',
      'login_url', 'dvwa_login_url', 'sqli_url', 'dvwa_sqli_url', 'dvwa_cookie',
      'security_level', 'domain', 'username', 'password', 'hash',
      'smb_port', 'winrm_port', 'ldap_port', 'rdp_port',
      'aws_region', 'aws_profile', 'aws_account_id', 's3_bucket',
      'wordlist_small', 'wordlist_medium', 'wordlist_small_users', 'wordlist_small_passwords',
      'nuclei_template_dir', 'evidence_dir',
    ]);

    const issues = [];
    for (const step of steps) {
      if (!step.args_template) continue;
      let args;
      try {
        args = JSON.parse(step.args_template);
      } catch {
        continue;
      }
      for (const arg of args) {
        if (typeof arg !== 'string') continue;
        let match;
        while ((match = TEMPLATE_VAR_PATTERN.exec(arg)) !== null) {
          const inner = match[1].trim();
          // Allow <target> and known context variables
          if (inner !== 'target' && inner !== '<target>' && !KNOWN_CONTEXT_VARS.has(inner)) {
            issues.push({
              step_index: step.step_index,
              tool_id: step.tool_id,
              unresolved: match[0],
            });
          }
        }
      }
    }
    const ok = issues.length === 0;
    checks.push({
      name: 'template_vars',
      passed: ok,
      message: ok
        ? 'All template variables are properly resolvable'
        : `Unresolved template variables found: ${issues.map(i => `${i.unresolved} (step ${i.step_index})`).join(', ')}`,
    });
  }

  // ── Check 5: wordlists ─────────────────────────────────────────────
  {
    const wordlistsDir = join(PROJECT_ROOT, 'data', 'wordlists');
    const ok = existsSync(wordlistsDir);
    checks.push({
      name: 'wordlists',
      passed: ok,
      message: ok
        ? `Wordlists directory exists: ${wordlistsDir}`
        : `Wordlists directory not found: ${wordlistsDir}`,
    });
  }

  // ── Check 6: nuclei_templates ──────────────────────────────────────
  {
    const templatesDir = join(PROJECT_ROOT, 'data', 'nuclei-templates');
    const ok = existsSync(templatesDir);
    checks.push({
      name: 'nuclei_templates',
      passed: ok,
      message: ok
        ? `Nuclei templates directory exists: ${templatesDir}`
        : `Nuclei templates directory not found: ${templatesDir}`,
    });
  }

  // ── Check 7: kg_data ───────────────────────────────────────────────
  {
    const kgPath = join(PROJECT_ROOT, 'data', 'knowledge', 'kg_full.json');
    const ok = existsSync(kgPath);
    checks.push({
      name: 'kg_data',
      passed: ok,
      message: ok
        ? `Knowledge graph file exists: ${kgPath}`
        : `Knowledge graph file not found: ${kgPath}`,
    });
  }

  // ── Check 8: llm_available ────────────────────────────────────────
  {
    // Check system_config table first, then env vars
    let apiKey = '';
    try {
      const row = db.prepare(
        "SELECT config_value FROM system_config WHERE category = 'llm' AND config_key = 'default'"
      ).get();
      if (row) {
        try {
          const parsed = JSON.parse(row.config_value);
          apiKey = parsed.key || '';
        } catch {
          apiKey = row.config_value;
        }
      }
    } catch {
      // Table may not exist yet
    }

    if (!apiKey) {
      apiKey = process.env.LLM_API_KEY ||
               process.env.OPENAI_API_KEY ||
               process.env.DEEPSEEK_API_KEY ||
               '';
    }

    const ok = !!apiKey;
    checks.push({
      name: 'llm_available',
      passed: ok,
      message: ok
        ? 'LLM API key is configured (system_config or environment variable)'
        : 'No LLM API key found. Set in system_config (category=llm) or via LLM_API_KEY/OPENAI_API_KEY/DEEPSEEK_API_KEY env var',
    });
  }

  // ── Check 9: db_writable ──────────────────────────────────────────
  {
    let ok = false;
    let msg = '';
    try {
      // Use a test write within an explicit transaction that we roll back
      const testKey = `_preflight_test_${Date.now()}`;
      const testValue = 'ok';

      db.exec('BEGIN');
      db.prepare(
        "INSERT INTO system_config (config_key, config_value, category, description, updated_at) VALUES (?, ?, '_preflight', 'PreflightGate write test', datetime('now'))"
      ).run(testKey, testValue);
      const readBack = db.prepare(
        'SELECT config_value FROM system_config WHERE config_key = ?'
      ).get(testKey);
      db.prepare('DELETE FROM system_config WHERE config_key = ?').run(testKey);
      db.exec('COMMIT');

      if (readBack && readBack.config_value === testValue) {
        ok = true;
        msg = 'SQLite database is writable and readable';
      } else {
        msg = 'Database write/read verification failed';
      }
    } catch (err) {
      try { db.exec('ROLLBACK'); } catch {}
      msg = `Database write test failed: ${err.message}`;
    }

    checks.push({
      name: 'db_writable',
      passed: ok,
      message: msg,
    });
  }

  // ── Aggregate result ───────────────────────────────────────────────
  const passed = checks.every(c => c.passed);
  return { passed, checks };
}

export default { runPreflightChecks };

function tryJson(str) {
  try { return JSON.parse(str || '[]'); } catch { return []; }
}
