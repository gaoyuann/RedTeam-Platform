/**
 * ReactRuntimeGuard.js
 *
 * Runtime Guard for the ReAct execution loop.
 * Prevents LLM from infinite insertion loops by enforcing category and global limits.
 * All numeric limits live in config/state_machine_rules.json.
 *
 * Ported from RedTeam-Edu: backend/src/hexstrike/ReactRuntimeGuard.js
 * Adapted: state.steps → mutableSteps array, state.status → from DB
 *
 * Public API
 * ----------
 *   validateNextAction(state, action)             → { allowed, reason }
 *   validateInsertion(state, actionType, toolId)   → { allowed, reason, category, used, limit }
 *   validatePlaybookContinue(pbState)              → { allowed, reason }
 *   recordBlock(state, category, toolId)           → void   (telemetry)
 *   getTelemetry(state)                            → { blocked_total, by_category }
 *   getToolCategory(toolId)                        → string
 *   buildInsertionWarning(state)                   → string
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// ── Load rules JSON ──────────────────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);

let _rules = null;
function loadRules() {
  if (_rules) return _rules;
  const rulesPath = join(__dirname, '..', 'config', 'state_machine_rules.json');
  try {
    _rules = JSON.parse(readFileSync(rulesPath, 'utf8'));
  } catch (e) {
    console.error('[ReactRuntimeGuard] Failed to load state_machine_rules.json:', e.message);
    // Fallback to safe defaults so the system never crashes
    _rules = {
      version: 'fallback',
      global: { max_total_react_inserts: 15 },
      actions: {
        stop:     { required_status: ['RUNNING', 'PENDING'], forbidden_if_status: ['COMPLETED', 'ABORTED', 'FAILED'], state_transitions: { to: 'COMPLETED', block_all_subsequent: true } },
        parallel: { global_max_parallel_groups: 10, per_category_limit: { dir_enum: 2, subdomain_enum: 1, vuln_scan: 2, brute_force: 3, cloud_scan: 1, port_scan: 3, default: 2 }, tool_categories: { gobuster: 'dir_enum', dirb: 'dir_enum', ffuf: 'dir_enum', subfinder: 'subdomain_enum', amass: 'subdomain_enum', nuclei: 'vuln_scan', sqlmap: 'vuln_scan', hydra: 'brute_force', john: 'brute_force', nmap: 'port_scan', masscan: 'port_scan' } },
        insert:   { per_category_limit: { dir_enum: 2, subdomain_enum: 1, vuln_scan: 2, brute_force: 3, cloud_scan: 1, port_scan: 3, default: 2 } }
      }
    };
  }
  return _rules;
}

// ── Telemetry key stored inside state ────────────────────────────────────────
const TELEMETRY_KEY = '_guardTelemetry';

function ensureTelemetry(state) {
  if (!state[TELEMETRY_KEY]) {
    state[TELEMETRY_KEY] = { blocked_total: 0, by_category: {} };
  }
  return state[TELEMETRY_KEY];
}

// ── Helper: resolve tool → category ─────────────────────────────────────────
export function getToolCategory(toolId) {
  const rules = loadRules();
  const cats  = rules.actions?.parallel?.tool_categories || {};
  return cats[toolId] || 'default';
}

// ── Count how many times a category has been inserted by ReAct ──────────────
function countCategoryInserts(state, category, actionTypes = ['insert', 'parallel']) {
  const steps = state.steps || [];
  let count = 0;
  for (const s of steps) {
    if (!s.step_id && !s.id) continue;
    const sid = s.step_id || s.id || '';
    const isReactInsert   = sid.startsWith('react_insert_');
    const isReactParallel = sid.startsWith('react_parallel_');
    if (!isReactInsert && !isReactParallel) continue;
    if (isReactInsert   && !actionTypes.includes('insert'))   continue;
    if (isReactParallel && !actionTypes.includes('parallel'))  continue;
    if (getToolCategory(s.tool_id || s.toolId) === category) count++;
  }
  return count;
}

// ── Count total ReAct-inserted steps ────────────────────────────────────────
function countTotalInserts(state) {
  return (state.steps || []).filter(s => {
    const sid = s.step_id || s.id || '';
    return sid.startsWith('react_insert_') || sid.startsWith('react_parallel_');
  }).length;
}

// ── Core: validate whether the next outer action is allowed ─────────────────
/**
 * Called BEFORE executing the next step in the run.
 *
 * @param {object} state   - { steps: mutableSteps, status: runStatus, stopReason }
 * @param {string} action  - e.g. 'runNextStep'
 * @returns {{ allowed: boolean, reason: string }}
 */
export function validateNextAction(state, action = 'runNextStep') {
  const rules = loadRules();
  const stopRule = rules.actions?.stop || {};

  // 1. If run is already in a terminal state → block
  const terminalStatuses = stopRule.forbidden_if_status || ['COMPLETED', 'ABORTED', 'FAILED'];
  if (terminalStatuses.includes(state.status)) {
    return {
      allowed: false,
      reason: `[Guard] Run is already ${state.status}. Action '${action}' blocked.`
    };
  }

  // 2. If stopReason is set (LLM stopped the run) → block
  if (state.stopReason) {
    return {
      allowed: false,
      reason: `[Guard] Run was stopped by ReAct AI. Action '${action}' blocked.`
    };
  }

  return { allowed: true, reason: 'ok' };
}

/**
 * Validate whether the playbook runtime's current state allows continuing.
 *
 * @param {object} pbState  - { status, steps, currentStepIndex }
 * @returns {{ allowed: boolean, reason: string }}
 */
export function validatePlaybookContinue(pbState) {
  if (!pbState) return { allowed: true, reason: 'no pbState' };

  const rules    = loadRules();
  const stopRule = rules.actions?.stop || {};
  const terminalStatuses = stopRule.forbidden_if_status || ['COMPLETED', 'ABORTED', 'FAILED'];

  if (terminalStatuses.includes(pbState.status)) {
    return {
      allowed: false,
      reason: `[Guard] Run status is ${pbState.status}. Blocking further execution.`
    };
  }
  if (pbState.stopReason) {
    return {
      allowed: false,
      reason: `[Guard] Run stopped by ReAct AI. Blocking further execution.`
    };
  }

  return { allowed: true, reason: 'ok' };
}

// ── Core: validate a ReAct insert / parallel insertion ──────────────────────
/**
 * Called BEFORE splicing a new step into the steps array.
 *
 * @param {object} state      - { steps: mutableSteps, status, stopReason }
 * @param {string} actionType - 'insert' | 'parallel'
 * @param {string} toolId     - the tool being inserted
 * @param {boolean} [disableAutoInsert] - if true, block all insertions
 * @returns {{ allowed: boolean, reason: string, category: string, used: number, limit: number }}
 */
export function validateInsertion(state, actionType, toolId, disableAutoInsert = false) {
  const rules    = loadRules();
  const category = getToolCategory(toolId);

  // 0. Playbook disableAutoInsert check
  if (disableAutoInsert) {
    return {
      allowed:  false,
      reason:   `[Guard] Blocked ${actionType} for tool '${toolId}': disableAutoInsert=true.`,
      category, used: 0, limit: 0
    };
  }

  // 1. Global total insert limit
  const globalMax   = rules.global?.max_total_react_inserts ?? 15;
  const totalUsed   = countTotalInserts(state);
  if (totalUsed >= globalMax) {
    return {
      allowed:  false,
      reason:   `[Guard] Blocked ${actionType} for tool '${toolId}' (category: ${category}): global total insert limit reached (${totalUsed}/${globalMax}).`,
      category, used: totalUsed, limit: globalMax
    };
  }

  // 2. Per-category limit (applies to both insert and parallel)
  const actionRule   = rules.actions?.[actionType] || {};
  const catLimits    = actionRule.per_category_limit || {};
  const catLimit     = catLimits[category] ?? catLimits['default'] ?? 2;
  const catUsed      = countCategoryInserts(state, category);

  if (catUsed >= catLimit) {
    return {
      allowed:  false,
      reason:   `[Guard] Blocked ${actionType} for tool '${toolId}' (category: ${category}): per-category limit reached (${catUsed}/${catLimit}).`,
      category, used: catUsed, limit: catLimit
    };
  }

  // 3. For parallel: global parallel group limit
  if (actionType === 'parallel') {
    const parallelRule = rules.actions?.parallel || {};
    const maxGroups    = parallelRule.global_max_parallel_groups ?? 10;
    const groupsUsed   = (state.steps || []).filter(s => {
      const sid = s.step_id || s.id || '';
      return sid.startsWith('react_parallel_');
    }).length;
    if (groupsUsed >= maxGroups) {
      return {
        allowed:  false,
        reason:   `[Guard] Blocked parallel for tool '${toolId}': global parallel group limit reached (${groupsUsed}/${maxGroups}).`,
        category, used: groupsUsed, limit: maxGroups
      };
    }
  }

  return { allowed: true, reason: 'ok', category, used: catUsed, limit: catLimit };
}

// ── Telemetry ────────────────────────────────────────────────────────────────
/**
 * Record a blocked insertion event into state telemetry.
 */
export function recordBlock(state, category, toolId) {
  const t = ensureTelemetry(state);
  t.blocked_total++;
  if (!t.by_category[category]) t.by_category[category] = { count: 0, tools: [] };
  t.by_category[category].count++;
  if (!t.by_category[category].tools.includes(toolId)) {
    t.by_category[category].tools.push(toolId);
  }
  console.warn(`[Guard] Telemetry: blocked_total=${t.blocked_total}, category=${category}, tool=${toolId}`);
}

/**
 * Get current telemetry snapshot from state.
 */
export function getTelemetry(state) {
  return state[TELEMETRY_KEY] || { blocked_total: 0, by_category: {} };
}

// ── Convenience: build a human-readable prompt warning for the LLM ──────────
/**
 * Returns a warning string to inject into the ReAct prompt when a category
 * is at or near its limit, so the LLM is informed before it tries to insert.
 */
export function buildInsertionWarning(state) {
  const rules    = loadRules();
  const warnings = [];
  const categories = new Set(Object.values(rules.actions?.parallel?.tool_categories || {}));

  for (const cat of categories) {
    const used     = countCategoryInserts(state, cat);
    const catLimit = rules.actions?.parallel?.per_category_limit?.[cat]
                  ?? rules.actions?.insert?.per_category_limit?.[cat]
                  ?? rules.actions?.parallel?.per_category_limit?.default
                  ?? 2;
    if (used >= catLimit) {
      warnings.push(`  • 类别 [${cat}]：已插入 ${used}/${catLimit} 次，已达上限，禁止再次插入。`);
    }
  }

  const globalMax  = rules.global?.max_total_react_inserts ?? 15;
  const totalUsed  = countTotalInserts(state);
  if (totalUsed >= globalMax) {
    warnings.push(`  • 全局插入总数：${totalUsed}/${globalMax}，已达上限，禁止任何插入。`);
  }

  if (warnings.length === 0) return '';
  return `\n\n🚫 【Runtime Guard 强制限制 - 绝对遵守】以下工具类别已达到插入上限，你绝对不允许再次使用 insert 或 parallel 插入这些类别的工具：\n${warnings.join('\n')}\n如果计划中仍有这些工具，必须使用 continue 跳过或 stop 终止。`;
}
