/**
 * InterventionGuards - Blue Team defense system
 * Ported from RedTeam-Edu: backend/src/defense/interventionGuards.js
 * Adapted: reads interventions from SQLite blue_team_interventions table instead of JSON runStore
 *
 * MVP philosophy: deterministic, explainable, and safe for teaching.
 */

import { getDb } from '../db/connection.js';

function normalizeTarget(t) {
  return String(t || '').trim();
}

/**
 * Get interventions for a run from DB
 * @param {string} runId
 * @returns {Array<object>}
 */
function getInterventions(runId) {
  if (!runId) return [];
  const db = getDb();
  try {
    return db.prepare(
      'SELECT * FROM blue_team_interventions WHERE run_id = ? ORDER BY id'
    ).all(runId);
  } catch {
    // Table may not exist yet
    return [];
  }
}

/**
 * List blocked ports from interventions
 * @param {Array} interventions
 * @returns {Array<{port: number, proto: string}>}
 */
function listBlockedPorts(interventions = []) {
  return interventions
    .filter(iv => iv?.type === 'block_port')
    .map(iv => ({ port: Number(iv.port), proto: String(iv.proto || 'tcp') }))
    .filter(x => Number.isFinite(x.port) && x.port > 0);
}

/**
 * List blocked paths from interventions
 * @param {Array} interventions
 * @returns {string[]}
 */
function listBlockedPaths(interventions = []) {
  return interventions
    .filter(iv => iv?.type === 'block_path')
    .map(iv => String(iv.path || '').trim())
    .filter(Boolean);
}

/**
 * Check if target is isolated
 * @param {Array} interventions
 * @param {string} target
 * @returns {boolean}
 */
function hasIsolation(interventions = [], target) {
  const t = normalizeTarget(target);
  return interventions.some(
    iv => iv?.type === 'isolate_host' && normalizeTarget(iv?.target) === t
  );
}

/**
 * Ensure nmap --exclude-ports is added
 * @param {string[]} args
 * @param {Array<{port: number}>} blockedPorts
 * @returns {{args: string[], applied: boolean}}
 */
function ensureNmapExcludePorts(args = [], blockedPorts = []) {
  const ports = blockedPorts.map(p => p.port).filter(Boolean);
  if (ports.length === 0) return { args, applied: false };

  // If already contains --exclude-ports, don't duplicate
  const joined = args.join(' ');
  if (joined.includes('--exclude-ports')) return { args, applied: false };

  return { args: [...args, '--exclude-ports', ports.join(',')], applied: true };
}

/**
 * Apply pre-execution blue-team guards.
 * Returns { allowed, deniedReason?, adjustedArgs?, notes? }
 *
 * @param {{ runId: string, toolId: string, args: string[], target: string }} params
 * @returns {{ allowed: boolean, deniedReason?: string, adjustedArgs?: string[], notes?: string[] }}
 */
export function applyBlueTeamPreExec({ runId, toolId, args = [], target }) {
  const interventions = getInterventions(runId);
  const notes = [];

  // Isolation: hard stop
  if (hasIsolation(interventions, target)) {
    return {
      allowed: false,
      deniedReason: `目标 ${target} 已被蓝队隔离（isolate_host），禁止继续执行红队工具`,
      notes: [`isolate_host:${target}`],
    };
  }

  // Block ports: for nmap we can enforce "exclude" so results change deterministically
  const blockedPorts = listBlockedPorts(interventions);
  let adjustedArgs = Array.isArray(args) ? [...args] : [];
  if (toolId === 'nmap') {
    const out = ensureNmapExcludePorts(adjustedArgs, blockedPorts);
    adjustedArgs = out.args;
    if (out.applied) {
      notes.push(
        `applied:nmap_exclude_ports(${blockedPorts.map(p => p.port).join(',')})`
      );
    }
  }

  return { allowed: true, adjustedArgs, notes };
}

/**
 * Apply post-execution filtering so blue-team blocks have visible impact.
 * Filters web_path findings if block_path exists.
 *
 * @param {{ runId: string, findings: Array, evidence: object|null }} params
 * @returns {{ findings: Array, evidence: object|null, notes: string[] }}
 */
export function applyBlueTeamPostProcess({ runId, findings = [], evidence = null }) {
  const interventions = getInterventions(runId);
  const blockedPaths = listBlockedPaths(interventions);
  if (blockedPaths.length === 0) return { findings, evidence, notes: [] };

  const notes = [];
  const filtered = [];
  let removed = 0;

  for (const f of findings) {
    if (f?.type === 'web_path' && typeof f.path === 'string') {
      const hit = blockedPaths.find(
        p => p === f.path || (p.endsWith('/') ? f.path.startsWith(p) : false)
      );
      if (hit) {
        removed += 1;
        continue;
      }
    }
    filtered.push(f);
  }

  if (removed > 0) {
    notes.push(`filtered_web_path:${removed}`);
    // annotate evidence (best-effort)
    if (evidence && typeof evidence === 'object') {
      evidence._blueTeam = evidence._blueTeam || {};
      evidence._blueTeam.filteredWebPaths = removed;
      evidence._blueTeam.blockedPaths = blockedPaths.slice(0, 50);
    }
  }

  return { findings: filtered, evidence, notes };
}
