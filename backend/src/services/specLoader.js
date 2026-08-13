/**
 * Spec Loader
 *
 * Loads rulespec JSON files from data/rulespecs/ directory.
 * Simplified port from RedTeam-Edu: backend/src/hexstrike/specLoader.js
 */

import { readdirSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = dirname(__filename);
const PROJECT_ROOT = join(__dirname, '..', '..', '..');

const DEFAULT_RULESPECS_DIR = join(PROJECT_ROOT, 'data', 'rulespecs');

let _rulespecs = null;
let _loadTime = 0;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

/**
 * Load all rulespec JSON files from directory.
 * Results are cached for 5 minutes.
 *
 * @param {string} [dir] - override directory path
 * @returns {Array<object>} array of rulespec objects
 */
export function loadRuleSpecs(dir) {
  const now = Date.now();
  if (_rulespecs && (now - _loadTime) < CACHE_TTL) {
    return _rulespecs;
  }

  const rulespecsDir = dir || DEFAULT_RULESPECS_DIR;
  const specs = [];

  try {
    const files = readdirSync(rulespecsDir)
      .filter(f => f.endsWith('.json'))
      .sort();

    for (const file of files) {
      try {
        const content = readFileSync(join(rulespecsDir, file), 'utf8');
        const spec = JSON.parse(content);
        specs.push(spec);
      } catch (e) {
        console.warn(`[specLoader] Failed to load ${file}: ${e.message}`);
      }
    }
  } catch (e) {
    console.warn(`[specLoader] Failed to read rulespecs directory: ${e.message}`);
  }

  _rulespecs = specs;
  _loadTime = now;
  console.log(`[specLoader] Loaded ${specs.length} rulespecs from ${rulespecsDir}`);
  return specs;
}

/**
 * Get a single rulespec by ID.
 *
 * @param {string} id - rulespec ID
 * @param {string} [dir] - override directory path
 * @returns {object|null}
 */
export function getRuleSpec(id, dir) {
  const specs = loadRuleSpecs(dir);
  return specs.find(s => s.id === id) || null;
}

/**
 * Clear the cached rulespecs (for testing or hot-reload).
 */
export function clearCache() {
  _rulespecs = null;
  _loadTime = 0;
}
