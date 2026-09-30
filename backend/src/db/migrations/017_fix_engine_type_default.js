/**
 * Migration 017: Fix engine_type legacy values
 *
 * Migration 001 created execution_runs.engine_type with DEFAULT 'playbook'.
 * Migration 006 introduced 'mechanical' as the proper name for non-AI mode,
 * but couldn't change the column default (SQLite ALTER TABLE limitation).
 *
 * This migration converts existing 'playbook' values to 'mechanical' so the
 * DB reflects the correct naming. The column default remains 'playbook'
 * (changing it requires table recreation, which is too risky). New runs
 * with engine_type='playbook' are handled by executionEngine.js's compat
 * check (treating 'playbook' as a legacy alias for 'mechanical').
 */
export default function up(db) {
  const tx = db.transaction(() => {
    const result = db.prepare(
      "UPDATE execution_runs SET engine_type = 'mechanical' WHERE engine_type = 'playbook'"
    ).run();
    console.log(`[Migration 017] Converted ${result.changes} runs from 'playbook' to 'mechanical'`);
  });
  tx();
}
