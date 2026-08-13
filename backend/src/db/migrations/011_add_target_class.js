/**
 * Migration 011: Add target_class and target_profile columns
 * to execution_runs and scan_tasks tables for multi-target support.
 */
export default function up(db) {
  // Add target_class column to execution_runs
  try {
    db.exec(`ALTER TABLE execution_runs ADD COLUMN target_class TEXT`);
  } catch (e) {
    if (!e.message.includes('duplicate column')) throw e;
  }

  // Add target_profile column to execution_runs (stores full profile JSON)
  try {
    db.exec(`ALTER TABLE execution_runs ADD COLUMN target_profile TEXT`);
  } catch (e) {
    if (!e.message.includes('duplicate column')) throw e;
  }

  // Add target_class column to scan_tasks
  try {
    db.exec(`ALTER TABLE scan_tasks ADD COLUMN target_class TEXT`);
  } catch (e) {
    if (!e.message.includes('duplicate column')) throw e;
  }

  // Add indexes
  db.exec(`CREATE INDEX IF NOT EXISTS idx_runs_target_class ON execution_runs(target_class)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_scan_tasks_target_class ON scan_tasks(target_class)`);

  console.log('[Migration 011] Added target_class and target_profile columns');
}
