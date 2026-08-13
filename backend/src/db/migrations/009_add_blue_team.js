/**
 * Migration 009: Add Blue Team interventions table
 *
 * Creates the blue_team_interventions table for storing blue-team
 * defense measures that affect red-team tool execution.
 */
export default function up(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS blue_team_interventions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      type TEXT NOT NULL,
      target TEXT,
      port INTEGER,
      proto TEXT DEFAULT 'tcp',
      path TEXT,
      created_by TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (run_id) REFERENCES execution_runs(run_id)
    )
  `);
  console.log('[Migration 009] Created blue_team_interventions table');
}
