/**
 * Migration 010: Add candidate_mappings table for runtime mapping detection
 *
 * Stores auto-detected tool-to-technique mappings from successful tool execution.
 * These candidates can be reviewed/approved/rejected via the knowledge API.
 */
export default function up(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS candidate_mappings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT,
      tool_id TEXT NOT NULL,
      technique_id TEXT NOT NULL,
      confidence REAL DEFAULT 0.5,
      signal TEXT,
      snippet TEXT,
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_candidate_mappings_status ON candidate_mappings(status)
  `);
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_candidate_mappings_run_id ON candidate_mappings(run_id)
  `);
  console.log('[Migration 010] Created candidate_mappings table');
}
