export default function up(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS finding_payload_links (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_result_id INTEGER NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
      payload_id TEXT NOT NULL,
      payload_version TEXT NOT NULL,
      match_basis TEXT NOT NULL,
      consumption TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
      created_by TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(scan_result_id, payload_id, payload_version)
    );
    CREATE INDEX IF NOT EXISTS idx_finding_payload_links_result
      ON finding_payload_links(scan_result_id, active);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_finding_payload_links_current
      ON finding_payload_links(scan_result_id, payload_id) WHERE active = 1;
  `);
}
