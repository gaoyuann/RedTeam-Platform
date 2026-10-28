export default function up(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS source_payload_queue (
    scan_task_id TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT 'pending',
    last_finding_id INTEGER NOT NULL DEFAULT 0, error_count INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`);
}
