export default function up(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS finding_verification_code (
    id TEXT PRIMARY KEY, verification_id TEXT NOT NULL REFERENCES finding_verifications(id),
    request_id TEXT NOT NULL, input_hash TEXT NOT NULL, input_data TEXT NOT NULL,
    state TEXT NOT NULL, result TEXT, error_message TEXT, created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(verification_id,request_id)
  )`);
}
