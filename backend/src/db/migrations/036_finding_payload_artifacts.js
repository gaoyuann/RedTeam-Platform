export default function up(db) {
  db.transaction(()=>db.exec(`
    CREATE TABLE IF NOT EXISTS finding_payload_collections (
      id TEXT PRIMARY KEY, verification_id TEXT NOT NULL REFERENCES finding_verifications(id),
      flow_id TEXT NOT NULL, assistant_id TEXT, request_marker TEXT NOT NULL UNIQUE,
      state TEXT NOT NULL, dispatch_started INTEGER NOT NULL DEFAULT 0, request_sent INTEGER NOT NULL DEFAULT 0,
      baseline_logs TEXT NOT NULL DEFAULT '[]', source_fingerprint TEXT NOT NULL,
      summary TEXT NOT NULL DEFAULT '', scripts TEXT NOT NULL DEFAULT '[]', error_message TEXT,
      created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_payload_collection_finding ON finding_payload_collections(verification_id,created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_payload_collection_active ON finding_payload_collections(verification_id) WHERE state='collecting';
    CREATE TABLE IF NOT EXISTS finding_payload_rewrites (
      id TEXT PRIMARY KEY, collection_id TEXT NOT NULL REFERENCES finding_payload_collections(id),
      script_id TEXT NOT NULL, source_hash TEXT NOT NULL, state TEXT NOT NULL,
      python_code TEXT NOT NULL DEFAULT '', explanation TEXT NOT NULL DEFAULT '', usage TEXT NOT NULL DEFAULT '',
      error_message TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
      UNIQUE(collection_id,script_id)
    );
  `))();
}
