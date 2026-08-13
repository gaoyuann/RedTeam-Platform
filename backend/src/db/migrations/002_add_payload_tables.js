export default function up(db) {
  db.exec(`
    -- ── Generated Payloads (AI-generated, require teacher review) ────────
    CREATE TABLE IF NOT EXISTS generated_payloads (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      payload_id      TEXT    NOT NULL UNIQUE,
      name            TEXT    NOT NULL,
      category        TEXT,
      payload_type    TEXT    NOT NULL CHECK(payload_type IN ('web','intranet','tool')),
      payload_data    TEXT    NOT NULL,
      source          TEXT    DEFAULT 'ai_generated',
      mitre_technique TEXT,
      import_status   TEXT    DEFAULT 'candidate' CHECK(import_status IN ('candidate','accepted','rejected')),
      reviewed_by     TEXT,
      reviewed_at     TEXT,
      created_by      TEXT,
      created_at      TEXT    DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_gen_payloads_status ON generated_payloads(import_status);
    CREATE INDEX IF NOT EXISTS idx_gen_payloads_type   ON generated_payloads(payload_type);
  `);
  console.log('[Migration 002] Created generated_payloads table');
}
