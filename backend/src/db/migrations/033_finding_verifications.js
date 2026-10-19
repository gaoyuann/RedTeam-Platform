export default function up(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS finding_verifications (
      id TEXT PRIMARY KEY, pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id),
      finding_id INTEGER NOT NULL REFERENCES scan_results(id), scan_task_id TEXT NOT NULL,
      revision INTEGER NOT NULL DEFAULT 0, state TEXT NOT NULL DEFAULT 'needs_conditions',
      reason TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(pipeline_id,finding_id)
    );
    CREATE TABLE IF NOT EXISTS finding_verification_plans (
      verification_id TEXT NOT NULL REFERENCES finding_verifications(id), revision INTEGER NOT NULL,
      content TEXT NOT NULL, fingerprint TEXT NOT NULL, confirmed_by TEXT, confirmed_at TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')), PRIMARY KEY(verification_id,revision)
    );
    CREATE TABLE IF NOT EXISTS finding_verification_attempts (
      id TEXT PRIMARY KEY, verification_id TEXT NOT NULL REFERENCES finding_verifications(id),
      pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id), revision INTEGER NOT NULL,
      run_id TEXT NOT NULL UNIQUE REFERENCES execution_runs(run_id), request_id TEXT NOT NULL,
      state TEXT NOT NULL, stop_confirmed INTEGER NOT NULL DEFAULT 0,
      reason TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), completed_at TEXT,
      UNIQUE(verification_id,request_id),
      FOREIGN KEY(verification_id,revision) REFERENCES finding_verification_plans(verification_id,revision)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_verification_active_task ON finding_verification_attempts(pipeline_id)
      WHERE state IN ('queued','running','cancelling','unknown');
    CREATE TABLE IF NOT EXISTS finding_verification_reviews (
      id INTEGER PRIMARY KEY, attempt_id TEXT NOT NULL REFERENCES finding_verification_attempts(id),
      conclusion TEXT NOT NULL, evidence_ids TEXT NOT NULL, note TEXT NOT NULL, reviewed_by TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
}
