export default function up(db) {
  // SQLite doesn't support ALTER TABLE to modify CHECK constraints.
  // Rebuild the pipelines table with the updated status enum.
  db.pragma('foreign_keys = OFF');

  db.exec(`
    CREATE TABLE pipelines_new (
      id                  INTEGER PRIMARY KEY AUTOINCREMENT,
      pipeline_id         TEXT    NOT NULL UNIQUE,
      target              TEXT    NOT NULL,
      status              TEXT    NOT NULL DEFAULT 'created'
                            CHECK (status IN (
                              'created','running','paused','awaiting_approval',
                              'completed','failed','cancelled'
                            )),
      scan_task_id        TEXT,
      analysis_result     TEXT,
      generated_playbook_id TEXT,
      run_id              TEXT,
      config              TEXT    DEFAULT '{}',
      result              TEXT,
      error_message       TEXT,
      created_by          TEXT    REFERENCES users(username),
      created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
      updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
    );

    INSERT INTO pipelines_new
      SELECT * FROM pipelines;

    DROP TABLE pipelines;

    ALTER TABLE pipelines_new RENAME TO pipelines;

    CREATE INDEX IF NOT EXISTS idx_pipelines_status      ON pipelines(status);
    CREATE INDEX IF NOT EXISTS idx_pipelines_created_by  ON pipelines(created_by);
    CREATE INDEX IF NOT EXISTS idx_pipelines_target      ON pipelines(target);
  `);

  db.pragma('foreign_keys = ON');
  console.log('[Migration 015] Added awaiting_approval status to pipelines');
}
