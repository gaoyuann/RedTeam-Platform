export default function up(db) {
  db.exec(`
    CREATE TABLE task_report_reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id TEXT NOT NULL REFERENCES test_reports(report_id) ON DELETE CASCADE,
      pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id) ON DELETE CASCADE,
      revision INTEGER NOT NULL CHECK (revision > 0),
      source_fingerprint TEXT NOT NULL,
      action TEXT NOT NULL CHECK (action IN ('submit', 'approve', 'reject', 'reopen')),
      from_state TEXT NOT NULL,
      state TEXT NOT NULL CHECK (state IN ('draft', 'submitted', 'reviewed', 'rejected')),
      actor TEXT NOT NULL,
      actor_role TEXT NOT NULL CHECK (actor_role IN ('admin', 'user')),
      note TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE (report_id, revision)
    );
    CREATE INDEX idx_task_report_reviews_task ON task_report_reviews(pipeline_id, report_id, revision);
  `);
}
