export default function up(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS task_deletions (
    pipeline_id TEXT PRIMARY KEY REFERENCES pipelines(pipeline_id) ON DELETE CASCADE,
    deleted_by TEXT NOT NULL,
    deleted_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`);
}
