export default function up(db) {
  db.exec(`
    CREATE TABLE pipeline_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id) ON DELETE CASCADE,
      level TEXT NOT NULL CHECK (level IN ('info', 'warn', 'error')),
      message TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
    CREATE INDEX idx_pipeline_logs_task ON pipeline_logs(pipeline_id, id);
  `);
}
