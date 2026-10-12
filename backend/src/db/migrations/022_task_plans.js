export default function up(db) {
  db.exec(`
    CREATE TABLE task_plans (
      pipeline_id TEXT PRIMARY KEY REFERENCES pipelines(pipeline_id) ON DELETE CASCADE,
      state TEXT NOT NULL CHECK (state IN ('draft', 'submitted', 'rejected', 'approved')),
      revision INTEGER NOT NULL DEFAULT 1,
      content TEXT NOT NULL,
      approved_playbook_id TEXT,
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE task_plan_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      pipeline_id TEXT NOT NULL REFERENCES task_plans(pipeline_id) ON DELETE CASCADE,
      revision INTEGER NOT NULL,
      action TEXT NOT NULL,
      actor TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      note TEXT NOT NULL DEFAULT '',
      snapshot TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX idx_task_plan_history ON task_plan_history(pipeline_id, id);
  `);
}
