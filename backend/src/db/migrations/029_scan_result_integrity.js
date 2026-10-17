export default function up(db) {
  db.transaction(() => {
    const add = (table, name, definition) => {
      if (!db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === name))
        db.exec(`ALTER TABLE ${table} ADD COLUMN ${name} ${definition}`);
    };
    add('scan_tasks', 'pipeline_id', 'TEXT REFERENCES pipelines(pipeline_id)');
    add('scan_tasks', 'retry_of_scan_task_id', 'TEXT REFERENCES scan_tasks(scan_task_id)');
    add('scan_tasks', 'retry_request_id', 'TEXT');
    db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_retry_request ON scan_tasks(retry_of_scan_task_id,retry_request_id) WHERE retry_request_id IS NOT NULL;
    CREATE TABLE IF NOT EXISTS scan_tool_runs (
      tool_run_id TEXT PRIMARY KEY,
      scan_task_id TEXT NOT NULL REFERENCES scan_tasks(scan_task_id) ON DELETE CASCADE,
      tool_id TEXT NOT NULL, scan_type TEXT, state TEXT NOT NULL,
      started_at TEXT NOT NULL, completed_at TEXT,
      outcome TEXT, diagnostics TEXT, evidence TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_scan_tool_runs_task ON scan_tool_runs(scan_task_id);
    CREATE INDEX IF NOT EXISTS idx_scan_pipeline ON scan_tasks(pipeline_id);
    CREATE INDEX IF NOT EXISTS idx_scan_retry ON scan_tasks(retry_of_scan_task_id);`);
    add('scan_results', 'tool_run_id', 'TEXT REFERENCES scan_tool_runs(tool_run_id)');
    add('scan_results', 'record_index', 'INTEGER');
    db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_result_call_record
      ON scan_results(tool_run_id, record_index) WHERE tool_run_id IS NOT NULL;`);
  })();
}
