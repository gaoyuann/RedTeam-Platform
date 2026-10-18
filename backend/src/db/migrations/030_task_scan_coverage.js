export default function up(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS task_assets (
      asset_id TEXT PRIMARY KEY, pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id) ON DELETE CASCADE,
      host TEXT NOT NULL, state TEXT NOT NULL, source_record_id INTEGER, UNIQUE(pipeline_id,host)
    );
    CREATE TABLE IF NOT EXISTS task_services (
      service_id TEXT PRIMARY KEY, pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id) ON DELETE CASCADE,
      asset_id TEXT NOT NULL REFERENCES task_assets(asset_id) ON DELETE CASCADE,
      port INTEGER NOT NULL, protocol TEXT NOT NULL, name TEXT NOT NULL, state TEXT NOT NULL,
      source_record_id INTEGER, UNIQUE(pipeline_id,asset_id,port,protocol)
    );
    CREATE TABLE IF NOT EXISTS task_entries (
      entry_id TEXT PRIMARY KEY, pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id) ON DELETE CASCADE,
      service_id TEXT REFERENCES task_services(service_id) ON DELETE CASCADE,
      kind TEXT NOT NULL, value TEXT NOT NULL, state TEXT NOT NULL, source_record_id INTEGER,
      UNIQUE(pipeline_id,kind,value)
    );
    CREATE TABLE IF NOT EXISTS task_checks (
      check_id TEXT PRIMARY KEY, pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id) ON DELETE CASCADE,
      service_id TEXT REFERENCES task_services(service_id) ON DELETE CASCADE,
      entry_id TEXT REFERENCES task_entries(entry_id) ON DELETE CASCADE,
      check_type TEXT NOT NULL, scan_type TEXT, target TEXT, state TEXT NOT NULL,
      reason TEXT, scan_task_id TEXT REFERENCES scan_tasks(scan_task_id), source_record_id INTEGER,
      created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_task_coverage_assets ON task_assets(pipeline_id);
    CREATE INDEX IF NOT EXISTS idx_task_coverage_services ON task_services(pipeline_id);
    CREATE INDEX IF NOT EXISTS idx_task_coverage_entries ON task_entries(pipeline_id);
    CREATE INDEX IF NOT EXISTS idx_task_coverage_checks ON task_checks(pipeline_id,state);
  `);
}
