export default function up(db) {
  db.transaction(()=>{
  db.exec(`
    CREATE TABLE IF NOT EXISTS finding_instances (
      instance_id TEXT PRIMARY KEY, pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id),
      identity TEXT NOT NULL, rule_version INTEGER NOT NULL, created_at TEXT NOT NULL,
      UNIQUE(pipeline_id,identity,rule_version)
    );
    CREATE TABLE IF NOT EXISTS finding_instance_records (
      pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id),
      finding_id INTEGER NOT NULL REFERENCES scan_results(id),
      instance_id TEXT NOT NULL REFERENCES finding_instances(instance_id),
      basis TEXT NOT NULL, PRIMARY KEY(pipeline_id,finding_id)
    );
    CREATE INDEX IF NOT EXISTS idx_instance_records_instance ON finding_instance_records(instance_id);
    CREATE TABLE IF NOT EXISTS task_baselines (
      id INTEGER PRIMARY KEY, pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id),
      content TEXT NOT NULL, content_hash TEXT NOT NULL, imported_by TEXT NOT NULL,
      created_at TEXT NOT NULL, UNIQUE(pipeline_id,content_hash)
    );
    CREATE TABLE IF NOT EXISTS task_baseline_selection (
      pipeline_id TEXT PRIMARY KEY REFERENCES pipelines(pipeline_id),
      baseline_id INTEGER NOT NULL REFERENCES task_baselines(id)
    );
  `);
  if (!db.prepare('PRAGMA table_info(test_reports)').all().some(c=>c.name==='pipeline_id'))
    db.exec('ALTER TABLE test_reports ADD COLUMN pipeline_id TEXT REFERENCES pipelines(pipeline_id)');
  db.exec('CREATE INDEX IF NOT EXISTS idx_report_pipeline ON test_reports(pipeline_id)');
  })();
}
