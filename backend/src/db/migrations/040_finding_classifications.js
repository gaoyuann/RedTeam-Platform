export default function up(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS finding_classifications (
    pipeline_id TEXT NOT NULL REFERENCES pipelines(pipeline_id) ON DELETE CASCADE,
    finding_id INTEGER NOT NULL REFERENCES scan_results(id) ON DELETE CASCADE,
    input_hash TEXT NOT NULL,
    input_data TEXT NOT NULL,
    result TEXT NOT NULL,
    created_by TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (pipeline_id, finding_id)
  )`);
}
