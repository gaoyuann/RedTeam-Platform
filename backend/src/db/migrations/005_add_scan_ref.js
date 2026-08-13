export const id = '005_add_scan_ref';
export const description = 'Add scan_task_id to execution_runs for scan-driven workflow';

export function up(db) {
  db.exec(`ALTER TABLE execution_runs ADD COLUMN scan_task_id TEXT REFERENCES scan_tasks(scan_task_id)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_runs_scan ON execution_runs(scan_task_id)`);
}
