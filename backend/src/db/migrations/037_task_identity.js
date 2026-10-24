import { allocateTaskNumber, taskNumberDay } from '../../services/taskIdentity.js';

export default function up(db) {
  db.transaction(() => {
    if (!db.prepare('PRAGMA table_info(pipelines)').all().some(column => column.name === 'task_no'))
      db.exec('ALTER TABLE pipelines ADD COLUMN task_no TEXT COLLATE NOCASE');
    db.exec(`CREATE TABLE IF NOT EXISTS task_number_counters (
      day TEXT PRIMARY KEY, last_value INTEGER NOT NULL CHECK(last_value>=0)
    );
    CREATE TABLE IF NOT EXISTS task_creation_requests (
      owner TEXT NOT NULL, request_id TEXT NOT NULL, request_hash TEXT NOT NULL,
      pipeline_id TEXT NOT NULL, task_no TEXT NOT NULL,
      PRIMARY KEY(owner,request_id)
    );`);
    // Validate all dates before issuing any historical number. The transaction also rolls back DDL.
    const rows = db.prepare('SELECT id,pipeline_id,created_at,task_no FROM pipelines ORDER BY julianday(created_at),id,pipeline_id').all();
    for (const row of rows) if (!row.task_no) {
      try { taskNumberDay(row.created_at); } catch { throw new Error(`任务 ${row.pipeline_id} 创建时间无效，任务ID迁移已回滚`); }
    }
    for (const row of rows) if (row.task_no) {
      const match = row.task_no.match(/^TASK-(\d{8})-(\d{6,})$/);
      if (!match || !Number.isSafeInteger(Number(match[2])) || Number(match[2]) < 1) throw new Error('已有任务ID格式无效');
      db.prepare(`INSERT INTO task_number_counters(day,last_value) VALUES (?,?)
        ON CONFLICT(day) DO UPDATE SET last_value=MAX(last_value,excluded.last_value)`).run(match[1], Number(match[2]));
    }
    for (const row of rows) if (!row.task_no)
      db.prepare('UPDATE pipelines SET task_no=? WHERE pipeline_id=?').run(allocateTaskNumber(db, row.created_at), row.pipeline_id);
    db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_pipelines_task_no ON pipelines(task_no COLLATE NOCASE);
      CREATE TRIGGER IF NOT EXISTS pipelines_task_no_immutable BEFORE UPDATE OF task_no ON pipelines
      WHEN OLD.task_no IS NOT NULL AND NEW.task_no COLLATE BINARY IS NOT OLD.task_no COLLATE BINARY
      BEGIN SELECT RAISE(ABORT,'任务ID不可修改'); END;`);
  }).immediate();
}
