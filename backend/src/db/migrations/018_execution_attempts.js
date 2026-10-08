export default function up(db) {
  db.transaction(() => {
    const columns = db.prepare('PRAGMA table_info(execution_steps)').all().map(column => column.name);
    for (const [name, type] of [['step_id', 'TEXT'], ['source', 'TEXT'], ['attempt_id', 'INTEGER']]) {
      if (!columns.includes(name)) db.exec(`ALTER TABLE execution_steps ADD COLUMN ${name} ${type}`);
    }
    if (!db.prepare('PRAGMA table_info(evidence_records)').all().some(column => column.name === 'attempt_id')) {
      db.exec('ALTER TABLE evidence_records ADD COLUMN attempt_id INTEGER');
    }
    db.exec(`CREATE TABLE IF NOT EXISTS execution_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL REFERENCES execution_runs(run_id) ON DELETE CASCADE,
      step_index INTEGER NOT NULL, step_id TEXT, source TEXT, tool_id TEXT,
      args TEXT, started_at TEXT, completed_at TEXT, success INTEGER, exit_code INTEGER,
      stdout TEXT, stderr TEXT, execution_mode TEXT, duration_ms INTEGER,
      react_thought TEXT, react_action TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_execution_attempts_run ON execution_attempts(run_id, id);`);
  })();
}
