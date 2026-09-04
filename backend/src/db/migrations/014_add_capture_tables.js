// ── Capture Tasks & Analysis Tables ─────────────────────────────────────
// 网络数据捕获任务 + 捕获分析结果
export default function up(db) {
  db.exec(`
    -- ── Capture Tasks ────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS capture_tasks (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      capture_task_id TEXT    NOT NULL UNIQUE,
      interface       TEXT    NOT NULL DEFAULT 'eth0',
      bpf_filter      TEXT,
      capture_type    TEXT    NOT NULL DEFAULT 'timed'
                      CHECK (capture_type IN ('timed','manual')),
      duration_sec    INTEGER DEFAULT 60,
      status          TEXT    NOT NULL DEFAULT 'PENDING'
                      CHECK (status IN ('PENDING','RUNNING','COMPLETED','FAILED','STOPPED')),
      pcap_path       TEXT,
      packet_count    INTEGER DEFAULT 0,
      file_size_bytes INTEGER DEFAULT 0,
      created_by      TEXT    REFERENCES users(username),
      error_message   TEXT,
      created_at      TEXT,
      started_at      TEXT,
      stopped_at      TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_capture_tasks_status ON capture_tasks(status);
    CREATE INDEX IF NOT EXISTS idx_capture_tasks_created ON capture_tasks(created_at);

    -- ── Capture Analysis Results ─────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS capture_analysis (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      capture_task_id TEXT    NOT NULL REFERENCES capture_tasks(capture_task_id) ON DELETE CASCADE,
      analysis_type   TEXT    NOT NULL,
      analysis_data   TEXT    NOT NULL,
      severity        TEXT,
      created_at      TEXT    DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_capture_analysis_task ON capture_analysis(capture_task_id);
    CREATE INDEX IF NOT EXISTS idx_capture_analysis_type ON capture_analysis(analysis_type);
  `);
}
