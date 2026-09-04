export default function up(db) {
  db.exec(`
    -- ── 流水线（Pipeline）：扫描→分析→生成Playbook→执行 ─────────────────────
    CREATE TABLE IF NOT EXISTS pipelines (
      id                  INTEGER PRIMARY KEY AUTOINCREMENT,
      pipeline_id         TEXT    NOT NULL UNIQUE,
      target              TEXT    NOT NULL,
      status              TEXT    NOT NULL DEFAULT 'created'
                            CHECK (status IN (
                              'created','running','paused','completed','failed','cancelled'
                            )),
      scan_task_id        TEXT,                        -- 主扫描任务ID（逗号分隔多任务）
      analysis_result     TEXT,                        -- JSON：技术栈/攻击面/风险评估/策略
      generated_playbook_id TEXT,                       -- AI生成或匹配的playbook_id
      run_id              TEXT,                        -- 最终执行run_id
      config              TEXT    DEFAULT '{}',
      result              TEXT,                        -- 最终执行摘要
      error_message       TEXT,
      created_by          TEXT    REFERENCES users(username),
      created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
      updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_pipelines_status      ON pipelines(status);
    CREATE INDEX IF NOT EXISTS idx_pipelines_created_by  ON pipelines(created_by);
    CREATE INDEX IF NOT EXISTS idx_pipelines_target      ON pipelines(target);

    -- ── 流水线步骤（细化每个阶段的执行状态） ──────────────────────────────────
    CREATE TABLE IF NOT EXISTS pipeline_steps (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      pipeline_id     TEXT    NOT NULL REFERENCES pipelines(pipeline_id) ON DELETE CASCADE,
      step_order      INTEGER NOT NULL,
      step_type       TEXT    NOT NULL
                      CHECK (step_type IN ('scan','analyze','generate','execute')),
      status          TEXT    NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','running','completed','failed','skipped','cancelled')),
      input_data      TEXT,                             -- 步骤输入（JSON）
      output_data     TEXT,                             -- 步骤输出（JSON）
      started_at      TEXT,
      completed_at    TEXT,
      error_message   TEXT,
      UNIQUE(pipeline_id, step_order)
    );
    CREATE INDEX IF NOT EXISTS idx_ps_pipeline ON pipeline_steps(pipeline_id);
    CREATE INDEX IF NOT EXISTS idx_ps_status   ON pipeline_steps(status);
  `);
  console.log('[Migration 013] Pipeline tables created');
}
