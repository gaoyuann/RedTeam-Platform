export default function up(db) {
  db.exec(`
    -- ── 攻击战役 ──────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS campaigns (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id     TEXT    NOT NULL UNIQUE,
      name            TEXT    NOT NULL,
      description     TEXT,
      target          TEXT,
      status          TEXT    NOT NULL DEFAULT 'draft'
                      CHECK (status IN ('draft','running','paused','completed','failed','aborted')),
      created_by      TEXT    REFERENCES users(username),
      created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
      updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_campaigns_status     ON campaigns(status);
    CREATE INDEX IF NOT EXISTS idx_campaigns_created_by ON campaigns(created_by);

    -- ── 战役阶段 ──────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS campaign_phases (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      phase_id        TEXT    NOT NULL UNIQUE,
      campaign_id     TEXT    NOT NULL REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
      phase_type      TEXT    NOT NULL
                      CHECK (phase_type IN ('data-exfiltration','tampering-deception','device-control')),
      display_name    TEXT,
      order_index     INTEGER NOT NULL DEFAULT 0,
      status          TEXT    NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','running','completed','skipped','failed')),
      summary         TEXT,
      config          TEXT,
      started_at      TEXT,
      completed_at    TEXT,
      created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_phases_campaign       ON campaign_phases(campaign_id);
    CREATE INDEX IF NOT EXISTS idx_phases_type           ON campaign_phases(phase_type);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_phases_campaign_type ON campaign_phases(campaign_id, phase_type);

    -- ── 阶段-Playbook编排 ─────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS campaign_playbooks (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id     TEXT    NOT NULL REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
      phase_id        TEXT    NOT NULL REFERENCES campaign_phases(phase_id) ON DELETE CASCADE,
      playbook_id     TEXT    NOT NULL REFERENCES playbooks(playbook_id),
      execution_order INTEGER NOT NULL DEFAULT 0,
      execution_mode  TEXT    NOT NULL DEFAULT 'sequential'
                      CHECK (execution_mode IN ('sequential','parallel','conditional')),
      run_id          TEXT,
      status          TEXT    NOT NULL DEFAULT 'pending'
                      CHECK (status IN ('pending','running','completed','skipped','failed')),
      target_override TEXT,
      created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_cp_campaign  ON campaign_playbooks(campaign_id);
    CREATE INDEX IF NOT EXISTS idx_cp_phase     ON campaign_playbooks(phase_id);
    CREATE INDEX IF NOT EXISTS idx_cp_playbook  ON campaign_playbooks(playbook_id);

    -- ── 阶段产物（跨阶段数据传递） ────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS campaign_artifacts (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      campaign_id     TEXT    NOT NULL REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
      phase_id        TEXT    NOT NULL REFERENCES campaign_phases(phase_id),
      artifact_type   TEXT    NOT NULL,
      artifact_key    TEXT    NOT NULL,
      artifact_value  TEXT    NOT NULL,
      source_run_id   TEXT,
      created_at      TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_artifacts_campaign ON campaign_artifacts(campaign_id);
    CREATE INDEX IF NOT EXISTS idx_artifacts_phase    ON campaign_artifacts(phase_id);
    CREATE INDEX IF NOT EXISTS idx_artifacts_type     ON campaign_artifacts(artifact_type);
  `);
  console.log('[Migration 012] Campaign tables created');
}
