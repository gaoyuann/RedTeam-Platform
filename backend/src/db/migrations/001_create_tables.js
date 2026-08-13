export default function up(db) {
  db.exec(`
    -- ── Users ────────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    NOT NULL UNIQUE,
      password      TEXT    NOT NULL,
      role          TEXT    NOT NULL CHECK (role IN ('admin','teacher','student','operator','viewer')),
      display_name  TEXT,
      is_active     INTEGER NOT NULL DEFAULT 1,
      created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
      updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

    -- ── Classes ──────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS classes (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      class_id    TEXT    NOT NULL UNIQUE,
      name        TEXT    NOT NULL,
      teacher_sub TEXT    REFERENCES users(username),
      join_code   TEXT,
      created_at  TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_classes_teacher ON classes(teacher_sub);

    -- ── Memberships ──────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS memberships (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      class_id   TEXT    NOT NULL REFERENCES classes(class_id),
      user_sub   TEXT    NOT NULL REFERENCES users(username),
      role       TEXT    NOT NULL,
      joined_at  TEXT,
      UNIQUE(class_id, user_sub)
    );
    CREATE INDEX IF NOT EXISTS idx_memberships_class ON memberships(class_id);
    CREATE INDEX IF NOT EXISTS idx_memberships_user  ON memberships(user_sub);

    -- ── Assignments ──────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS assignments (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      assignment_id TEXT    NOT NULL UNIQUE,
      class_id      TEXT    NOT NULL REFERENCES classes(class_id),
      title         TEXT    NOT NULL,
      playbook_id   TEXT,
      due_at        TEXT,
      rubric        TEXT,
      created_by    TEXT    REFERENCES users(username),
      created_at    TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_assignments_class ON assignments(class_id);

    -- ── Submissions ──────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS submissions (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      submission_id   TEXT    NOT NULL UNIQUE,
      assignment_id   TEXT    NOT NULL REFERENCES assignments(assignment_id),
      class_id        TEXT    NOT NULL REFERENCES classes(class_id),
      student_sub     TEXT    NOT NULL REFERENCES users(username),
      run_id          TEXT,
      submitted_at    TEXT,
      auto_grade      TEXT,
      override_grade  TEXT,
      final_grade     TEXT,
      feedback        TEXT,
      reviewed_at     TEXT,
      reviewed_by     TEXT    REFERENCES users(username)
    );
    CREATE INDEX IF NOT EXISTS idx_submissions_assignment ON submissions(assignment_id);
    CREATE INDEX IF NOT EXISTS idx_submissions_student    ON submissions(student_sub);
    CREATE INDEX IF NOT EXISTS idx_submissions_run        ON submissions(run_id);

    -- ── Playbooks ────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS playbooks (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      playbook_id     TEXT    NOT NULL UNIQUE,
      name            TEXT    NOT NULL,
      description     TEXT,
      author          TEXT,
      difficulty      TEXT,
      category        TEXT,
      estimated_time  INTEGER,
      target_type     TEXT,
      not_suitable_for TEXT,
      baseline_group  TEXT,
      expected_output_policy TEXT,
      teaching_objective TEXT,
      roles_allowed   TEXT,
      disable_auto_insert INTEGER DEFAULT 0,
      enable_kg_context    INTEGER DEFAULT 0,
      requires_teacher_review INTEGER DEFAULT 0,
      mitre_techniques TEXT,
      metadata         TEXT,
      is_generated     INTEGER DEFAULT 0,
      generated_from   TEXT,
      generated_at     TEXT,
      created_at       TEXT    DEFAULT (datetime('now')),
      updated_at       TEXT    DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_playbooks_baseline  ON playbooks(baseline_group);
    CREATE INDEX IF NOT EXISTS idx_playbooks_generated ON playbooks(is_generated);

    -- ── Playbook Steps ───────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS playbook_steps (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      playbook_id     TEXT    NOT NULL REFERENCES playbooks(playbook_id) ON DELETE CASCADE,
      step_index      INTEGER NOT NULL,
      step_id         TEXT    NOT NULL,
      name            TEXT    NOT NULL,
      tool_id         TEXT    NOT NULL,
      args_template   TEXT,
      description     TEXT,
      score           INTEGER DEFAULT 0,
      expected_mitre  TEXT,
      payload_id      TEXT,
      payload_variables TEXT,
      evidence_config TEXT,
      requires_teacher_review INTEGER DEFAULT 0,
      optional        INTEGER DEFAULT 0,
      UNIQUE(playbook_id, step_index)
    );
    CREATE INDEX IF NOT EXISTS idx_playbook_steps_playbook ON playbook_steps(playbook_id);
    CREATE INDEX IF NOT EXISTS idx_playbook_steps_tool     ON playbook_steps(tool_id);

    -- ── Execution Runs ───────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS execution_runs (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id           TEXT    NOT NULL UNIQUE,
      playbook_id      TEXT    REFERENCES playbooks(playbook_id),
      playbook_run_id  TEXT,
      status           TEXT    NOT NULL DEFAULT 'PENDING'
                       CHECK (status IN ('PENDING','RUNNING','COMPLETED','FAILED','ABORTED')),
      user_sub         TEXT,
      user_role        TEXT,
      target           TEXT,
      engine_type      TEXT    DEFAULT 'playbook',
      preflight_status TEXT,
      preflight_data   TEXT,
      score_data       TEXT,
      graph_data       TEXT,
      plan_data        TEXT,
      final_summary    TEXT,
      stop_reason      TEXT,
      aborted_at       TEXT,
      created_at       TEXT,
      updated_at       TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_runs_status    ON execution_runs(status);
    CREATE INDEX IF NOT EXISTS idx_runs_playbook  ON execution_runs(playbook_id);
    CREATE INDEX IF NOT EXISTS idx_runs_user      ON execution_runs(user_sub);
    CREATE INDEX IF NOT EXISTS idx_runs_created   ON execution_runs(created_at);

    -- ── Execution Steps ──────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS execution_steps (
      id           INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id       TEXT    NOT NULL REFERENCES execution_runs(run_id) ON DELETE CASCADE,
      step_index   INTEGER NOT NULL,
      tool_id      TEXT,
      args         TEXT,
      executed_at  TEXT,
      success      INTEGER,
      exit_code    INTEGER,
      notes        TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_exec_steps_run ON execution_steps(run_id);

    -- ── Evidence Records ─────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS evidence_records (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id          TEXT    NOT NULL REFERENCES execution_runs(run_id) ON DELETE CASCADE,
      step_index      INTEGER,
      tool_id         TEXT,
      evidence_type   TEXT,
      evidence_data   TEXT,
      raw_stdout      TEXT,
      raw_stderr      TEXT,
      target          TEXT,
      mitre_hits      TEXT,
      recommendations TEXT,
      rule_matches    TEXT,
      recorded_at     TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence_records(run_id);

    -- ── Audit Log ────────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS audit_log (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      type           TEXT    NOT NULL,
      execution_id   TEXT,
      tool_id        TEXT,
      bin            TEXT,
      args           TEXT,
      user_role      TEXT,
      target         TEXT,
      run_id         TEXT,
      use_sandbox    INTEGER,
      execution_mode TEXT,
      success        INTEGER,
      exit_code      INTEGER,
      duration_ms    INTEGER,
      output_size    INTEGER,
      reasons        TEXT,
      timestamp      TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_audit_type      ON audit_log(type);
    CREATE INDEX IF NOT EXISTS idx_audit_tool      ON audit_log(tool_id);
    CREATE INDEX IF NOT EXISTS idx_audit_run       ON audit_log(run_id);

    -- ── Scan Tasks (new workflow) ────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS scan_tasks (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_task_id  TEXT    NOT NULL UNIQUE,
      target        TEXT    NOT NULL,
      scan_type     TEXT    NOT NULL,
      status        TEXT    NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING','RUNNING','COMPLETED','FAILED','CANCELLED')),
      parameters    TEXT,
      created_by    TEXT    REFERENCES users(username),
      created_at    TEXT,
      started_at    TEXT,
      completed_at  TEXT,
      error_message TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_scan_tasks_status  ON scan_tasks(status);
    CREATE INDEX IF NOT EXISTS idx_scan_tasks_target  ON scan_tasks(target);
    CREATE INDEX IF NOT EXISTS idx_scan_tasks_type    ON scan_tasks(scan_type);

    -- ── Scan Results (new workflow) ──────────────────────────────────────
    CREATE TABLE IF NOT EXISTS scan_results (
      id                 INTEGER PRIMARY KEY AUTOINCREMENT,
      scan_task_id       TEXT    NOT NULL REFERENCES scan_tasks(scan_task_id) ON DELETE CASCADE,
      result_type        TEXT    NOT NULL,
      result_data        TEXT,
      severity           TEXT,
      confidence         REAL,
      mitre_technique_id TEXT,
      source_tool        TEXT,
      captured_at        TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_scan_results_task     ON scan_results(scan_task_id);
    CREATE INDEX IF NOT EXISTS idx_scan_results_type     ON scan_results(result_type);
    CREATE INDEX IF NOT EXISTS idx_scan_results_severity ON scan_results(severity);
    CREATE INDEX IF NOT EXISTS idx_scan_results_mitre    ON scan_results(mitre_technique_id);

    -- ── System Config ────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS system_config (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      config_key  TEXT    NOT NULL UNIQUE,
      config_value TEXT   NOT NULL,
      category    TEXT    NOT NULL,
      description TEXT,
      updated_at  TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_sysconfig_category ON system_config(category);

    -- ── Test Reports ─────────────────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS test_reports (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      report_id     TEXT    NOT NULL UNIQUE,
      title         TEXT    NOT NULL,
      run_id        TEXT    REFERENCES execution_runs(run_id),
      scan_task_id  TEXT    REFERENCES scan_tasks(scan_task_id),
      template      TEXT,
      status        TEXT    DEFAULT 'draft',
      content       TEXT,
      generated_by  TEXT    REFERENCES users(username),
      created_at    TEXT,
      updated_at    TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_reports_run    ON test_reports(run_id);
    CREATE INDEX IF NOT EXISTS idx_reports_status ON test_reports(status);
  `);
}
