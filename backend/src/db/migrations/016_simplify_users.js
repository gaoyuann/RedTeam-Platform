// ── Migration 016: Simplify users to admin + user only ──────────────────
// Removes all roles except 'admin' and 'user'. Resets admin password to
// 'admin' (plaintext, upgraded to bcrypt on first login) and creates a
// 'user' account with password 'user'. Cleans up referencing data and
// clears any DB-stored RBAC config so the new hardcoded defaults apply.
export default function up(db) {
  // Disable FK enforcement during table recreation
  db.pragma('foreign_keys = OFF');

  const tx = db.transaction(() => {
    // 1. Clean up data that references users being removed
    db.prepare(`DELETE FROM refresh_tokens WHERE user_id IN (SELECT id FROM users WHERE username NOT IN ('admin','user'))`).run();
    db.prepare(`DELETE FROM memberships WHERE user_sub NOT IN ('admin','user')`).run();
    db.prepare(`DELETE FROM submissions WHERE student_sub NOT IN ('admin','user')`).run();
    db.prepare(`UPDATE submissions SET reviewed_by = NULL WHERE reviewed_by IS NOT NULL AND reviewed_by NOT IN ('admin','user')`).run();
    db.prepare(`UPDATE classes SET teacher_sub = NULL WHERE teacher_sub IS NOT NULL AND teacher_sub NOT IN ('admin','user')`).run();
    db.prepare(`UPDATE assignments SET created_by = 'admin' WHERE created_by IS NOT NULL AND created_by NOT IN ('admin','user')`).run();
    db.prepare(`UPDATE scan_tasks SET created_by = 'admin' WHERE created_by IS NOT NULL AND created_by NOT IN ('admin','user')`).run();
    db.prepare(`UPDATE test_reports SET generated_by = 'admin' WHERE generated_by IS NOT NULL AND generated_by NOT IN ('admin','user')`).run();
    db.prepare(`UPDATE execution_runs SET user_sub = 'admin' WHERE user_sub IS NOT NULL AND user_sub NOT IN ('admin','user')`).run();

    // 2. Recreate users table with new CHECK constraint
    db.exec(`
      CREATE TABLE users_new (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        username      TEXT    NOT NULL UNIQUE,
        password      TEXT    NOT NULL,
        role          TEXT    NOT NULL CHECK (role IN ('admin','user')),
        display_name  TEXT,
        is_active     INTEGER NOT NULL DEFAULT 1,
        created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
        updated_at    TEXT    NOT NULL DEFAULT (datetime('now'))
      )
    `);

    // 3. Carry over admin (preserve id so refresh tokens stay valid), reset password
    const adminRow = db.prepare(`SELECT id, created_at FROM users WHERE username = 'admin'`).get();
    if (adminRow) {
      db.prepare(
        `INSERT INTO users_new (id, username, password, role, display_name, is_active, created_at, updated_at)
         VALUES (?, 'admin', 'admin', 'admin', '系统管理员', 1, ?, datetime('now'))`
      ).run(adminRow.id, adminRow.created_at);
    } else {
      db.prepare(
        `INSERT INTO users_new (username, password, role, display_name)
         VALUES ('admin', 'admin', 'admin', '系统管理员')`
      ).run();
    }

    // 4. Add 'user' account (password = username, plaintext)
    db.prepare(
      `INSERT INTO users_new (username, password, role, display_name)
       VALUES ('user', 'user', 'user', '普通用户')`
    ).run();

    // 5. Swap tables
    db.exec(`DROP TABLE users`);
    db.exec(`ALTER TABLE users_new RENAME TO users`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)`);

    // 6. Clear DB-stored RBAC config so new hardcoded defaults take effect
    db.prepare(`DELETE FROM system_config WHERE category = 'rbac'`).run();
  });

  tx();
  db.pragma('foreign_keys = ON');

  console.log('[Migration 016] Simplified users to admin/admin + user/user');
}
