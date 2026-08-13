// ── Migration 007: Auth tables (token blacklist + refresh tokens) ───────
export default function up(db) {
  db.exec(`
    -- Token blacklist (for logout / forced token revocation)
    CREATE TABLE IF NOT EXISTS token_blacklist (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      jti        TEXT    NOT NULL UNIQUE,
      expires_at TEXT    NOT NULL,
      created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_token_blacklist_jti     ON token_blacklist(jti);
    CREATE INDEX IF NOT EXISTS idx_token_blacklist_expires ON token_blacklist(expires_at);

    -- Refresh tokens (opaque, stored in DB for server-side revocation)
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token      TEXT    NOT NULL UNIQUE,
      expires_at TEXT    NOT NULL,
      created_at TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user   ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token  ON refresh_tokens(token);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
  `);

  // Seed default users if the users table is empty
  const userCount = db.prepare('SELECT COUNT(*) AS n FROM users').get().n;
  if (userCount === 0) {
    const insertUser = db.prepare(
      'INSERT OR IGNORE INTO users (username, password, role, display_name) VALUES (?, ?, ?, ?)'
    );
    insertUser.run('admin', 'admin', 'admin', '系统管理员');
    insertUser.run('teacher', '123', 'teacher', '教师');
    insertUser.run('student', '123456', 'student', '学生');
    console.log('[Migration 007] Seeded default users: admin/admin, teacher/123, student/123456');
  }
}
