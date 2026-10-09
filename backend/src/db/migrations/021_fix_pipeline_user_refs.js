export default function up(db) {
  const changes = db.transaction(() => {
    const admin = db.prepare("SELECT username FROM users WHERE username = 'admin' AND role = 'admin'").get();
    return db.prepare(`
      UPDATE pipelines SET created_by = ?
      WHERE created_by IS NOT NULL
        AND NOT EXISTS (SELECT 1 FROM users WHERE username = pipelines.created_by)
    `).run(admin?.username || null).changes;
  })();
  if (changes > 0) console.log(`[Migration 021] Repaired ${changes} pipeline reference(s) to deleted users`);
}
