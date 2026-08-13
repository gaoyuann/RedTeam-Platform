import { readdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export async function runMigrations(db, migrationsDir) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS _migrations (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      name       TEXT    NOT NULL UNIQUE,
      applied_at TEXT    NOT NULL DEFAULT (datetime('now'))
    )
  `);

  const applied = new Set(
    db.prepare('SELECT name FROM _migrations').all().map(r => r.name)
  );

  const files = readdirSync(migrationsDir)
    .filter(f => f.endsWith('.js'))
    .sort();

  const insertMigration = db.prepare(
    'INSERT INTO _migrations (name) VALUES (?)'
  );

  const appliedNames = [];

  for (const file of files) {
    if (applied.has(file)) continue;
    console.log(`[Migration] Running: ${file}`);
    const mod = await import(join(migrationsDir, file));
    const up = mod.default || mod.up;
    if (typeof up !== 'function') {
      throw new Error(`Migration ${file} has no default export or up() function`);
    }
    up(db);
    insertMigration.run(file);
    appliedNames.push(file);
    console.log(`[Migration] Applied: ${file}`);
  }

  if (appliedNames.length === 0) {
    console.log('[Migration] All migrations already applied');
  }

  return appliedNames;
}
