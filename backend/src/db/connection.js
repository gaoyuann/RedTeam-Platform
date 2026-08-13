import BetterSqlite3 from 'better-sqlite3';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..', '..');
const DEFAULT_DB_PATH = resolve(PROJECT_ROOT, 'data', 'redteam.db');

let _db = null;

export function getDb(dbPath) {
  if (_db) return _db;
  const path = dbPath || process.env.DB_PATH || DEFAULT_DB_PATH;
  console.log(`[DB] Opening database at: ${path}`);
  _db = new BetterSqlite3(path);
  _db.pragma('journal_mode = WAL');
  _db.pragma('foreign_keys = ON');
  return _db;
}

export function closeDb() {
  if (_db) {
    _db.close();
    _db = null;
  }
}
