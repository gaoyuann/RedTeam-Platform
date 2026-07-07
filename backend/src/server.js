/**
 * RedTeam Platform Backend - Phase 0 Verification Server
 *
 * Minimal Express server that verifies:
 *   1. Qt ↔ Node.js HTTP communication (/api/health)
 *   2. Node.js ↔ SQLite database chain (/api/db-test)
 *   3. Node.js ↔ Docker container chain (/api/container-test)
 */

import express from 'express';
import cors from 'cors';
import { exec } from 'child_process';
import { promisify } from 'util';
import BetterSqlite3 from 'better-sqlite3';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

// ── Config ──────────────────────────────────────────────────────────────
const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..');
const DB_PATH = resolve(PROJECT_ROOT, 'data', 'redteam.db');
const PORT = process.env.PORT || 3002;

const execAsync = promisify(exec);

// ── SQLite Setup ────────────────────────────────────────────────────────
console.log(`[DB] Opening database at: ${DB_PATH}`);
const db = new BetterSqlite3(DB_PATH);

// Create verification test table and seed data
db.exec(`
  CREATE TABLE IF NOT EXISTS verification_test (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT    NOT NULL,
    value TEXT    NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// Seed test data if table is empty
const count = db.prepare('SELECT COUNT(*) AS n FROM verification_test').get();
if (count.n === 0) {
  const insert = db.prepare(
    'INSERT INTO verification_test (name, value) VALUES (?, ?)'
  );
  const seed = [
    ['backend_engine', 'Express.js 4.x'],
    ['database_engine', 'SQLite 3.x via better-sqlite3'],
    ['frontend_engine', 'Qt 5.15.3 C++'],
    ['container_engine', 'Docker (Podman fallback)'],
    ['protocol', 'HTTP REST on 127.0.0.1:3002'],
  ];
  const tx = db.transaction((rows) => {
    for (const [name, value] of rows) insert.run(name, value);
  });
  tx(seed);
  console.log(`[DB] Seeded ${seed.length} verification rows`);
} else {
  console.log(`[DB] verification_test already has ${count.n} rows, skip seed`);
}

// ── Express App ─────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());

// ── API: Health Check ───────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// ── API: SQLite Data Test ───────────────────────────────────────────────
app.get('/api/db-test', (_req, res) => {
  try {
    const rows = db.prepare('SELECT * FROM verification_test ORDER BY id').all();
    res.json({ status: 'ok', source: 'SQLite', count: rows.length, data: rows });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ── API: Container Tool Test ────────────────────────────────────────────
app.get('/api/container-test', async (_req, res) => {
  const IMAGE = 'redteam-nmap:latest';
  const CMD = `docker run --rm ${IMAGE} nmap --version`;

  try {
    const { stdout, stderr } = await execAsync(CMD, { timeout: 15000 });
    res.json({
      status: 'ok',
      engine: 'docker',
      tool: 'nmap',
      image: IMAGE,
      output: stdout.trim() || stderr.trim(),
    });
  } catch (err) {
    // Docker not available or image not found
    res.json({
      status: 'error',
      engine: 'docker',
      tool: 'nmap',
      image: IMAGE,
      message: err.message,
      hint: 'Run: docker build -t redteam-nmap:latest containers/nmap/',
    });
  }
});

// ── Start ───────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[Server] RedTeam Backend running on http://127.0.0.1:${PORT}`);
  console.log(`[Server] Endpoints:`);
  console.log(`[Server]   GET /api/health        - Health check`);
  console.log(`[Server]   GET /api/db-test       - SQLite verification data`);
  console.log(`[Server]   GET /api/container-test - Docker nmap test`);
});
