import express from 'express';
import cors from 'cors';
import { createServer } from 'http';
import { exec } from 'child_process';
import { promisify } from 'util';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

import { getDb } from './db/connection.js';
import { runMigrations } from './db/migrate.js';
import errorHandler from './middleware/errorHandler.js';
import { authenticate } from './middleware/auth.js';
import { rbacGuard } from './middleware/rbac.js';
import { initWebSocket } from './services/wsManager.js';

import healthRoutes from './routes/health.js';
import userRoutes from './routes/users.js';
import classRoutes from './routes/classes.js';
import membershipRoutes from './routes/memberships.js';
import assignmentRoutes from './routes/assignments.js';
import submissionRoutes from './routes/submissions.js';
import playbookRoutes from './routes/playbooks.js';
import runRoutes from './routes/runs.js';
import auditRoutes from './routes/audit.js';
import scanRoutes from './routes/scans.js';
import configRoutes from './routes/config.js';
import reportRoutes from './routes/reports.js';
import toolRoutes from './routes/tools.js';
import topologyRoutes from './routes/topology.js';
import knowledgeRoutes from './routes/knowledge.js';
import payloadRoutes from './routes/payloads.js';

// ── Config ──────────────────────────────────────────────────────────────
const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..');
const PORT = process.env.PORT || 3002;
const MIGRATIONS_DIR = resolve(__dirname, 'db', 'migrations');

const execAsync = promisify(exec);

// ── Database & Migrations ───────────────────────────────────────────────
const db = getDb();

// ── Express App ─────────────────────────────────────────────────────────
const app = express();
app.use(cors());
app.use(express.json());

// ── Mount Routes ────────────────────────────────────────────────────────
// Public routes (no auth required)
app.use('/api', healthRoutes(db));
app.use('/api/users', userRoutes(db));  // login/refresh are public; CRUD is protected internally

// Protected routes (authenticate + RBAC guard)
const protectedRoutes = [
  ['/api/classes',     classRoutes(db),     'classes'],
  ['/api/memberships', membershipRoutes(db),'memberships'],
  ['/api/assignments', assignmentRoutes(db),'assignments'],
  ['/api/submissions', submissionRoutes(db),'submissions'],
  ['/api/playbooks',   playbookRoutes(db),  'playbooks'],
  ['/api/runs',        runRoutes(db),       'runs'],
  ['/api/audit',       auditRoutes(db),     'audit'],
  ['/api/scan-tasks',  scanRoutes(db),      'scan-tasks'],
  ['/api/config',      configRoutes(db),    'config'],
  ['/api/tools',       toolRoutes(db),      'tools'],
  ['/api/reports',     reportRoutes(db),    'reports'],
  ['/api/topology',    topologyRoutes(db),  'topology'],
  ['/api/kg',          knowledgeRoutes(db), 'kg'],
  ['/api/payloads',    payloadRoutes(db),   'payloads'],
];
for (const [path, routeFn, guard] of protectedRoutes) {
  app.use(path, authenticate, rbacGuard(guard), routeFn);
}

// ── Legacy Phase 0 endpoints (keep for Qt frontend compat) ──────────────
app.get('/api/db-test', (_req, res) => {
  try {
    const tables = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).all().map(r => r.name);
    const stats = {};
    for (const t of tables) {
      const row = db.prepare(`SELECT COUNT(*) AS n FROM "${t}"`).get();
      stats[t] = row.n;
    }
    res.json({ status: 'ok', source: 'SQLite', tables: stats });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

app.get('/api/container-test', async (_req, res) => {
  try {
    const { runTool } = await import('./tools/toolRunner.js');
    const result = await runTool('nmap', ['--version'], { timeout: 15000 });
    res.json({
      status: result.success ? 'ok' : 'error',
      engine: result.executionMode,
      tool: 'nmap',
      image: 'rt-recon:latest',
      output: result.stdout || result.stderr,
      ...(result.success ? {} : { message: result.stderr }),
    });
  } catch (err) {
    res.json({ status: 'error', engine: 'unknown', tool: 'nmap', message: err.message });
  }
});

// ── DB Admin ────────────────────────────────────────────────────────────
app.get('/api/db/stats', (_req, res) => {
  try {
    const tables = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).all().map(r => r.name);
    const stats = {};
    for (const t of tables) {
      const row = db.prepare(`SELECT COUNT(*) AS n FROM "${t}"`).get();
      stats[t] = row.n;
    }
    import('fs').then(fs => fs.promises.stat(resolve(PROJECT_ROOT, 'data', 'redteam.db'))).then(({ size }) => {
      res.json({ status: 'ok', data: { tableRowCounts: stats, dbSizeBytes: size } });
    }).catch(() => {
      res.json({ status: 'ok', data: { tableRowCounts: stats, dbSizeBytes: null } });
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
});

// ── Error Handler ───────────────────────────────────────────────────────
app.use(errorHandler);

// ── Start ───────────────────────────────────────────────────────────────
async function start() {
  const applied = await runMigrations(db, MIGRATIONS_DIR);
  if (applied.length > 0) {
    console.log(`[DB] Applied ${applied.length} new migrations`);
  }

  const HOST = process.env.HOST || '0.0.0.0';
  const server = createServer(app);
  initWebSocket(server);
  server.listen(PORT, HOST, () => {
    console.log(`[Server] RedTeam Backend running on http://${HOST}:${PORT}`);
    console.log(`[Server] WebSocket available at ws://${HOST}:${PORT}/ws`);
    console.log(`[Server] API endpoints mounted: /api/users, /api/classes, /api/playbooks, /api/runs, /api/scan-tasks, /api/config, ...`);
  });
}

start();
