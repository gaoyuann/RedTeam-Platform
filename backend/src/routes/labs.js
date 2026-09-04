// ── Labs Router ────────────────────────────────────────────────────────────
// Manages penetration-testing target labs (DVWA, Juice Shop, WebGoat, etc.)
// Each lab is a subdirectory under containers/labs/ with a docker-compose.yml.
import { Router } from 'express';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { readdir, readFile } from 'fs/promises';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getEngine } from '../tools/containerEngine.js';
import { getWsManager } from '../services/wsManager.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..', '..');
const LABS_DIR = resolve(PROJECT_ROOT, 'containers', 'labs');

const execFileAsync = promisify(execFile);

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * List all available labs by scanning the containers/labs/ directory.
 * @returns {Promise<string[]>} Array of lab names (directory basenames)
 */
async function listAvailableLabs() {
  try {
    const entries = await readdir(LABS_DIR, { withFileTypes: true });
    return entries
      .filter((e) => e.isDirectory())
      .map((e) => e.name)
      .sort();
  } catch {
    return [];
  }
}

/**
 * Check which labs are currently running by querying the container engine
 * for compose projects with label com.docker.compose.project.
 * @returns {Promise<Set<string>>} Set of running lab names
 */
async function getRunningLabs() {
  const engine = await getEngine();
  if (engine === 'host') return new Set();

  try {
    const { stdout } = await execFileAsync(engine, [
      'ps', '--filter', 'label=com.docker.compose.project',
      '--format', '{{.Label "com.docker.compose.project"}}',
    ]);
    const projects = stdout.trim().split('\n').filter(Boolean);
    return new Set(projects);
  } catch {
    return new Set();
  }
}

/**
 * Get detailed container status for a single compose project.
 * @param {string} engine
 * @param {string} projectName
 * @returns {Promise<Array<{name: string, status: string, health: string|null}>>}
 */
async function getProjectContainers(engine, projectName) {
  try {
    const { stdout } = await execFileAsync(engine, [
      'ps', '--filter', `label=com.docker.compose.project=${projectName}`,
      '--format', '{{.Names}}\t{{.Status}}\t{{.ID}}',
    ]);
    const lines = stdout.trim().split('\n').filter(Boolean);
    return lines.map((line) => {
      const [name, status] = line.split('\t');
      const healthyLabel = status && status.includes('healthy') ? 'healthy'
        : status && status.includes('unhealthy') ? 'unhealthy'
        : status && status.includes('Up') ? 'starting'
        : 'stopped';
      return { name, status: status || 'unknown', health: healthyLabel };
    });
  } catch {
    return [];
  }
}

/**
 * Parse a docker-compose.yml for basic metadata (services, ports, image).
 * @param {string} labName
 * @returns {Promise<object>} Parsed metadata
 */
async function parseLabMetadata(labName) {
  const composePath = resolve(LABS_DIR, labName, 'docker-compose.yml');
  try {
    const content = await readFile(composePath, 'utf-8');
    // Simple YAML-like parsing for service/port info
    const services = [];
    const lines = content.split('\n');
    let currentService = null;

    for (const line of lines) {
      const serviceMatch = line.match(/^\s{2}(\w[\w-]*):\s*$/);
      if (serviceMatch) {
        currentService = { name: serviceMatch[1], image: null, ports: [] };
        services.push(currentService);
        continue;
      }
      if (currentService) {
        const imageMatch = line.match(/^\s{4}image:\s*["']?(.+?)["']?\s*$/);
        if (imageMatch) {
          currentService.image = imageMatch[1];
          continue;
        }
        const portMatch = line.match(/^\s{4}-\s*["']?(?:127\.0\.0\.1:)?(\d+):(\d+)["']?\s*$/);
        if (portMatch) {
          currentService.ports.push({
            host: parseInt(portMatch[1], 10),
            container: parseInt(portMatch[2], 10),
          });
          continue;
        }
      }
    }

    return { services };
  } catch {
    return { services: [] };
  }
}

// ── Route factory ─────────────────────────────────────────────────────────

export default function (/* db */) {
  const router = Router();

  // ── GET / — List available labs with their running status ───────────────

  router.get('/', async (req, res) => {
    try {
      const [available, running] = await Promise.all([
        listAvailableLabs(),
        getRunningLabs(),
      ]);

      // Build detailed lab info (parse compose metadata for each lab)
      const data = await Promise.all(
        available.map(async (name) => {
          const metadata = await parseLabMetadata(name);
          const isRunning = running.has(name);
          let containers = [];
          if (isRunning) {
            const engine = await getEngine();
            containers = await getProjectContainers(engine, name);
          }
          return {
            name,
            status: isRunning ? 'running' : 'stopped',
            containers,
            services: metadata.services,
          };
        })
      );

      res.json({ status: 'ok', data, meta: { total: data.length } });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── GET /:name — Get single lab details with status ────────────────────

  router.get('/:name', async (req, res) => {
    try {
      const labName = req.params.name;
      const metadata = await parseLabMetadata(labName);
      const engine = await getEngine();
      const containers = await getProjectContainers(engine, labName);
      const isRunning = containers.length > 0;

      res.json({
        status: 'ok',
        data: {
          name: labName,
          status: isRunning ? 'running' : 'stopped',
          containers,
          services: metadata.services,
        },
      });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── POST /:name/start — Start a lab via compose up -d ──────────────────

  router.post('/:name/start', async (req, res) => {
    try {
      const labName = req.params.name;
      const labDir = resolve(LABS_DIR, labName);
      const engine = await getEngine();

      if (engine === 'host') {
        return res.status(503).json({
          status: 'error',
          error: { message: 'No container engine available (podman/docker)' },
        });
      }

      // Check if already running
      const existing = await getProjectContainers(engine, labName);
      if (existing.length > 0) {
        return res.status(409).json({
          status: 'error',
          error: { message: `Lab '${labName}' is already running` },
        });
      }

      // Start via compose
      await execFileAsync(
        engine, ['compose', '-f', `${labDir}/docker-compose.yml`, 'up', '-d'],
        { timeout: 30_000 }
      );

      // Broadcast event
      const ws = getWsManager();
      if (ws) {
        ws.broadcast('lab:started', {
          labName,
          userId: req.user?.sub || null,
          username: req.user?.sub || null,
          role: req.user?.role || null,
        });
      }

      res.status(202).json({
        status: 'ok',
        data: { name: labName, status: 'starting', message: 'Lab is starting' },
      });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        error: { message: `Failed to start lab: ${err.message}` },
      });
    }
  });

  // ── POST /:name/stop — Stop a lab via compose down ─────────────────────

  router.post('/:name/stop', async (req, res) => {
    try {
      const labName = req.params.name;
      const labDir = resolve(LABS_DIR, labName);
      const engine = await getEngine();

      if (engine === 'host') {
        return res.status(503).json({
          status: 'error',
          error: { message: 'No container engine available (podman/docker)' },
        });
      }

      // Stop via compose
      await execFileAsync(
        engine, ['compose', '-f', `${labDir}/docker-compose.yml`, 'down'],
        { timeout: 30_000 }
      );

      // Broadcast event
      const ws = getWsManager();
      if (ws) {
        ws.broadcast('lab:stopped', {
          labName,
          userId: req.user?.sub || null,
          username: req.user?.sub || null,
          role: req.user?.role || null,
        });
      }

      res.json({
        status: 'ok',
        data: { name: labName, status: 'stopped', message: 'Lab stopped' },
      });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        error: { message: `Failed to stop lab: ${err.message}` },
      });
    }
  });

  // ── GET /:name/status — Get detailed running status for a lab ──────────

  router.get('/:name/status', async (req, res) => {
    try {
      const labName = req.params.name;
      const engine = await getEngine();

      if (engine === 'host') {
        return res.status(503).json({
          status: 'error',
          error: { message: 'No container engine available (podman/docker)' },
        });
      }

      const containers = await getProjectContainers(engine, labName);
      const isRunning = containers.length > 0;

      res.json({
        status: 'ok',
        data: {
          name: labName,
          status: isRunning ? 'running' : 'stopped',
          containers,
        },
      });
    } catch (err) {
      res.status(500).json({ status: 'error', error: { message: err.message } });
    }
  });

  // ── POST /:name/verify — Run self-test (start → scan → stop) ──────────

  router.post('/:name/verify', async (req, res) => {
    try {
      const labName = req.params.name;

      // Import and run the self-test service
      const { runSelfTest } = await import('../services/labSelfTest.js');
      const result = await runSelfTest(labName);

      // Broadcast result
      const ws = getWsManager();
      if (ws) {
        ws.broadcast('lab:verify_result', {
          labName,
          ok: result.ok,
          checks: result.checks,
          duration: result.duration,
          userId: req.user?.sub || null,
          username: req.user?.sub || null,
          role: req.user?.role || null,
        });
      }

      if (!result.ok) {
        return res.status(200).json({
          status: 'error',
          error: { message: result.error || 'Self-test failed' },
          data: { checks: result.checks, duration: result.duration },
        });
      }

      res.json({
        status: 'ok',
        data: {
          name: labName,
          ok: true,
          checks: result.checks,
          duration: result.duration,
        },
      });
    } catch (err) {
      res.status(500).json({
        status: 'error',
        error: { message: `Self-test failed: ${err.message}` },
      });
    }
  });

  return router;
}
