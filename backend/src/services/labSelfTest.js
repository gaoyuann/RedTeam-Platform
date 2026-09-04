// ── Lab Self-Test Service ──────────────────────────────────────────────────
// Runs an end-to-end self-test against a lab to verify the tool chain works:
//   start lab → wait for healthy → nmap quick scan → verify open ports → stop lab
import { execFile } from 'child_process';
import { promisify } from 'util';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { getEngine } from '../tools/containerEngine.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..', '..');
const LABS_DIR = resolve(PROJECT_ROOT, 'containers', 'labs');

const execFileAsync = promisify(execFile);

/**
 * Wait for a lab's containers to become healthy (or at least 'Up').
 * Polls the container engine every 2s until all containers report healthy status
 * or the timeout is reached.
 *
 * @param {string} name - Lab/compose project name
 * @param {number} [maxWaitMs=120000] - Maximum time to wait in ms
 * @returns {Promise<boolean>} true if all containers are healthy
 */
async function waitForHealthy(name, maxWaitMs = 120_000) {
  const engine = await getEngine();
  if (engine === 'host') return false;

  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    try {
      const { stdout } = await execFileAsync(engine, [
        'ps', '--filter', `label=com.docker.compose.project=${name}`,
        '--format', '{{.Status}}\t{{.Names}}',
      ]);
      const lines = stdout.trim().split('\n').filter(Boolean);
      if (lines.length > 0) {
        // All containers should be healthy or at least Up
        const allHealthy = lines.every((line) => {
          const [status] = line.split('\t');
          return status.includes('healthy') || status.includes('Up');
        });
        if (allHealthy) return true;
      }
    } catch {
      // Engine not ready yet, keep polling
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  return false;
}

/**
 * Get the first container's IP address on the compose network for a given project.
 *
 * @param {string} engine - Container engine binary (podman or docker)
 * @param {string} name - Compose project name
 * @returns {Promise<string|null>} IP address or null
 */
async function getLabTargetIp(engine, name) {
  try {
    const { stdout: psOut } = await execFileAsync(engine, [
      'ps', '--filter', `label=com.docker.compose.project=${name}`,
      '--format', '{{.ID}}',
    ]);
    const ids = psOut.trim().split('\n').filter(Boolean);
    if (ids.length === 0) return null;

    // Inspect the first container for its network IP
    const { stdout: inspectOut } = await execFileAsync(engine, [
      'inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}', ids[0],
    ]);
    const ips = inspectOut.trim().split(/\s+/).filter(Boolean);
    return ips[0] || null;
  } catch {
    return null;
  }
}

/**
 * Run a quick nmap scan against the given target inside the rt-recon container.
 *
 * @param {string} engine - Container engine binary
 * @param {string} targetIp - IP address to scan
 * @returns {Promise<{success: boolean, openPortCount: number, stdout: string, stderr: string}>}
 */
async function quickScan(engine, targetIp) {
  try {
    const { stdout, stderr } = await execFileAsync(engine, [
      'run', '--rm', '--network', 'host',
      'rt-recon', 'nmap', '-Pn', '-sV', '--top-ports', '100', targetIp,
    ], { timeout: 60_000 });

    // Count lines like "80/tcp   open  http"
    const openPorts = stdout.match(/^\d+\/tcp\s+open\s+/gm);
    return {
      success: openPorts && openPorts.length > 0,
      openPortCount: openPorts ? openPorts.length : 0,
      stdout,
      stderr,
    };
  } catch (err) {
    return { success: false, openPortCount: 0, stdout: '', stderr: err.message };
  }
}

/**
 * Run a full end-to-end self-test against a lab.
 *
 * The test follows this sequence:
 *   1. Detect container engine (podman/docker)
 *   2. Start lab containers via `compose up -d`
 *   3. Wait for all containers to report healthy (up to 120s)
 *   4. Retrieve the first container's IP on the compose network
 *   5. Run a quick nmap scan (top 100 ports) against that IP
 *   6. Verify at least one open port was found
 *   7. Stop lab containers via `compose down`
 *
 * @param {string} labName - Name of the lab (subdirectory under containers/labs/)
 * @returns {Promise<{ok: boolean, checks: Array<{name: string, passed: boolean, detail: string}>, duration: number, error?: string}>}
 */
export async function runSelfTest(labName) {
  const startTime = Date.now();
  const checks = [];

  // ── Helper to stop lab (best-effort cleanup) ────────────────────────────
  const stopLab = async (engine) => {
    try {
      const labDir = resolve(LABS_DIR, labName);
      await execFileAsync(engine, ['compose', '-f', `${labDir}/docker-compose.yml`, 'down'], { timeout: 15_000 });
    } catch {
      // Best-effort cleanup, ignore errors
    }
  };

  try {
    // 1. Engine detection
    const engine = await getEngine();
    if (engine === 'host') {
      return {
        ok: false,
        error: 'No container engine (podman/docker) available',
        checks: [{ name: 'engine-detection', passed: false, detail: 'No container engine found' }],
        duration: Date.now() - startTime,
      };
    }
    checks.push({ name: 'engine-detection', passed: true, detail: `Using engine: ${engine}` });

    // 2. Start lab
    const labDir = resolve(LABS_DIR, labName);
    let composeResult;
    try {
      const { stdout, stderr } = await execFileAsync(
        engine, ['compose', '-f', `${labDir}/docker-compose.yml`, 'up', '-d'],
        { timeout: 30_000 }
      );
      composeResult = { stdout, stderr };
    } catch (err) {
      await stopLab(engine);
      return {
        ok: false,
        error: `Failed to start lab: ${err.message}`,
        checks: [...checks, { name: 'compose-up', passed: false, detail: err.message }],
        duration: Date.now() - startTime,
      };
    }
    checks.push({ name: 'compose-up', passed: true, detail: 'Lab containers started' });

    // 3. Wait for healthy
    const healthy = await waitForHealthy(labName);
    if (!healthy) {
      await stopLab(engine);
      return {
        ok: false,
        error: 'Lab did not become healthy within timeout',
        checks: [...checks, { name: 'wait-healthy', passed: false, detail: 'Timed out waiting for healthy status (120s)' }],
        duration: Date.now() - startTime,
      };
    }
    checks.push({ name: 'wait-healthy', passed: true, detail: 'Lab containers are healthy' });

    // 4. Get target IP
    const targetIp = await getLabTargetIp(engine, labName);
    if (!targetIp) {
      await stopLab(engine);
      return {
        ok: false,
        error: 'Could not determine lab container IP',
        checks: [...checks, { name: 'get-target-ip', passed: false, detail: 'Failed to retrieve container IP from inspect' }],
        duration: Date.now() - startTime,
      };
    }
    checks.push({ name: 'get-target-ip', passed: true, detail: `Target IP: ${targetIp}` });

    // 5. Run quick nmap scan
    const scanResult = await quickScan(engine, targetIp);
    if (!scanResult.success || scanResult.openPortCount === 0) {
      const detail = scanResult.openPortCount === 0
        ? 'Nmap scan completed but no open ports found'
        : `Nmap scan failed: ${(scanResult.stderr || '').slice(0, 200)}`;
      await stopLab(engine);
      return {
        ok: false,
        error: 'Nmap scan did not detect open ports',
        checks: [...checks, { name: 'quick-scan', passed: false, detail }],
        duration: Date.now() - startTime,
      };
    }
    checks.push({
      name: 'quick-scan',
      passed: true,
      detail: `Found ${scanResult.openPortCount} open port(s) on ${targetIp}`,
    });

    // 6. Stop lab
    try {
      const { stdout, stderr } = await execFileAsync(
        engine, ['compose', '-f', `${labDir}/docker-compose.yml`, 'down'],
        { timeout: 15_000 }
      );
      checks.push({ name: 'compose-down', passed: true, detail: 'Lab containers stopped' });
    } catch (err) {
      return {
        ok: false,
        error: `Failed to stop lab: ${err.message}`,
        checks: [...checks, { name: 'compose-down', passed: false, detail: err.message }],
        duration: Date.now() - startTime,
      };
    }

    return {
      ok: true,
      checks,
      duration: Date.now() - startTime,
    };
  } catch (err) {
    // Unexpected error — attempt cleanup
    try {
      const engine = await getEngine();
      if (engine !== 'host') await stopLab(engine);
    } catch {
      // Ignore cleanup errors
    }

    return {
      ok: false,
      error: err.message,
      checks: [...checks, { name: 'unexpected-error', passed: false, detail: err.message }],
      duration: Date.now() - startTime,
    };
  }
}
