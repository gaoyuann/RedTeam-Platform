// ── Capture Executor ────────────────────────────────────────────────────
// Manages network packet capture lifecycle using tcpdump in containers.
// Supports timed and manual capture modes with real-time WebSocket updates.
import { getDb } from '../db/connection.js';
import { getEngine } from '../tools/containerEngine.js';
import { getWsManager } from './wsManager.js';
import { spawn } from 'child_process';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { existsSync, statSync, mkdirSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(__dirname, '..', '..', '..');
const CAPTURES_DIR = resolve(PROJECT_ROOT, 'data', 'captures');

// Track running capture processes for stop/control
const runningCaptures = new Map(); // captureTaskId → { child, timer, manuallyStopped }

// Ensure captures directory exists
if (!existsSync(CAPTURES_DIR)) {
  mkdirSync(CAPTURES_DIR, { recursive: true });
}

// ── Execute a capture task ──────────────────────────────────────────────
export async function executeCapture(captureTaskId) {
  if (runningCaptures.has(captureTaskId)) {
    return { ok: false, error: 'Capture is already running' };
  }

  const db = getDb();
  const task = db.prepare(
    'SELECT capture_task_id, interface, bpf_filter, capture_type, duration_sec, status FROM capture_tasks WHERE capture_task_id = ?'
  ).get(captureTaskId);

  if (!task) return { ok: false, error: 'Capture task not found' };
  if (task.status === 'RUNNING') return { ok: false, error: 'Capture is already running' };

  // Mark as RUNNING
  const now = new Date().toISOString();
  db.prepare("UPDATE capture_tasks SET status = 'RUNNING', started_at = ? WHERE capture_task_id = ?")
    .run(now, captureTaskId);

  const pcapFile = `/tmp/captures/${captureTaskId}.pcap`;
  const localPcapPath = resolve(CAPTURES_DIR, `${captureTaskId}.pcap`);

  try {
    const engine = await getEngine();
    if (engine === 'host') {
      // Direct execution fallback
      return await executeCaptureDirect(captureTaskId, task, pcapFile, localPcapPath);
    }

    // Container execution
    return await executeCaptureInContainer(captureTaskId, task, engine, pcapFile, localPcapPath);
  } catch (err) {
    markFailed(captureTaskId, err.message);
    return { ok: false, error: err.message };
  }
}

// ── Execute capture in container ────────────────────────────────────────
async function executeCaptureInContainer(captureTaskId, task, engine, pcapFile, localPcapPath) {
  const db = getDb();
  const ws = getWsManager();

  // Build tcpdump arguments
  const tcpdumpArgs = [
    '-i', task.interface,
    '-w', pcapFile,
  ];
  // Add BPF filter if specified
  if (task.bpf_filter && task.bpf_filter.trim()) {
    tcpdumpArgs.push(task.bpf_filter.trim());
  }

  // Build container command
  const containerArgs = [
    'run', '--rm',
    '--network', 'host',
    '--privileged',
    '-v', `${CAPTURES_DIR}:/tmp/captures`,
    'rt-capture',
    'tcpdump', ...tcpdumpArgs,
  ];

  const child = spawn(engine, containerArgs, { shell: false });
  let packetCount = 0;
  let stderrOutput = '';

  // Parse tcpdump stderr for packet count updates
  // tcpdump outputs: "N packets captured" periodically to stderr
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (d) => {
    stderrOutput += d;
    // Match packet count: "123 packets captured" or "123 packets received by filter"
    const match = d.match(/(\d+)\s+packets?\s+(captured|received)/);
    if (match) {
      packetCount = parseInt(match[1], 10);
      // Update DB packet count
      try {
        db.prepare('UPDATE capture_tasks SET packet_count = ? WHERE capture_task_id = ?')
          .run(packetCount, captureTaskId);
      } catch {}
      // WebSocket: push packet count update
      if (ws) ws.broadcast('capture:packet', { captureTaskId, packetCount });
    }
  });

  // Set up duration timer for timed captures
  let durationTimer = null;
  if (task.capture_type === 'timed' && task.duration_sec > 0) {
    durationTimer = setTimeout(() => {
      if (child.killed) return;
      child.kill('SIGINT');
    }, task.duration_sec * 1000);
  }

  // Store in running map
  runningCaptures.set(captureTaskId, { child, timer: durationTimer, manuallyStopped: false });

  // WebSocket: notify capture started
  if (ws) ws.broadcast('capture:started', { captureTaskId, interface: task.interface });

  // Wait for process to exit
  return new Promise((resolve) => {
    child.on('close', (code) => {
      if (durationTimer) clearTimeout(durationTimer);
      const entry = runningCaptures.get(captureTaskId);
      const wasManualStop = entry ? entry.manuallyStopped : false;
      runningCaptures.delete(captureTaskId);

      // Get file size if PCAP exists
      let fileSize = 0;
      try {
        if (existsSync(localPcapPath)) {
          const stat = statSync(localPcapPath);
          fileSize = stat.size;
        }
      } catch {}

      // Final packet count from stderr
      const finalMatch = stderrOutput.match(/(\d+)\s+packets?\s+captured/);
      if (finalMatch) packetCount = parseInt(finalMatch[1], 10);

      const stoppedAt = new Date().toISOString();
      let status, errorMessage = null;
      if (wasManualStop) {
        status = 'STOPPED';
      } else {
        status = code === 0 || packetCount > 0 ? 'COMPLETED' : 'FAILED';
        if (status === 'FAILED') {
          // Capture useful error context from stderr (e.g. "Unable to find image")
          errorMessage = stderrOutput.trim().split('\n').pop() || `tcpdump exited with code ${code}`;
        }
      }

      db.prepare(`UPDATE capture_tasks SET status = ?, stopped_at = ?, pcap_path = ?, packet_count = ?, file_size_bytes = ?, error_message = ? WHERE capture_task_id = ?`)
        .run(status, stoppedAt, localPcapPath, packetCount, fileSize, errorMessage, captureTaskId);

      // WebSocket: notify capture completed
      if (ws) ws.broadcast('capture:completed', {
        captureTaskId, status, packetCount, fileSize, error: errorMessage,
      });

      resolve({ ok: true, captureTaskId, status, packetCount, fileSize });
    });

    child.on('error', (err) => {
      if (durationTimer) clearTimeout(durationTimer);
      runningCaptures.delete(captureTaskId);
      markFailed(captureTaskId, err.message);
      resolve({ ok: false, error: err.message });
    });
  });
}

// ── Execute capture directly on host (fallback) ────────────────────────
async function executeCaptureDirect(captureTaskId, task, pcapFile, localPcapPath) {
  const db = getDb();
  const ws = getWsManager();

  const tcpdumpArgs = ['-i', task.interface, '-w', localPcapPath];
  if (task.bpf_filter && task.bpf_filter.trim()) {
    tcpdumpArgs.push(task.bpf_filter.trim());
  }

  const child = spawn('tcpdump', tcpdumpArgs, { shell: false });
  let packetCount = 0;
  let stderrOutput = '';

  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (d) => {
    stderrOutput += d;
    const match = d.match(/(\d+)\s+packets?\s+(captured|received)/);
    if (match) {
      packetCount = parseInt(match[1], 10);
      try {
        db.prepare('UPDATE capture_tasks SET packet_count = ? WHERE capture_task_id = ?')
          .run(packetCount, captureTaskId);
      } catch {}
      if (ws) ws.broadcast('capture:packet', { captureTaskId, packetCount });
    }
  });

  let durationTimer = null;
  if (task.capture_type === 'timed' && task.duration_sec > 0) {
    durationTimer = setTimeout(() => {
      if (child.killed) return;
      child.kill('SIGINT');
    }, task.duration_sec * 1000);
  }

  runningCaptures.set(captureTaskId, { child, timer: durationTimer, manuallyStopped: false });

  if (ws) ws.broadcast('capture:started', { captureTaskId, interface: task.interface });

  return new Promise((resolve) => {
    child.on('close', (code) => {
      if (durationTimer) clearTimeout(durationTimer);
      const entry = runningCaptures.get(captureTaskId);
      const wasManualStop = entry ? entry.manuallyStopped : false;
      runningCaptures.delete(captureTaskId);

      let fileSize = 0;
      try {
        if (existsSync(localPcapPath)) {
          fileSize = statSync(localPcapPath).size;
        }
      } catch {}

      const finalMatch = stderrOutput.match(/(\d+)\s+packets?\s+captured/);
      if (finalMatch) packetCount = parseInt(finalMatch[1], 10);

      const stoppedAt = new Date().toISOString();
      let status;
      if (wasManualStop) {
        status = 'STOPPED';
      } else {
        status = code === 0 || packetCount > 0 ? 'COMPLETED' : 'FAILED';
      }

      db.prepare(`UPDATE capture_tasks SET status = ?, stopped_at = ?, pcap_path = ?, packet_count = ?, file_size_bytes = ? WHERE capture_task_id = ?`)
        .run(status, stoppedAt, localPcapPath, packetCount, fileSize, captureTaskId);

      if (ws) ws.broadcast('capture:completed', {
        captureTaskId, status, packetCount, fileSize,
      });

      resolve({ ok: true, captureTaskId, status, packetCount, fileSize });
    });

    child.on('error', (err) => {
      if (durationTimer) clearTimeout(durationTimer);
      runningCaptures.delete(captureTaskId);
      markFailed(captureTaskId, err.message);
      resolve({ ok: false, error: err.message });
    });
  });
}

// ── Stop a running capture ──────────────────────────────────────────────
export function stopCapture(captureTaskId) {
  const entry = runningCaptures.get(captureTaskId);
  if (!entry) return { ok: false, error: 'No running capture found for this task' };

  const { child, timer } = entry;
  if (timer) clearTimeout(timer);

  // Mark as manually stopped so close handler sets status = STOPPED
  entry.manuallyStopped = true;

  // Send SIGINT to gracefully stop tcpdump (flushes PCAP)
  child.kill('SIGINT');
  return { ok: true, captureTaskId, message: 'Stop signal sent' };
}

// ── Check if a capture is running ───────────────────────────────────────
export function isCaptureRunning(captureTaskId) {
  return runningCaptures.has(captureTaskId);
}

// ── Get all running capture IDs ─────────────────────────────────────────
export function getRunningCaptureIds() {
  return [...runningCaptures.keys()];
}

// ── Helper: mark capture as FAILED ─────────────────────────────────────
function markFailed(captureTaskId, errorMessage) {
  const db = getDb();
  const ws = getWsManager();
  const stoppedAt = new Date().toISOString();
  db.prepare("UPDATE capture_tasks SET status = 'FAILED', stopped_at = ?, error_message = ? WHERE capture_task_id = ?")
    .run(stoppedAt, errorMessage, captureTaskId);
  if (ws) ws.broadcast('capture:completed', { captureTaskId, status: 'FAILED', error: errorMessage });
}
