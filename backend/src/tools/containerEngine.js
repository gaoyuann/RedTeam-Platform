import { exec as execCb } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(execCb);

let _engine = null;
let _detectedAt = 0;
const CACHE_TTL_MS = 60_000;

export async function detectEngine() {
  const now = Date.now();
  if (_engine && (now - _detectedAt) < CACHE_TTL_MS) return _engine;

  // 尝试 Podman（国产 OS 优先）
  try {
    await execAsync('podman version', { timeout: 5000 });
    _engine = 'podman';
    _detectedAt = now;
    console.log('[Container] Detected engine: podman');
    return _engine;
  } catch {}

  // 尝试 Docker
  try {
    await execAsync('docker version', { timeout: 5000 });
    _engine = 'docker';
    _detectedAt = now;
    console.log('[Container] Detected engine: docker');
    return _engine;
  } catch {}

  // Fallback 到宿主机
  _engine = 'host';
  _detectedAt = now;
  console.log('[Container] No container engine found, using host execution');
  return _engine;
}

export async function getEngine() {
  return detectEngine();
}

export function resetCache() {
  _engine = null;
  _detectedAt = 0;
}
