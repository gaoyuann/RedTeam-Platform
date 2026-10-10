import { isIP } from 'node:net';

function address(value) {
  const normalized = String(value || '').replace(/^::ffff:/i, '');
  return isIP(normalized) ? normalized : '';
}

// Record the socket peer, not client-controlled forwarded headers or body data.
export function captureTopologyOrigin(req) {
  return { sourceAddress: address(req.socket?.remoteAddress),
    serverAddress: address(req.socket?.localAddress),
    capturedAt: new Date().toISOString(), transport: 'http-request' };
}

export function readTopologyOrigin(config) {
  try {
    const parsed = typeof config === 'string' ? JSON.parse(config) : config;
    const origin = parsed?.topology_origin;
    if (origin?.transport !== 'http-request') return null;
    return { ...origin, sourceAddress: address(origin.sourceAddress), serverAddress: address(origin.serverAddress) };
  } catch { return null; }
}

export function isLoopbackAddress(value) {
  const ip = address(value);
  return ip === '::1' || ip.startsWith('127.');
}
