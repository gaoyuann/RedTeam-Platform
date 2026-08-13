// ── WebSocket Manager ──────────────────────────────────────────────────
// Manages WebSocket connections from frontend clients.
// Broadcasts real-time events (scan progress, execution steps, etc.)
import { WebSocketServer } from 'ws';
import { verifyToken } from '../middleware/jwtUtils.js';

class WsManager {
  constructor(server) {
    this.wss = new WebSocketServer({ server, path: '/ws' });
    this.clients = new Map(); // ws → { userId, role }

    this.wss.on('connection', (ws, req) => {
      console.log('[WS] New connection');

      // Client must send an auth message first
      ws.isAlive = false;

      ws.on('message', (raw) => {
        try {
          const msg = JSON.parse(raw);

          // Auth message: { type: 'auth', token: '...' }
          if (msg.type === 'auth' && msg.token) {
            try {
              const decoded = verifyToken(msg.token);
              this.clients.set(ws, { userId: decoded.sub, role: decoded.role });
              ws.isAlive = true;
              ws.send(JSON.stringify({ event: 'auth:ok', data: { userId: decoded.sub, role: decoded.role } }));
              console.log(`[WS] Authenticated: ${decoded.sub} (${decoded.role})`);
            } catch (err) {
              ws.send(JSON.stringify({ event: 'auth:error', data: { message: 'Invalid token' } }));
              ws.close(4001, 'Authentication failed');
            }
            return;
          }

          // Ping/pong for keepalive
          if (msg.type === 'ping') {
            ws.send(JSON.stringify({ event: 'pong' }));
            return;
          }
        } catch (err) {
          // Ignore malformed messages
        }
      });

      ws.on('close', () => {
        const client = this.clients.get(ws);
        if (client) {
          console.log(`[WS] Disconnected: ${client.userId} (${client.role})`);
        }
        this.clients.delete(ws);
      });

      ws.on('error', () => {
        this.clients.delete(ws);
      });
    });

    // Periodic cleanup: terminate unauthenticated connections after 10s
    this._cleanupInterval = setInterval(() => {
      for (const [ws] of this.wss.clients) {
        if (!ws.isAlive) {
          ws.terminate();
        }
      }
    }, 30000);
  }

  // ── Broadcast methods ──────────────────────────────────────────────────

  /**
   * Broadcast an event to all connected and authenticated clients.
   * @param {string} event - Event name (e.g. 'scan:progress')
   * @param {object} data  - Event payload
   */
  broadcast(event, data) {
    if (this.clients.size === 0) return;
    const msg = JSON.stringify({ event, data, timestamp: Date.now() });
    for (const [ws] of this.clients) {
      if (ws.readyState === 1) { // OPEN
        ws.send(msg);
      }
    }
  }

  /**
   * Broadcast to clients with a specific role.
   * @param {string} role
   * @param {string} event
   * @param {object} data
   */
  broadcastToRole(role, event, data) {
    if (this.clients.size === 0) return;
    const msg = JSON.stringify({ event, data, timestamp: Date.now() });
    for (const [ws, client] of this.clients) {
      if (client.role === role && ws.readyState === 1) {
        ws.send(msg);
      }
    }
  }

  /**
   * Broadcast to a specific user.
   * @param {string} userId
   * @param {string} event
   * @param {object} data
   */
  broadcastToUser(userId, event, data) {
    if (this.clients.size === 0) return;
    const msg = JSON.stringify({ event, data, timestamp: Date.now() });
    for (const [ws, client] of this.clients) {
      if (client.userId === userId && ws.readyState === 1) {
        ws.send(msg);
      }
    }
  }

  /**
   * Get count of connected clients.
   */
  get clientCount() {
    return this.clients.size;
  }

  /**
   * Shutdown the WebSocket server.
   */
  close() {
    clearInterval(this._cleanupInterval);
    this.wss.close();
  }
}

// ── Singleton ──────────────────────────────────────────────────────────
let wsManager = null;

/**
 * Initialize the WebSocket manager on an existing HTTP server.
 * @param {import('http').Server} server
 * @returns {WsManager}
 */
export function initWebSocket(server) {
  wsManager = new WsManager(server);
  return wsManager;
}

/**
 * Get the current WebSocket manager instance.
 * Returns null if not initialized.
 * @returns {WsManager|null}
 */
export function getWsManager() {
  return wsManager;
}
