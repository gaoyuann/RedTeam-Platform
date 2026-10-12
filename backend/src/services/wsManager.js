// ── WebSocket Manager ──────────────────────────────────────────────────
// Manages WebSocket connections from frontend clients.
// Broadcasts real-time events (scan progress, execution steps, etc.)
import { WebSocketServer } from 'ws';
import { verifyToken } from '../middleware/jwtUtils.js';
import { getDb } from '../db/connection.js';
import { currentActor, getRecord, recordOwner } from '../middleware/recordAccess.js';

const eventResources = {
  scan: ['scan', 'scanTaskId'],
  run: ['run', 'runId'],
  capture: ['capture', 'captureTaskId'],
  campaign: ['campaign', 'campaign_id'],
  phase: ['campaign', 'campaign_id'],
  pipeline: ['pipeline', 'pipeline_id'],
};

class WsManager {
  constructor(server, db) {
    this.db = db;
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
              if (typeof decoded.sub !== 'string' || !decoded.sub.trim() || !['admin', 'user'].includes(decoded.role) || !Number.isFinite(decoded.exp))
                throw new Error('Invalid identity');
              if (!currentActor(this.db, decoded)) throw new Error('Inactive identity');
              this.clients.set(ws, { userId: decoded.sub, role: decoded.role, expiresAt: decoded.exp * 1000 });
              ws.isAlive = true;
              ws.send(JSON.stringify({ event: 'auth:ok', data: { userId: decoded.sub, role: decoded.role } }));
              console.log(`[WS] Authenticated: ${decoded.sub} (${decoded.role})`);
            } catch (err) {
              this.clients.delete(ws);
              ws.isAlive = false;
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
      for (const ws of this.wss.clients) {
        const client = this.clients.get(ws);
        if (!ws.isAlive || client?.expiresAt <= Date.now()) {
          this.clients.delete(ws);
          ws.terminate();
        }
      }
    }, 30000);
  }

  // ── Broadcast methods ──────────────────────────────────────────────────

  /**
   * Send record events to their stored owner and administrators; other events are admin-only.
   * @param {string} event - Event name (e.g. 'scan:progress')
   * @param {object} data  - Event payload
   */
  broadcast(event, data) {
    const resource = eventResources[String(event).split(':')[0]];
    if (!resource) return this.broadcastToRole('admin', event, data);
    const [kind, idField] = resource;
    let record;
    try { record = getRecord(this.db, kind, data?.[idField]); } catch { return; }
    if (!record) return;
    const owner = recordOwner(kind, record);
    this.send(event, data, client => client.role === 'admin' || owner && client.userId === owner);
  }

  send(event, data, accepts) {
    if (this.clients.size === 0) return;
    const message = JSON.stringify({ event, data, timestamp: Date.now() });
    for (const [socket, client] of this.clients) {
      if (client.expiresAt <= Date.now() || !currentActor(this.db, { sub: client.userId, role: client.role })) {
        this.clients.delete(socket);
        socket.close?.(4001, 'Authentication expired');
        continue;
      }
      if (!client.userId || !['admin', 'user'].includes(client.role) || socket.readyState !== 1 || !accepts(client)) continue;
      try { socket.send(message); } catch { this.clients.delete(socket); }
    }
  }

  /**
   * Broadcast to clients with a specific role.
   * @param {string} role
   * @param {string} event
   * @param {object} data
   */
  broadcastToRole(role, event, data) {
    this.send(event, data, client => client.role === role);
  }

  /**
   * Broadcast to a specific user.
   * @param {string} userId
   * @param {string} event
   * @param {object} data
   */
  broadcastToUser(userId, event, data) {
    if (userId) this.send(event, data, client => client.userId === userId);
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
export function initWebSocket(server, db = getDb()) {
  wsManager = new WsManager(server, db);
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
