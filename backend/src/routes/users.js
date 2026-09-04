import { Router } from 'express';
import { generateAccessToken, generateRefreshToken, refreshTokenExpiry,
         comparePassword, hashPassword, needsPasswordUpgrade } from '../middleware/jwtUtils.js';
import { authenticate, requireRole } from '../middleware/auth.js';
import { RBAC as DEFAULT_RBAC } from '../config/rbac.js';

// ── RBAC config helpers (DB-driven with fallback) ────────────────────────

/**
 * Load RBAC config: try DB first, fall back to hardcoded defaults.
 * DB stores one row per (category='rbac', config_key=<prefix>) with
 * config_value = JSON { read: [...], write: [...] }.
 */
function loadRBACFromDB(db) {
  try {
    const rows = db.prepare(
      "SELECT config_key, config_value FROM system_config WHERE category = 'rbac'"
    ).all();
    if (rows.length === 0) return null;
    const rbac = {};
    for (const row of rows) {
      try {
        rbac[row.config_key] = JSON.parse(row.config_value);
      } catch { /* skip malformed */ }
    }
    return Object.keys(rbac).length > 0 ? rbac : null;
  } catch {
    return null;
  }
}

export function getEffectiveRBAC(db) {
  return loadRBACFromDB(db) || DEFAULT_RBAC;
}

export default function (db) {
  const router = Router();

  // ── Public endpoints (no auth required) ──────────────────────────────

  // Login: validate credentials, return JWT tokens
  router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ status: 'error', error: { message: 'username and password are required' } });
    }

    const user = db.prepare(
      'SELECT id, username, password, role, display_name, is_active FROM users WHERE username = ?'
    ).get(username);

    if (!user) {
      return res.status(401).json({ status: 'error', error: { message: '用户名或密码错误' } });
    }
    if (!user.is_active) {
      return res.status(403).json({ status: 'error', error: { message: '账户已被禁用' } });
    }

    try {
      const passwordValid = await comparePassword(password, user.password);
      if (!passwordValid) {
        return res.status(401).json({ status: 'error', error: { message: '用户名或密码错误' } });
      }

      // Lazy upgrade: migrate plaintext password to bcrypt on first login
      if (needsPasswordUpgrade(user.password)) {
        const hashed = await hashPassword(password);
        db.prepare('UPDATE users SET password = ?, updated_at = datetime(\'now\') WHERE id = ?').run(hashed, user.id);
        console.log(`[Auth] Password upgraded to bcrypt for user: ${user.username}`);
      }

      // Generate tokens
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken();
      const expiresAt = refreshTokenExpiry();

      // Store refresh token in DB
      db.prepare(
        'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
      ).run(user.id, refreshToken, expiresAt.toISOString());

      // Clean up expired refresh tokens for this user
      db.prepare(
        'DELETE FROM refresh_tokens WHERE user_id = ? AND expires_at <= datetime(\'now\')'
      ).run(user.id);

      res.json({
        status: 'ok',
        data: {
          username: user.username,
          role: user.role,
          display_name: user.display_name,
          access_token: accessToken,
          refresh_token: refreshToken,
          expires_in: 7200, // 2 hours in seconds
        },
      });
    } catch (err) {
      console.error('[Auth] Login error:', err.message);
      return res.status(500).json({ status: 'error', error: { message: '登录处理失败' } });
    }
  });

  // Refresh: exchange a valid refresh token for new access + refresh tokens
  router.post('/refresh', (req, res) => {
    const { refresh_token: refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ status: 'error', error: { message: 'refresh_token is required' } });
    }

    const stored = db.prepare(`
      SELECT rt.id, rt.user_id, u.username, u.role, u.is_active
      FROM refresh_tokens rt
      JOIN users u ON u.id = rt.user_id
      WHERE rt.token = ? AND rt.expires_at > datetime('now')
    `).get(refreshToken);

    if (!stored) {
      return res.status(401).json({
        status: 'error',
        error: { message: 'Refresh token 无效或已过期', code: 'INVALID_REFRESH_TOKEN' },
      });
    }

    if (!stored.is_active) {
      return res.status(403).json({ status: 'error', error: { message: '账户已被禁用' } });
    }

    // Token rotation: delete old refresh token, issue new pair
    db.prepare('DELETE FROM refresh_tokens WHERE id = ?').run(stored.id);

    const newAccessToken = generateAccessToken(stored);
    const newRefreshToken = generateRefreshToken();
    const expiresAt = refreshTokenExpiry();

    db.prepare(
      'INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
    ).run(stored.user_id, newRefreshToken, expiresAt.toISOString());

    res.json({
      status: 'ok',
      data: {
        access_token: newAccessToken,
        refresh_token: newRefreshToken,
        expires_in: 7200,
      },
    });
  });

  // ── Protected endpoints (require authentication) ─────────────────────

  // Apply authenticate middleware to all routes below
  router.use(authenticate);

  // Logout: revoke all refresh tokens for the current user
  router.post('/logout', (req, res) => {
    const user = db.prepare('SELECT id FROM users WHERE username = ?').get(req.user.sub);
    if (user) {
      db.prepare('DELETE FROM refresh_tokens WHERE user_id = ?').run(user.id);
    }
    res.json({ status: 'ok', data: { message: '已退出登录' } });
  });

  // List users (admin only)
  router.get('/', requireRole('admin'), (_req, res) => {
    const rows = db.prepare('SELECT id, username, role, display_name, is_active, created_at, updated_at FROM users ORDER BY id').all();
    res.json({ status: 'ok', data: rows, meta: { total: rows.length } });
  });

  // Get single user (admin only)
  router.get('/:username', requireRole('admin'), (req, res) => {
    const row = db.prepare('SELECT id, username, role, display_name, is_active, created_at, updated_at FROM users WHERE username = ?').get(req.params.username);
    if (!row) return res.status(404).json({ status: 'error', error: { message: 'User not found' } });
    res.json({ status: 'ok', data: row });
  });

  // Create user (admin only) — password is hashed with bcrypt
  router.post('/', requireRole('admin'), async (req, res) => {
    const { username, password, role, display_name } = req.body;
    if (!username || !password || !role) {
      return res.status(400).json({ status: 'error', error: { message: 'username, password, role are required' } });
    }
    try {
      const hashedPassword = await hashPassword(password);
      db.prepare('INSERT INTO users (username, password, role, display_name) VALUES (?, ?, ?, ?)').run(username, hashedPassword, role, display_name || username);
      const user = db.prepare('SELECT id, username, role, display_name, is_active, created_at FROM users WHERE username = ?').get(username);
      res.status(201).json({ status: 'ok', data: user });
    } catch (err) {
      if (err.message.includes('UNIQUE')) return res.status(409).json({ status: 'error', error: { message: 'Username already exists' } });
      throw err;
    }
  });

  // Update user (admin only)
  router.put('/:username', requireRole('admin'), async (req, res) => {
    const { password, role, display_name, is_active } = req.body;
    const sets = [], params = [];
    if (password !== undefined) {
      sets.push('password = ?');
      params.push(await hashPassword(password));
    }
    if (role !== undefined) { sets.push('role = ?'); params.push(role); }
    if (display_name !== undefined) { sets.push('display_name = ?'); params.push(display_name); }
    if (is_active !== undefined) { sets.push('is_active = ?'); params.push(is_active); }
    if (sets.length === 0) return res.status(400).json({ status: 'error', error: { message: 'No fields to update' } });
    sets.push("updated_at = datetime('now')");
    params.push(req.params.username);
    const result = db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE username = ?`).run(...params);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'User not found' } });
    const user = db.prepare('SELECT id, username, role, display_name, is_active, created_at, updated_at FROM users WHERE username = ?').get(req.params.username);
    res.json({ status: 'ok', data: user });
  });

  // Delete user (admin only)
  router.delete('/:username', requireRole('admin'), (req, res) => {
    const result = db.prepare('DELETE FROM users WHERE username = ?').run(req.params.username);
    if (result.changes === 0) return res.status(404).json({ status: 'error', error: { message: 'User not found' } });
    res.json({ status: 'ok', data: { deleted: true } });
  });

  // ── Permissions (RBAC) management ──────────────────────────────────────

  // Get current RBAC configuration (admin only)
  router.get('/permissions', requireRole('admin'), (_req, res) => {
    const rbac = getEffectiveRBAC(db);
    res.json({ status: 'ok', data: rbac });
  });

  // Update RBAC configuration (admin only)
  // Body: { permissions: { <prefix>: { read: [...], write: [...] }, ... } }
  router.put('/permissions', requireRole('admin'), (req, res) => {
    const { permissions } = req.body;
    if (!permissions || typeof permissions !== 'object') {
      return res.status(400).json({ status: 'error', error: { message: 'permissions object is required' } });
    }

    // Validate: each key must have read/write arrays of role strings
    const validRoles = ['admin', 'teacher', 'operator', 'student', 'viewer'];
    for (const [prefix, rules] of Object.entries(permissions)) {
      if (!rules || typeof rules !== 'object') {
        return res.status(400).json({ status: 'error', error: { message: `Invalid rules for ${prefix}` } });
      }
      for (const accessType of ['read', 'write']) {
        if (!Array.isArray(rules[accessType])) {
          return res.status(400).json({ status: 'error', error: { message: `${prefix}.${accessType} must be an array` } });
        }
        for (const role of rules[accessType]) {
          if (!validRoles.includes(role)) {
            return res.status(400).json({ status: 'error', error: { message: `Invalid role: ${role}` } });
          }
        }
      }
    }

    // Write each prefix as a separate system_config row (category='rbac')
    const upsert = db.prepare(
      `INSERT INTO system_config (category, config_key, config_value, description)
       VALUES ('rbac', ?, ?, 'RBAC permission rule')
       ON CONFLICT(category, config_key) DO UPDATE SET config_value = excluded.config_value`
    );
    for (const [prefix, rules] of Object.entries(permissions)) {
      upsert.run(prefix, JSON.stringify(rules));
    }

    // Update the in-process RBAC cache so changes take effect immediately
    const merged = { ...DEFAULT_RBAC };
    for (const [prefix, rules] of Object.entries(permissions)) {
      merged[prefix] = rules;
    }
    // Replace the live RBAC object keys
    for (const key of Object.keys(DEFAULT_RBAC)) {
      if (merged[key]) {
        DEFAULT_RBAC[key] = merged[key];
      }
    }

    res.json({ status: 'ok', data: { updated: Object.keys(permissions).length, message: '权限配置已更新' } });
  });

  return router;
}
