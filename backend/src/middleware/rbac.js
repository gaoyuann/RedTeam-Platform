// ── RBAC Middleware ─────────────────────────────────────────────────────
import { RBAC } from '../config/rbac.js';

/**
 * Factory: returns middleware that checks role-based access for a route prefix.
 * Read operations (GET/HEAD/OPTIONS) check `rules.read`.
 * Write operations (POST/PUT/PATCH/DELETE) check `rules.write`.
 *
 * @param {string} prefix - Route prefix key in RBAC config (e.g. 'scan-tasks')
 */
export function rbacGuard(prefix) {
  const rules = RBAC[prefix];

  return (req, res, next) => {
    // If no RBAC rule defined for this prefix, deny by default
    if (!rules) {
      if (!req.user || req.user.role !== 'admin') {
        return res.status(403).json({
          status: 'error',
          error: { message: '没有权限', code: 'FORBIDDEN' },
        });
      }
      return next();
    }

    const isWrite = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
    const allowedRoles = isWrite ? rules.write : rules.read;

    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'error',
        error: { message: '没有权限执行此操作', code: 'FORBIDDEN' },
      });
    }
    next();
  };
}
