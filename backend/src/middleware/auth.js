// ── Authentication & Authorization Middleware ───────────────────────────
import { verifyToken } from './jwtUtils.js';

/**
 * Express middleware: require a valid JWT in the Authorization header.
 * On success, attaches decoded token payload to `req.user`.
 */
export function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      status: 'error',
      error: { message: '缺少认证令牌', code: 'AUTH_REQUIRED' },
    });
  }

  const token = authHeader.split(' ')[1];
  try {
    req.user = verifyToken(token);
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        status: 'error',
        error: { message: '令牌已过期，请重新登录', code: 'TOKEN_EXPIRED' },
      });
    }
    return res.status(401).json({
      status: 'error',
      error: { message: '无效的认证令牌', code: 'INVALID_TOKEN' },
    });
  }
}

/**
 * Factory: returns middleware that requires the user to have one of the given roles.
 * @param {...string} roles - Allowed roles
 */
export function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        status: 'error',
        error: { message: '未认证', code: 'AUTH_REQUIRED' },
      });
    }
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: 'error',
        error: { message: '没有权限执行此操作', code: 'FORBIDDEN' },
      });
    }
    next();
  };
}
