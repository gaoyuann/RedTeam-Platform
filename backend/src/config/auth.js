// ── Auth Configuration ─────────────────────────────────────────────────
// JWT and password hashing constants.
// In production, ALWAYS set JWT_SECRET via environment variable.

export const JWT_SECRET = process.env.JWT_SECRET || 'redteam-dev-secret-change-in-prod';
export const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '2h';
export const REFRESH_TOKEN_EXPIRES_DAYS = 7;
export const BCRYPT_ROUNDS = 10;

// Warn if using default secret in non-dev environments
if (!process.env.JWT_SECRET && process.env.NODE_ENV !== 'development') {
  console.warn('[Auth] WARNING: JWT_SECRET not set. Using insecure default. Set JWT_SECRET env var in production!');
}
