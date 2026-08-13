// ── JWT & Password Utilities ───────────────────────────────────────────
import jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';
import bcrypt from 'bcrypt';
import { JWT_SECRET, JWT_EXPIRES_IN, REFRESH_TOKEN_EXPIRES_DAYS, BCRYPT_ROUNDS } from '../config/auth.js';

// ── Access Token ────────────────────────────────────────────────────────

/**
 * Generate a JWT access token.
 * @param {object} user - { username, role }
 * @returns {string} Signed JWT
 */
export function generateAccessToken(user) {
  return jwt.sign(
    { sub: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES_IN }
  );
}

/**
 * Verify a JWT access token.
 * @param {string} token
 * @returns {object} Decoded payload { sub, role, iat, exp }
 * @throws {JsonWebTokenError|TokenExpiredError}
 */
export function verifyToken(token) {
  return jwt.verify(token, JWT_SECRET);
}

// ── Refresh Token (opaque, stored in DB) ────────────────────────────────

/**
 * Generate a cryptographically random refresh token.
 * @returns {string} 96-char hex string
 */
export function generateRefreshToken() {
  return randomBytes(48).toString('hex');
}

/**
 * Calculate the expiry date for a new refresh token.
 * @returns {Date}
 */
export function refreshTokenExpiry() {
  const d = new Date();
  d.setDate(d.getDate() + REFRESH_TOKEN_EXPIRES_DAYS);
  return d;
}

// ── Password Hashing ────────────────────────────────────────────────────

/**
 * Hash a plaintext password with bcrypt.
 * @param {string} password
 * @returns {Promise<string>} bcrypt hash
 */
export async function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_ROUNDS);
}

/**
 * Compare a plaintext password against a stored hash.
 * Supports both bcrypt hashes and legacy plaintext passwords
 * for backward-compatible migration.
 * @param {string} password - User-supplied plaintext
 * @param {string} hash     - Stored hash (bcrypt) or plaintext (legacy)
 * @returns {Promise<boolean>}
 */
export async function comparePassword(password, hash) {
  // Legacy: plaintext comparison for pre-migration data
  if (!hash || !hash.startsWith('$2')) {
    return password === hash;
  }
  return bcrypt.compare(password, hash);
}

/**
 * Check if a stored password hash needs upgrading from plaintext to bcrypt.
 * @param {string} hash
 * @returns {boolean}
 */
export function needsPasswordUpgrade(hash) {
  return !hash || !hash.startsWith('$2');
}
