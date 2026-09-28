// ── RBAC Configuration ─────────────────────────────────────────────────
// Maps route prefixes to allowed roles for read and write operations.
//
// Roles:
//   admin → 系统管理员 (full access to all modules + user/permission management)
//   user  → 普通用户 (operational access: scan, attack, reports; no system management)

export const RBAC = {
  'config':        { read: ['admin', 'user'], write: ['admin'] },
  'playbooks':     { read: ['admin', 'user'], write: ['admin'] },
  'topology':      { read: ['admin', 'user'], write: ['admin', 'user'] },
  'scan-tasks':    { read: ['admin', 'user'], write: ['admin', 'user'] },
  'runs':          { read: ['admin', 'user'], write: ['admin', 'user'] },
  'tools':         { read: ['admin', 'user'], write: ['admin', 'user'] },
  'reports':       { read: ['admin', 'user'], write: ['admin', 'user'] },
  'classes':       { read: ['admin', 'user'], write: ['admin'] },
  'assignments':   { read: ['admin', 'user'], write: ['admin'] },
  'submissions':   { read: ['admin', 'user'], write: ['admin', 'user'] },
  'memberships':   { read: ['admin', 'user'], write: ['admin'] },
  'audit':         { read: ['admin', 'user'], write: [] },
  'kg':            { read: ['admin', 'user'], write: [] },
  'payloads':      { read: ['admin', 'user'], write: ['admin', 'user'] },
  'users':         { read: ['admin'],         write: ['admin'] },
  'campaign':      { read: ['admin', 'user'], write: ['admin', 'user'] },
  'capture-tasks': { read: ['admin', 'user'], write: ['admin', 'user'] },
  'labs':          { read: ['admin', 'user'], write: ['admin'] },
  'pipelines':     { read: ['admin', 'user'], write: ['admin', 'user'] },
};
