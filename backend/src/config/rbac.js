// ── RBAC Configuration ─────────────────────────────────────────────────
// Maps route prefixes to allowed roles for read and write operations.
//
// Role mapping to terminals (from CS架构改造方案.md):
//   admin    → 测试控制端 (all 7 modules)
//   teacher  → 测试控制端 (all 7 modules, teaching subset)
//   operator → 攻击测试端 (modules 3+4+5: topology, scan, attack)
//   viewer   → Read-only observer
//   student  → Learner (limited access)

export const RBAC = {
  'config':        { read: ['admin', 'teacher'],                       write: ['admin'] },
  'playbooks':     { read: ['admin', 'teacher', 'operator', 'viewer', 'student'], write: ['admin', 'teacher'] },
  'topology':      { read: ['admin', 'teacher', 'operator', 'viewer', 'student'], write: ['admin', 'teacher', 'operator', 'student'] },
  'scan-tasks':    { read: ['admin', 'teacher', 'operator', 'viewer', 'student'], write: ['admin', 'teacher', 'operator', 'student'] },
  'runs':          { read: ['admin', 'teacher', 'operator', 'viewer', 'student'], write: ['admin', 'teacher', 'operator', 'student'] },
  'tools':         { read: ['admin', 'teacher', 'operator', 'student'], write: ['admin', 'teacher', 'operator', 'student'] },
  'reports':       { read: ['admin', 'teacher', 'operator', 'viewer', 'student'], write: ['admin', 'teacher', 'student'] },
  'classes':       { read: ['admin', 'teacher', 'student'],           write: ['admin', 'teacher'] },
  'assignments':   { read: ['admin', 'teacher', 'student'],           write: ['admin', 'teacher'] },
  'submissions':   { read: ['admin', 'teacher', 'student'],           write: ['admin', 'teacher', 'student'] },
  'memberships':   { read: ['admin', 'teacher'],                      write: ['admin', 'teacher'] },
  'audit':         { read: ['admin', 'teacher'],                      write: [] },
  'kg':            { read: ['admin', 'teacher', 'operator', 'viewer', 'student'], write: [] },
  'payloads':      { read: ['admin', 'teacher', 'operator', 'viewer', 'student'], write: ['admin', 'teacher', 'operator', 'student'] },
  'users':         { read: ['admin'],                                  write: ['admin'] },
};
