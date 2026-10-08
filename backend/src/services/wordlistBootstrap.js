import { existsSync, mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';

const DEFAULTS = {
  'common_passwords.txt': ['password', 'admin', '123456', 'admin123', 'root', 'test', 'guest', 'user', 'letmein', 'welcome', '12345678', 'qwerty', 'password123', 'changeme'],
  'common_users.txt': ['admin', 'root', 'test', 'guest', 'user'],
  'common_dirs.txt': ['docs', 'hackable', 'vulnerabilities', 'config', 'security.php', 'login.php', 'index.php'],
};

export function ensureBuiltinWordlists(projectRoot) {
  const directory = join(projectRoot, 'data', 'wordlists');
  mkdirSync(directory, { recursive: true });
  const created = [];
  for (const [name, entries] of Object.entries(DEFAULTS)) {
    const path = join(directory, name);
    if (existsSync(path)) continue;
    try {
      writeFileSync(path, entries.join('\n') + '\n', { flag: 'wx', mode: 0o644 });
      created.push(name);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
  }
  return created;
}
