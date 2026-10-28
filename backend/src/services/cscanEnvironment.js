import {readFileSync} from 'node:fs';

// Treat configuration as data, never as shell commands. Existing environment wins.
export function loadCscanEnvironment(env = process.env) {
  const path = env.REDTEAM_CSCAN_ENV_FILE;
  if (!path) return false;
  let text;
  try { text = readFileSync(path, 'utf8'); }
  catch { throw new Error('CScan 配置文件无法读取'); }
  const pending = {};
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const match = line.match(/^\s*(?:export\s+)?(CSCAN_[A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!match) throw new Error('CScan 配置文件格式无效（仅支持 CSCAN_* 配置）');
    let value = match[2];
    if (value.startsWith('"') || value.startsWith("'")) {
      if (value.at(-1) !== value[0] || value.length < 2) throw new Error('CScan 配置文件引号不完整');
      value = value.slice(1, -1);
    }
    pending[match[1]] = value;
  }
  for (const [key, value] of Object.entries(pending)) if (env[key] === undefined) env[key] = value;
  return true;
}
