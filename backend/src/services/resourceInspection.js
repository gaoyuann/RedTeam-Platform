import { accessSync, constants, statSync } from 'fs';
import { delimiter, isAbsolute, join } from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

export function isReadableFile(path) {
  try {
    accessSync(path, constants.R_OK);
    return statSync(path).isFile() && statSync(path).size > 0;
  } catch {
    return false;
  }
}

export async function inspectRuntimeResources({ engine, toolIds, imageMap, binMap,
  inspect = execFileAsync, searchPath = process.env.PATH || '' }) {
  const missing = [];
  if (engine === 'docker' || engine === 'podman') {
    const images = new Set(toolIds.map(tool => imageMap[tool]).filter(Boolean));
    for (const image of images) {
      try {
        await inspect(engine, ['image', 'inspect', image], { timeout: 5000, maxBuffer: 1024 * 1024 });
      } catch {
        missing.push(`Image unavailable: ${image}`);
      }
    }
  } else if (engine === 'host') {
    for (const tool of new Set(toolIds)) {
      const binary = binMap[tool] || tool;
      const candidates = isAbsolute(binary) ? [binary] : searchPath.split(delimiter).map(directory => join(directory, binary));
      const available = candidates.some(path => {
        try {
          accessSync(path, constants.X_OK);
          return statSync(path).isFile();
        } catch {
          return false;
        }
      });
      if (!available) missing.push(`Executable unavailable: ${binary}`);
    }
  } else {
    missing.push('No supported execution environment available');
  }
  return { passed: missing.length === 0, missing };
}

export function inspectWordlistFiles(steps, context, projectRoot, engine = 'docker') {
  const required = new Set();
  const issues = [];
  for (const step of steps) {
    let args;
    try {
      args = JSON.parse(step.args_template || '[]');
      if (!Array.isArray(args)) throw new Error('Arguments must be an array');
    } catch {
      issues.push(`Invalid argument template (step ${step.step_index})`);
      continue;
    }
    for (const arg of args) {
      if (typeof arg !== 'string') continue;
      const value = arg.replace(/\{\{(wordlist_[a-z_]+)\}\}/g, (token, variable) => {
        if (typeof context[variable] === 'string' && context[variable].trim()) return context[variable];
        issues.push(`Missing resource variable: ${variable} (step ${step.step_index})`);
        return token;
      });
      for (const match of value.matchAll(/\/usr\/share\/wordlists\/[^\s'";|&<>]+/g)) {
        const relative = match[0].slice('/usr/share/wordlists/'.length);
        if (relative.split('/').includes('..')) {
          issues.push(`Invalid resource path (step ${step.step_index})`);
        } else {
          required.add(engine === 'host' ? match[0] : join(projectRoot, 'data', 'wordlists', relative));
        }
      }
    }
  }
  for (const path of required) {
    if (!isReadableFile(path)) issues.push(`Resource missing, empty or unreadable: ${path}`);
  }
  return { passed: issues.length === 0, issues, required: [...required] };
}
