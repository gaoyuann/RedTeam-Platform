import { accessSync, constants, statSync } from 'fs';
import { delimiter, isAbsolute, join } from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
import { normalizeToolArgs, inspectToolWordlists } from '../tools/toolContracts.js';

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
    args = args.map(arg => typeof arg === 'string' ? arg.replace(/\{\{(wordlist_[a-z_]+)\}\}/g, (token, variable) => {
        if (typeof context[variable] === 'string' && context[variable].trim()) return context[variable];
        issues.push(`Missing resource variable: ${variable} (step ${step.step_index})`);
        return token;
      }) : arg);
    try {
      const normalized = normalizeToolArgs(step.tool_id, args, { projectRoot, engine });
      const inspection = inspectToolWordlists(step.tool_id, normalized, projectRoot, engine);
      inspection.required.forEach(path => required.add(path));
      issues.push(...inspection.issues.map(issue => `${issue} (step ${step.step_index})`));
    } catch (error) {
      issues.push(`${error.message} (step ${step.step_index})`);
    }
  }
  for (const path of required) {
    if (!isReadableFile(path)) issues.push(`Resource missing, empty or unreadable: ${path}`);
  }
  return { passed: issues.length === 0, issues, required: [...required] };
}
