import { resolve, posix, relative, isAbsolute } from 'path';
import { accessSync, constants, statSync } from 'fs';

const WORDLIST_PREFIXES = ['/usr/share/wordlists/', 'config/wordlists/', 'data/wordlists/'];
const URL_FLAGS = {
  gobuster: ['-u', '--url'], ffuf: ['-u'], arjun: ['-u', '--url'],
  sqlmap: ['-u', '--url'], nuclei: ['-u', '-target'], httpx: ['-u'],
};
const FILE_FLAGS = {
  hydra: ['-P', '-L', '-C'], gobuster: ['-w', '--wordlist'],
  ffuf: ['-w'], john: ['--wordlist'], 'web-brute': ['--wordlist'],
};

export function normalizeToolArgs(toolId, args, { projectRoot, engine = 'docker', scheme = 'http' } = {}) {
  if (!Array.isArray(args)) throw new Error('Tool arguments must be an array');
  function normalizeWordlist(value) {
    const prefix = WORDLIST_PREFIXES.find(candidate => value.startsWith(candidate));
    if (!prefix) return value;
    const relative = value.slice(prefix.length);
    if (!relative || relative.split('/').includes('..') || relative.includes('\\')) {
      throw new Error(`Invalid wordlist path: ${value}`);
    }
    return engine === 'host' ? resolve(projectRoot, 'data', 'wordlists', relative) : posix.join('/usr/share/wordlists', relative);
  }
  const normalizedArgs = args.map((arg, index) => {
    if (typeof arg !== 'string') throw new Error('Tool arguments must be strings');
    const fileFlag = FILE_FLAGS[toolId]?.find(flag => arg.startsWith(`${flag}=`));
    if (fileFlag) return `${fileFlag}=${normalizeWordlist(arg.slice(fileFlag.length + 1))}`;
    const normalized = normalizeWordlist(arg);
    if (normalized !== arg) return normalized;
    const isUrl = URL_FLAGS[toolId]?.includes(args[index - 1]) ||
      (toolId === 'whatweb' && !arg.startsWith('-') && index === 0) ||
      (toolId === 'curl' && index === args.length - 1 && !arg.startsWith('-'));
    if (isUrl && !/^https?:\/\//i.test(arg)) return `${scheme}://${arg}`;
    return arg;
  });
  if (['nmap', 'hydra'].includes(toolId)) {
    for (let index = 0; index < normalizedArgs.length; index++) {
      if (!/^https?:\/\//i.test(normalizedArgs[index])) continue;
      const targetUrl = new URL(normalizedArgs[index]);
      normalizedArgs[index] = targetUrl.hostname.replace(/^\[|\]$/g, '');
      const port = targetUrl.port || (targetUrl.protocol === 'https:' ? '443' : '80');
      const flag = toolId === 'nmap' ? '-p' : '-s';
      const portIndex = normalizedArgs.indexOf(flag);
      if (portIndex < 0) normalizedArgs.push(flag, port);
      else if (toolId === 'nmap' && !normalizedArgs[portIndex + 1].split(',').includes(port)) normalizedArgs[portIndex + 1] += `,${port}`;
      if (toolId === 'hydra' && targetUrl.protocol === 'https:' && !normalizedArgs.includes('-S')) normalizedArgs.push('-S');
    }
  }
  return normalizedArgs;
}

export function inspectToolWordlists(toolId, args, projectRoot, engine = 'docker') {
  const wordlistRoot = resolve(projectRoot, 'data', 'wordlists');
  const required = new Set();
  const issues = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (FILE_FLAGS[toolId]?.includes(arg) && (!args[index + 1] || args[index + 1].startsWith('-'))) {
      issues.push(`Missing wordlist value for ${arg}`);
      continue;
    }
    let value = FILE_FLAGS[toolId]?.includes(args[index - 1]) ? arg : null;
    if (!value && FILE_FLAGS[toolId]?.some(flag => arg.startsWith(`${flag}=`))) value = arg.slice(arg.indexOf('=') + 1);
    if (!value && arg.startsWith('/usr/share/wordlists/')) value = arg;
    if (!value) continue;
    if (toolId === 'ffuf') value = value.split(':')[0];
    if (value.startsWith('/usr/share/wordlists/')) {
      const relative = value.slice('/usr/share/wordlists/'.length);
      if (relative.split('/').includes('..') || relative.includes('\\')) {
        issues.push(`Invalid wordlist path: ${value}`);
        continue;
      }
      value = resolve(wordlistRoot, relative);
    } else {
      const absoluteValue = resolve(value);
      const relativeValue = relative(wordlistRoot, absoluteValue);
      if (engine !== 'host' || !isAbsolute(value) || relativeValue.startsWith('..') || isAbsolute(relativeValue)) {
        issues.push(`Unsupported wordlist path: ${value}`);
        continue;
      }
      value = absoluteValue;
    }
    required.add(value);
    try {
      accessSync(value, constants.R_OK);
      if (!statSync(value).isFile() || statSync(value).size === 0) throw new Error('empty');
    } catch {
      issues.push(`Resource missing, empty or unreadable: ${value}`);
    }
  }
  return { passed: issues.length === 0, issues, required: [...required] };
}

export function classifyToolResult(toolId, result) {
  const output = `${result.stdout || ''}\n${result.stderr || ''}`.replace(/\x1b\[[0-9;]*m/g, '');
  const semanticFailure = toolId === 'arjun' && /is not a valid URL|Skipped .* due to errors/i.test(output) ||
    toolId === 'ffuf' && /Errors:\s*[1-9]\d*/.test(output) ||
    toolId === 'nmap' && /Unable to split netmask|No targets were specified|Failed to resolve/i.test(output) ||
    ['nikto', 'sqlmap', 'httpx'].includes(toolId) && /unable to connect|connection (?:refused|timed out)|no web server found|\[CRITICAL\]/i.test(output);
  const success = result.exitCode === 0 && !result.timedOut && !result.aborted && !result.outputLimitExceeded && !semanticFailure;
  return { ...result, success, error: success ? null : result.error ||
    (result.aborted ? '操作员手动中止' : result.timedOut ? 'Tool timed out' :
      result.outputLimitExceeded ? 'Tool output limit exceeded' : semanticFailure ? 'Tool rejected input or requests failed' : `Tool exited with code ${result.exitCode}`) };
}

export function redactToolArgs(args, toolId = '') {
  const sensitiveFlags = new Set(['--cookie', '-b', '--data', '--data-raw', '--data-urlencode', '-d', '--password', '--token', '-H', '--header']);
  if (['hydra', 'ssh-exec', 'evil-winrm', 'netexec', 'web-brute'].includes(toolId)) sensitiveFlags.add('-p');
  if (toolId === 'curl') sensitiveFlags.add('-u');
  return args.map((arg, index) => {
    if (sensitiveFlags.has(args[index - 1])) return '[REDACTED]';
    const value = String(arg);
    const inlineFlag = [...sensitiveFlags].find(flag => value.startsWith(`${flag}=`));
    if (inlineFlag) return `${inlineFlag}=[REDACTED]`;
    return value.replace(/(PHPSESSID=|password=|token=|Authorization:\s*Bearer\s+)[^\s;&]+/gi, '$1[REDACTED]');
  });
}
