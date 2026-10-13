import { resolve, posix, relative, isAbsolute } from 'path';
import { accessSync, constants, statSync } from 'fs';

const WORDLIST_PREFIXES = ['/usr/share/wordlists/', 'config/wordlists/', 'data/wordlists/'];
const URL_FLAGS = {
  gobuster: ['-u', '--url'], ffuf: ['-u'], arjun: ['-u', '--url'],
  sqlmap: ['-u', '--url'], nuclei: ['-u', '-target'], httpx: ['-u'],
};
const FILE_FLAGS = {
  hydra: ['-P', '-L', '-C'], gobuster: ['-w', '--wordlist'],
  ffuf: ['-w'], john: ['--wordlist'], 'web-brute': ['-P', '-L', '--users', '--passlist', '--wordlist'],
};
const GOBUSTER_SUBCOMMANDS = new Set(['dir', 'vhost', 'dns', 'fuzz', 'tftp', 's3', 'gcs']);
const HYDRA_SERVICE_ALIASES = new Map([
  ['http-form-post', 'http-post-form'],
  ['http-form-get', 'http-get-form'],
]);
const HYDRA_SERVICES = new Set([
  'http-post-form', 'http-get-form', 'http-post', 'http-get',
  'https-post-form', 'https-get-form', 'https-post', 'https-get',
  'ftp', 'ssh', 'rdp', 'smb', 'mysql', 'postgres', 'redis', 'telnet',
]);

function normalizeHydraServiceAliases(args) {
  return args.map(argument => HYDRA_SERVICE_ALIASES.get(String(argument).toLowerCase()) || argument);
}

export function validateToolArgs(toolId, args) {
  if (!Array.isArray(args)) return ['Tool arguments must be an array'];
  if (args.some(argument => typeof argument !== 'string')) return ['Tool arguments must be strings'];
  const issues = [];
  if (toolId === 'gobuster') {
    if (args[0] === '-m') {
      issues.push('Gobuster legacy -m mode is unsupported; use a subcommand such as "dir"');
    } else if (!GOBUSTER_SUBCOMMANDS.has(args[0])) {
      issues.push(`Gobuster requires a subcommand (${[...GOBUSTER_SUBCOMMANDS].join(', ')})`);
    }
  }
  if (toolId === 'hydra') {
    const normalized = normalizeHydraServiceAliases(args);
    const serviceIndex = normalized.findIndex(argument => HYDRA_SERVICES.has(String(argument).toLowerCase()));
    if (serviceIndex < 0) {
      issues.push('Hydra service module is missing or unsupported');
    } else {
      const targetIndex = serviceIndex - 1;
      if (targetIndex < 0 || String(normalized[targetIndex]).startsWith('-')) {
        issues.push('Hydra target must immediately precede the service module');
      }
      for (const flag of ['-s', '-S']) {
        const flagIndex = normalized.indexOf(flag);
        if (flagIndex > serviceIndex) issues.push(`Hydra ${flag} must appear before the service module`);
      }
    }
  }
  return issues;
}

export function normalizeToolArgs(toolId, args, { projectRoot, engine = 'docker', scheme = 'http', target } = {}) {
  if (!Array.isArray(args)) throw new Error('Tool arguments must be an array');
  if (toolId === 'web-brute' && args[0] === '/usr/local/bin/web-brute.py') args = args.slice(1);
  let scopeUrl = null;
  try { scopeUrl = target ? new URL(/^https?:\/\//i.test(target) ? target : `${scheme}://${target}`) : null; } catch {}
  function normalizeWordlist(value) {
    const prefix = WORDLIST_PREFIXES.find(candidate => value.startsWith(candidate));
    if (!prefix) return value;
    const relative = value.slice(prefix.length);
    if (!relative || relative.split('/').includes('..') || relative.includes('\\')) {
      throw new Error(`Invalid wordlist path: ${value}`);
    }
    return engine === 'host' ? resolve(projectRoot, 'data', 'wordlists', relative) : posix.join('/usr/share/wordlists', relative);
  }
  let normalizedArgs = args.map((arg, index) => {
    if (typeof arg !== 'string') throw new Error('Tool arguments must be strings');
    const fileFlag = FILE_FLAGS[toolId]?.find(flag => arg.startsWith(`${flag}=`));
    if (fileFlag) return `${fileFlag}=${normalizeWordlist(arg.slice(fileFlag.length + 1))}`;
    const normalized = normalizeWordlist(arg);
    if (normalized !== arg) return normalized;
    const isUrl = URL_FLAGS[toolId]?.includes(args[index - 1]) ||
      (toolId === 'whatweb' && !arg.startsWith('-') && index === 0) ||
      (toolId === 'web-brute' && !arg.startsWith('-') && index === 0) ||
      (toolId === 'curl' && index === args.length - 1 && !arg.startsWith('-'));
    if (!isUrl) return arg;
    let normalizedUrl = /^https?:\/\//i.test(arg) ? arg : `${scheme}://${arg}`;
    if (scopeUrl) {
      try {
        const candidate = new URL(normalizedUrl);
        if (candidate.hostname !== scopeUrl.hostname || candidate.port !== scopeUrl.port || candidate.protocol !== scopeUrl.protocol) {
          candidate.protocol = scopeUrl.protocol;
          candidate.host = scopeUrl.host;
          normalizedUrl = candidate.toString();
        }
      } catch {}
    }
    return normalizedUrl;
  });
  if (toolId === 'gobuster' && normalizedArgs[0] === '-m' && normalizedArgs[1]) {
    normalizedArgs = [normalizedArgs[1], ...normalizedArgs.slice(2)];
  }
  if (toolId === 'hydra') normalizedArgs = normalizeHydraServiceAliases(normalizedArgs);
  if (['nmap', 'hydra'].includes(toolId)) {
    for (let index = 0; index < normalizedArgs.length; index++) {
      if (!/^https?:\/\//i.test(normalizedArgs[index])) continue;
      const targetUrl = new URL(normalizedArgs[index]);
      normalizedArgs[index] = targetUrl.hostname.replace(/^\[|\]$/g, '');
      const port = targetUrl.port || (targetUrl.protocol === 'https:' ? '443' : '80');
      const flag = toolId === 'nmap' ? '-p' : '-s';
      if (toolId === 'nmap' && normalizedArgs.includes('-F') && !['80', '443'].includes(port)) {
        normalizedArgs.splice(normalizedArgs.indexOf('-F'), 1);
      }
      const portIndex = normalizedArgs.indexOf(flag);
      if (portIndex < 0) normalizedArgs.push(flag, port);
      else if (toolId === 'nmap') {
        const currentPorts = normalizedArgs[portIndex + 1] || '';
        if (!currentPorts.split(',').includes(port)) normalizedArgs[portIndex + 1] = `${currentPorts},${port}`.replace(/^,/, '');
      } else if (normalizedArgs[portIndex + 1] !== port) {
        normalizedArgs[portIndex + 1] = port;
      }
      const inlinePortIndex = normalizedArgs.findIndex(arg => arg.startsWith(`${flag}=`));
      if (toolId === 'hydra' && inlinePortIndex >= 0) normalizedArgs[inlinePortIndex] = `${flag}=${port}`;
      if (toolId === 'hydra' && targetUrl.protocol === 'https:' && !normalizedArgs.includes('-S')) normalizedArgs.push('-S');
    }
    if (toolId === 'hydra') {
      const targetIndex = normalizedArgs.findIndex((arg, index) =>
        index > 0 && !arg.startsWith('-') && normalizedArgs[index + 1] &&
        /^(https?|ftp|ssh|rdp|http-post-form|http-get-form|http-post|http-get|https-post-form|https-get-form|https-post|https-get)$/i.test(normalizedArgs[index + 1])
      );
      if (targetIndex >= 0) {
        const trailingOptions = [];
        for (const [flag, width] of [['-s', 2], ['-S', 1]]) {
          const optionIndex = normalizedArgs.indexOf(flag);
          if (optionIndex > targetIndex) trailingOptions.push(...normalizedArgs.splice(optionIndex, width));
        }
        if (trailingOptions.length > 0) normalizedArgs.splice(targetIndex, 0, ...trailingOptions);
      }
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
  const sourceImageMissing = ['cppcheck','flawfinder'].includes(toolId)
    && /rt-sast-c/.test(output) && /unable to find image|no such image|image .*not (?:known|found)|pull access denied|failed to resolve reference/i.test(output);
  const semanticFailure = toolId === 'arjun' && /is not a valid URL|Skipped .* due to errors/i.test(output) ||
    toolId === 'ffuf' && /Errors:\s*[1-9]\d*/.test(output) ||
    toolId === 'nmap' && /Unable to split netmask|No targets were specified|Failed to resolve/i.test(output) ||
    toolId === 'system-tools' && /(?:^|\n)\s*(?:FATAL|VERIFY_FAILED|FILE_TAMPER_FAILED|UPLOAD_RESULT:\s*check|ERROR):/im.test(output) ||
    ['nikto', 'sqlmap', 'httpx'].includes(toolId) && /unable to connect|connection (?:refused|timed out)|no web server found|\[CRITICAL\]/i.test(output);
  const success = result.exitCode === 0 && !result.timedOut && !result.aborted && !result.outputLimitExceeded && !semanticFailure;
  return { ...result, success, error: success ? null : sourceImageMissing
    ? '缺少或无法读取源码扫描镜像 rt-sast-c；请在扫描后端构建或导入镜像后新建扫描任务'
    : result.error ||
    (result.aborted ? '操作员手动中止' : result.timedOut ? 'Tool timed out' :
      result.outputLimitExceeded ? 'Tool output limit exceeded' : semanticFailure ? 'Tool rejected input or requests failed' : `Tool exited with code ${result.exitCode}`) };
}

export function redactToolArgs(args, toolId = '') {
  if (toolId === 'target-request') return args.map(arg => {
    try { const value=JSON.parse(arg); if(value.headers) for(const key of Object.keys(value.headers)) if(/cookie|authorization/i.test(key)) value.headers[key]='[REDACTED]'; return JSON.stringify(value); }
    catch { return '[INVALID REQUEST]'; }
  });
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
