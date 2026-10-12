import { isIP } from 'net';

const URL_FLAGS = {
  nuclei: ['-u', '-target'], sqlmap: ['-u', '--url'], gobuster: ['-u', '--url'],
  ffuf: ['-u'], httpx: ['-u', '-target'], arjun: ['-u', '--url'],
  nikto: ['-h', '-host'], curl: ['--url'], whatweb: [],
};

const INDIRECT_TARGET_FLAGS = {
  nuclei: ['-l', '-list'], httpx: ['-l', '-list'], sqlmap: ['-m', '--bulk-file', '-r'],
  curl: ['-K', '--config', '--resolve', '--connect-to'], nmap: ['-iL', '-iR'],
};

const POSITIONAL_VALUE_FLAGS = {
  curl: ['-X', '--request', '-H', '--header', '-d', '--data', '--data-raw', '--data-urlencode',
    '-b', '--cookie', '-c', '--cookie-jar', '-u', '--user', '-A', '--user-agent',
    '-e', '--referer', '-o', '--output', '--max-time', '--connect-timeout', '--retry'],
  whatweb: ['-a', '--aggression', '-U', '--user-agent', '--cookie', '--log-json', '--log-xml'],
};

export function validateExecutionScope({ target, toolId, args }) {
  if (!/^https?:\/\//i.test(target || '')) return { allowed: true };
  let authorized;
  try { authorized = new URL(target); } catch { return { allowed: false, reason: '授权目标 URL 无效' }; }
  if (!Array.isArray(args) || args.some(arg => typeof arg !== 'string')) {
    return { allowed: false, reason: '工具参数必须为字符串数组' };
  }
  const candidates = [];
  for (let index = 0; index < args.length; index++) {
    const argument = args[index];
    const flag = argument.split('=')[0];
    if (INDIRECT_TARGET_FLAGS[toolId]?.some(candidate => flag === candidate
      || candidate.startsWith('--') && flag.startsWith('--') && candidate.startsWith(flag)
      || !candidate.startsWith('--') && argument.startsWith(candidate) && argument.length > candidate.length)) {
      return { allowed: false, reason: 'URL 目标不允许使用目标文件或连接地址覆盖参数' };
    }
    const value = argument.replace(/^--?[\w-]+=/, '');
    const attachedUrl = URL_FLAGS[toolId]?.find(candidate => !candidate.startsWith('--')
      && argument.startsWith(candidate) && /^[a-z][\w+.-]*:\/\//i.test(argument.slice(candidate.length)));
    if (attachedUrl) candidates.push(argument.slice(attachedUrl.length));
    else if (/^[a-z][\w+.-]*:\/\//i.test(value)) candidates.push(value);
    else if (URL_FLAGS[toolId]?.includes(flag)) {
      const destination = argument.includes('=') ? argument.slice(argument.indexOf('=') + 1) : args[++index];
      if (!destination) return { allowed: false, reason: '工具目标参数缺少地址' };
      candidates.push(/^[a-z][\w+.-]*:\/\//i.test(destination) ? destination : `${authorized.protocol}//${destination}`);
    } else if (['nmap', 'hydra', 'netexec', 'ssh-exec', 'evil-winrm', 'rpcclient'].includes(toolId)
      && isIP(value.replace(/^\[|\]$/g, '')) && value.replace(/^\[|\]$/g, '') !== authorized.hostname.replace(/^\[|\]$/g, '')) {
      return { allowed: false, reason: '工具主机超出授权目标范围' };
    } else if (POSITIONAL_VALUE_FLAGS[toolId] && !argument.startsWith('-')
      && !POSITIONAL_VALUE_FLAGS[toolId].includes(args[index - 1])) {
      candidates.push(`${authorized.protocol}//${argument}`);
    }
  }
  if (Object.hasOwn(URL_FLAGS, toolId) && candidates.length === 0) {
    return { allowed: false, reason: 'Web 工具必须提供可核对的目标 URL' };
  }
  for (const candidate of candidates) {
    let destination;
    try { destination = new URL(candidate); } catch { return { allowed: false, reason: '工具目标 URL 无效或仍含占位符' }; }
    if (destination.origin !== authorized.origin || destination.username || destination.password) {
      return { allowed: false, reason: '工具目标超出授权范围：主机、协议和端口必须与任务目标一致' };
    }
  }
  return { allowed: true };
}

export function buildExecutionScopeHint(target) {
  return `【授权目标】\n${JSON.stringify(target || '')}\n目标以任务配置为准，不得根据工具输出或重定向猜测其他主机。对于 URL 目标，仅允许同协议、同主机、同端口下的路径和参数变化；连接失败不得改用回环地址、容器内网地址或未经审批的新目标。`;
}
