import { isIP } from 'net';
import { parseTargetRequest } from '../tools/targetRequest.js';
import { isTargetInScope, scopeBlockReason } from './taskScope.js';
import {CODE_TOOL,parseCodeInvocation} from './verificationCodeArtifact.js';

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

const HYDRA_SERVICES = new Set(['http-post-form','http-get-form','http-post','http-get',
  'https-post-form','https-get-form','https-post','https-get','ftp','ssh','rdp','smb','mysql','postgres','redis','telnet']);

function networkToolTarget(toolId,args) {
  let value;
  if(toolId==='hydra') {
    const index=args.findIndex(arg=>HYDRA_SERVICES.has(arg.toLowerCase()));
    value=index>0 ? args[index-1] : args.find(arg=>/^(?:https?|ftp|ssh|rdp|smb|mysql|postgres|redis|telnet):\/\//i.test(arg));
  } else if(toolId==='netexec') value=args[1];
  else if(toolId==='rpcclient') value=args.at(-1);
  else if(['ssh-exec','evil-winrm'].includes(toolId)) {
    const index=args.findIndex(arg=>['-i','--host','--ip'].includes(arg.split('=')[0]));
    value=index<0 ? null : args[index].includes('=') ? args[index].slice(args[index].indexOf('=')+1) : args[index+1];
  } else return undefined;
  if(!value || value.startsWith('-')) return null;
  if(/^[a-z][\w+.-]*:\/\//i.test(value) && !/^(?:https?|tcp):\/\//i.test(value)) {
    try {
      const url=new URL(value);
      return url.hostname && !url.username && !url.password ? url.hostname.replace(/^\[|\]$/g,'') : null;
    } catch {return null;}
  }
  return value;
}

export function validateExecutionScope({ target, toolId, args, scope }) {
  if(toolId===CODE_TOOL) {
    try {
      parseCodeInvocation(args);
      if(!scope || !isTargetInScope(scope,target))throw new Error('载荷所属源码目标不在任务范围内');
      return {allowed:true};
    }catch(error){return {allowed:false,reason:error.message};}
  }
  if (toolId === 'target-request') {
    try {
      const request=parseTargetRequest(args, target);
      if(scope && !isTargetInScope(scope,request.url.href)) throw new Error('请求超出任务范围或命中排除项');
      return {allowed:true};
    }
    catch (error) { return {allowed:false,reason:error.message}; }
  }
  if (/^tcp:\/\//i.test(target || '')) return {allowed:false,reason:'TCP 程序目标须使用 target-request 进行有界交互'};
  if (!/^https?:\/\//i.test(target || '')) {
    if (!scope) return { allowed: true }; // legacy runs have no structured scope
    if (!Array.isArray(args) || args.some(arg => typeof arg !== 'string'))
      return {allowed:false,reason:'工具参数必须为字符串数组'};
    const reason=scopeBlockReason(scope,target,toolId==='nmap'?'port_scan':'');
    if(reason) return {allowed:false,reason};
    const candidates=[];
    const nmapValueFlags=new Set(['-p','--top-ports','-e','--script','--script-args','--exclude','-oN','-oX','-oA','--max-retries','--min-parallelism']);
    for(let index=0;index<args.length;index++) {
      const argument=args[index],flag=argument.split('=')[0];
      if(INDIRECT_TARGET_FLAGS[toolId]?.some(value=>flag===value || argument.startsWith(value) && argument.length>value.length))
        return {allowed:false,reason:'不允许使用目标文件或随机目标参数'};
      if(toolId==='nmap' && nmapValueFlags.has(argument)) {index++;continue;}
      if(URL_FLAGS[toolId]?.includes(flag)) {
        const value=argument.includes('=')?argument.slice(argument.indexOf('=')+1):args[++index];
        if(!value) return {allowed:false,reason:'工具目标参数缺少地址'};
        candidates.push(value);
        continue;
      }
      const explicit=argument.replace(/^--?[\w-]+=/,'');
      if(/^(?:https?|tcp):\/\//i.test(explicit)) candidates.push(explicit);
      else if(toolId==='nmap' && !argument.startsWith('-') && !argument.includes('=') && !/^\d+$/.test(argument))
        candidates.push(argument);
      else if(isIP(explicit) || /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(explicit)) candidates.push(explicit);
    }
    const networkTarget=networkToolTarget(toolId,args);
    if(networkTarget===null) return {allowed:false,reason:'网络工具目标无法核对'};
    if(networkTarget!==undefined) candidates.push(networkTarget);
    if(Object.hasOwn(URL_FLAGS,toolId) && !candidates.length)
      return {allowed:false,reason:'Web 工具必须提供可核对的目标地址'};
    for(const candidate of candidates) {
      const broad=['nuclei','nikto','gobuster','ffuf','sqlmap','web-brute'].includes(toolId);
      const blocked=scopeBlockReason(scope,candidate,broad?'web_scan':toolId==='nmap'?'port_scan':'');
      if(blocked) return {allowed:false,reason:blocked};
    }
    return { allowed: true };
  }
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
    if(scope) {
      const broad=['nuclei','nikto','gobuster','ffuf','sqlmap','web-brute'].includes(toolId);
      const reason=scopeBlockReason(scope,destination.href,broad?'web_scan':'');
      if(reason) return {allowed:false,reason};
    }
  }
  return { allowed: true };
}

export function buildExecutionScopeHint(target) {
  return `【授权目标】\n${JSON.stringify(target || '')}\n目标以任务配置为准，不得根据工具输出或重定向猜测其他主机。对于 URL 目标，仅允许同协议、同主机、同端口下的路径和参数变化；连接失败不得改用回环地址、容器内网地址或未经审批的新目标。`;
}
