import {posix} from 'node:path';
import {normalizeTopologyTarget} from './nmapTopology.js';

export function cscanRemotePath(value) {
  if(typeof value!=='string' || value.length>1024 || /[\x00-\x1f\\]/.test(value)) throw new Error('远端源码路径无效');
  const path=value.trim().replace(/\/+$/,'');
  if(!path.startsWith('/') || path.split('/').some(part=>part==='.' || part==='..') || posix.normalize(path)!==path)
    throw new Error('远端源码路径无效，请填写明确的文件或目录路径');
  return path;
}

// Like the reference client, submit the target to the remote Flow, not to a
// local filesystem picker. A filesystem path belongs to the execution side.
export function cscanTarget(value) {
  if(typeof value!=='string' || !value.trim() || value.length>1024 || /[\x00-\x20\\]/.test(value.trim()))
    throw new Error('请填写靶机 IP、主机:端口、HTTP/TCP 地址或远端源码路径');
  const target=value.trim();
  if(target.startsWith('/')) return cscanRemotePath(target);
  if(/^(?:https?|tcp):\/\//i.test(target) || /^[^/:]+:\d+$/.test(target)) {
    const url=new URL(/^[^/:]+:\d+$/.test(target)?'tcp://'+target:target);
    if(!['http:','https:','tcp:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.hash
      || url.protocol==='tcp:' && (!url.port || !['','/'].includes(url.pathname) || url.search)
      || /%(?:2f|5c|2e|00|0a|0d)/i.test(url.pathname)) throw new Error('CScan 目标地址无效');
    return url.href;
  }
  const host=normalizeTopologyTarget(target);
  if(host.includes('/')) throw new Error('CScan 任务请指定单个靶机或远端源码路径');
  return host;
}

// Preserve the older /src service-path API for existing tasks and callers.
export function cscanSourcePath(value) {
  if(typeof value!=='string' || !value.trim() || value.length>1024 || /[\x00-\x1f\\]/.test(value))
    throw new Error('请填写 CScan 服务中的源码文件或目录路径，例如 /src/my-project');
  const path=value.trim().replace(/\/+$/,'');
  if(!path.startsWith('/src/') || path.split('/').some(part=>part==='.' || part==='..') || posix.normalize(path)!==path)
    throw new Error('源码路径必须指向 CScan 已挂载的 /src/项目目录或文件；本机路径不会自动上传');
  return path;
}

export function cscanNotes(value='') {
  if(typeof value!=='string' || value.length>4000 || /\x00/.test(value)) throw new Error('源码审计说明须为不超过 4000 字的文本');
  return value.trim();
}
