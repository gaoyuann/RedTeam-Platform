import {posix} from 'node:path';

// CScan mounts the authorized repository root at /src in its worker. This is
// a service-side path, never a request to read a file from the platform host.
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
