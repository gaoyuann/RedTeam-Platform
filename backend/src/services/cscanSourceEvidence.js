import {open,readdir,realpath,lstat} from 'node:fs/promises';
import {constants} from 'node:fs';
import {join,resolve} from 'node:path';
import {createHash} from 'node:crypto';

// Read only the standard source cache in this Flow's workspace. Never follow
// source symlinks, accept report-supplied host paths, or fetch the target anew.
export async function captureCscanSource(config,flowId,{signal}={}) {
  if(!config.workDir || !/^\d+$/.test(String(flowId)))return null;
  const work=await realpath(config.workDir);
  const root=join(work,'flow-'+flowId,'src');
  for(const directory of [join(work,'flow-'+flowId),root]) {
    const stat=await lstat(directory);if(!stat.isDirectory() || stat.isSymbolicLink())throw new Error('源码缓存目录无效');
  }
  const files=[];let total=0,visited=0;const skipped=[];
  async function walk(directory,depth=0) {
    if(depth>24)throw new Error('源码目录过深');
    for(const entry of await readdir(directory,{withFileTypes:true})) {
      signal?.throwIfAborted();
      if(++visited>10000)throw new Error('源码目录条目超过上限');
      if(entry.name.startsWith('.') || entry.isSymbolicLink())continue;
      const path=join(directory,entry.name);
      if(entry.isDirectory()){await walk(path,depth+1);continue;}
      if(!entry.isFile() || !/\.(?:c|h|cc|cpp|cxx|hpp|hxx)$/i.test(entry.name))continue;
      if(files.length>=500)throw new Error('源码文件数量超过保存上限');
      const file=await open(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
      try {
        // Validate the opened inode's actual location, including ancestor swaps.
        const actual=await realpath('/proc/self/fd/'+file.fd);
        if(!actual.startsWith(root+'/') || resolve(actual)!==path)throw new Error('源码路径发生变化');
        const before=await file.stat();if(!before.isFile() || before.size>512*1024) {skipped.push(path.slice(root.length+1));continue;}
        const bytes=Buffer.alloc(before.size+1);const {bytesRead}=await file.read(bytes,0,bytes.length,0);
        const after=await file.stat();
        if(bytesRead!==before.size || before.size!==after.size || before.mtimeMs!==after.mtimeMs)throw new Error('源码正在变化，等待下一次读取');
        const content=new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,bytesRead));
        if(content.includes('\0')) {skipped.push(path.slice(root.length+1));continue;}
        total+=bytesRead;if(total>8*1024*1024)throw new Error('源码总量超过保存上限');
        files.push({path:'/work/src/'+path.slice(root.length+1),relative_path:path.slice(root.length+1),content,
          sha256:createHash('sha256').update(bytes.subarray(0,bytesRead)).digest('hex'),bytes:bytesRead});
      } finally {await file.close();}
    }
  }
  await walk(root);
  return {flow_id:String(flowId),captured_at:new Date().toISOString(),origin:'cscan_workspace',
    note:'CScan 工作目录的文件副本；不证明每个文件均已审计或与运行版本一致。',files,skipped};
}
