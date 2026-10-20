import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {readFile} from 'node:fs/promises';
const exec = promisify(execFile);

export function sourceSubdir(value = '') {
  if (typeof value !== 'string' || value.length > 1024 || /[\\\x00-\x1f]/.test(value)
    || (value && value.split('/').some(part => !part || part === '.' || part === '..')))
    throw new Error('请选择已配置源码目录内的文件夹');
  return value;
}

// Credentials stay in server-side connection files, never in a browser request.
export async function runSourceScript(connection, script, values, {signal, execute = exec} = {}) {
  const encoded = Buffer.from(script).toString('base64');
  const args64 = Buffer.from(JSON.stringify(values)).toString('base64');
  const wrapper = `import base64,json,sys;sys.argv=['source']+json.loads(base64.b64decode('${args64}'));exec(base64.b64decode('${encoded}'))`;
  let binary = 'python3', args = ['-c', wrapper];
  if (connection.kind === 'ssh') {
    args = ['-T','-p',String(connection.port),'-o','ConnectTimeout=10','-o','ConnectionAttempts=1',
      '-o','StrictHostKeyChecking=yes','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2'];
    if (connection.known_hosts_file) args.push('-o',`UserKnownHostsFile=${connection.known_hosts_file}`);
    if (connection.identity_file) args.push('-o','BatchMode=yes','-o','IdentitiesOnly=yes','-i',connection.identity_file);
    else args.push('-o','NumberOfPasswordPrompts=1','-o','PreferredAuthentications=password');
    args.push(`${connection.username}@${connection.host}`,`python3 -c "${wrapper}"`);
    binary = 'ssh';
    if (connection.password_file) {binary = 'sshpass';args = ['-f',connection.password_file,'ssh',...args];}
  }
  try {
    return await execute(binary,args,{signal,timeout:60000,maxBuffer:32*1024*1024,killSignal:'SIGKILL'});
  } catch {
    if (signal?.aborted) throw new Error('源码访问已取消');
    throw new Error('目标目录无法读取，请检查目录权限、Python 3、SSH 连接及主机指纹');
  }
}

export async function browseRemoteSourceDirectory(connection, subdir = '', options = {}) {
  if (!['ssh','local'].includes(connection.kind)) throw new Error('此连接不支持文件系统目录浏览');
  subdir = sourceSubdir(subdir);
  const script = await readFile(new URL('./sourceDirectory.py',import.meta.url),'utf8');
  const {stdout} = await runSourceScript(connection,script,[connection.source_root,subdir],options);
  const result = JSON.parse(stdout);
  if (!Array.isArray(result.entries) || result.entries.length > 500) throw new Error('目录列表格式无效');
  return result;
}
