import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
const exec = promisify(execFile);
const directory = dirname(fileURLToPath(import.meta.url));
export const SNAPSHOT_ROOT = resolve(directory, '../../../data/source-scan/snapshots');
export async function collectSource(connection, { signal, execute = exec } = {}) {
  const collector = await readFile(resolve(directory, 'sourceCollector.py'), 'utf8');
  const root = Buffer.from(connection.source_root).toString('base64');
  let binary = 'python3', args = ['-c', collector, root];
  if (connection.kind === 'ssh') {
    const encoded = Buffer.from(collector).toString('base64');
    const command = `python3 -c "import base64;exec(base64.b64decode('${encoded}'))" '${root}'`;
    args = ['-T', '-p', String(connection.port), '-o', 'ConnectTimeout=10', '-o', 'ConnectionAttempts=1',
      '-o', 'StrictHostKeyChecking=yes', '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2'];
    if (connection.known_hosts_file) args.push('-o', `UserKnownHostsFile=${connection.known_hosts_file}`);
    if (connection.identity_file) args.push('-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-i', connection.identity_file);
    else args.push('-o', 'NumberOfPasswordPrompts=1', '-o', 'PreferredAuthentications=password');
    args.push(`${connection.username}@${connection.host}`, command);
    binary = 'ssh';
    if (connection.password_file) { binary = 'sshpass'; args = ['-f', connection.password_file, 'ssh', ...args]; }
  }
  let output;
  try { output = await execute(binary, args, { signal, timeout: 60000, maxBuffer: 32 * 1024 * 1024, killSignal: 'SIGKILL' }); }
  catch (error) {
    if (signal?.aborted) throw new Error('源码获取已取消');
    // execFile errors contain the whole command; never expose it or credential paths.
    throw new Error(`源码获取失败（${connection.kind}）：请检查目录、Python 3、SSH 认证和已验证的主机指纹。 ${String(error.stderr || '').slice(-500)}`);
  }
  const result = JSON.parse(output.stdout);
  if (!Array.isArray(result.files) || !Array.isArray(result.skipped) || result.files.length > 500) throw new Error('源码清单格式无效');
  const seen = new Set();
  let total = 0;
  for (const file of result.files) {
    if (typeof file.path !== 'string' || file.path.length > 1024 || file.path.includes('\\') || file.path.startsWith('/') || file.path.split('/').some(p => !p || p === '.' || p === '..') || /[\x00-\x1f]/.test(file.path) || seen.has(file.path)) throw new Error('源码清单包含无效路径');
    if (!/\.(c|h|cc|cpp|cxx|hpp|hh|hxx)$/i.test(file.path) || typeof file.content !== 'string') throw new Error('源码文件类型无效');
    total += Buffer.byteLength(file.content);
    if (Buffer.byteLength(file.content) > 512 * 1024 || total > 8 * 1024 * 1024) throw new Error('源码清单超过大小限制');
    seen.add(file.path);
  }
  if (!result.files.length) throw new Error('未读取到 C/C++ 源码文件，请检查项目目录和读取权限');
  return result;
}
export async function createSourceSnapshot(connection, options = {}) {
  const collected = await collectSource(connection, options);
  const id = randomUUID();
  const root = resolve(options.snapshotRoot || SNAPSHOT_ROOT, id);
  const sourceDir = resolve(root, 'project');
  await mkdir(sourceDir, { recursive: true, mode: 0o700 });
  const documents = [];
  for (const file of collected.files) {
    if (options.signal?.aborted) throw new Error('源码快照已取消');
    const path = resolve(sourceDir, ...file.path.split('/'));
    await mkdir(dirname(path), { recursive: true, mode: 0o700 });
    await writeFile(path, file.content, { flag: 'wx', mode: 0o400 });
    documents.push({ ...file, sha256: createHash('sha256').update(file.content).digest('hex'), start_line: 1, end_line: file.content.split('\n').length });
  }
  const manifest = { snapshot_id: id, connection_id: connection.id, architecture: connection.architecture,
    created_at: new Date().toISOString(), files: documents.map(({ content, ...info }) => info), skipped: collected.skipped };
  await writeFile(resolve(root, 'manifest.json'), JSON.stringify(manifest), { flag: 'wx', mode: 0o400 });
  return { ...manifest, documents, sourceDir };
}
