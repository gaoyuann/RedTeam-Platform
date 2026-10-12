import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { httpSourceConnection } from './sourceScanConnections.js';
const exec = promisify(execFile);
const directory = dirname(fileURLToPath(import.meta.url));
export const SNAPSHOT_ROOT = resolve(directory, '../../../data/source-scan/snapshots');
const SOURCE_EXTENSIONS = /\.(c|h|cc|cpp|cxx|hpp|hh|hxx)$/i;
const SOURCE_LIMIT_FILES = 500;
const SOURCE_LIMIT_BYTES = 8 * 1024 * 1024;
const SOURCE_LIMIT_FILE_BYTES = 512 * 1024;
const SOURCE_LIMIT_LINKS = 20000;

function decodeHtml(value) {
  return value.replace(/&amp;/gi, '&').replace(/&quot;/gi, '"').replace(/&#39;/gi, "'").replace(/&lt;/gi, '<').replace(/&gt;/gi, '>');
}

function listingLinks(html, base) {
  const links = [];
  const pattern = /<a\b[^>]*\bhref\s*=\s*(["'])(.*?)\1/gi;
  let match;
  while ((match = pattern.exec(html))) {
    try {
      const url = new URL(decodeHtml(match[2]), base);
      if (!['http:', 'https:'].includes(url.protocol) || url.origin !== base.origin || url.username || url.password) continue;
      url.hash = '';
      if (url.search || !url.href.startsWith(base.href)) continue;
      links.push(url);
    } catch { /* malformed links are skipped and recorded by the bounded walk */ }
  }
  return links;
}

async function boundedHttpBody(response) {
  const reader = response.body?.getReader();
  if (!reader) return Buffer.alloc(0);
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return Buffer.concat(chunks, size);
      size += value.byteLength;
      if (size > SOURCE_LIMIT_FILE_BYTES) {
        await reader.cancel();
        return null;
      }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
}

export async function browseHttpSourceDirectory(target, sourceUrl) {
  const connection = httpSourceConnection(target, sourceUrl);
  const url = new URL(connection.source_url);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  try {
    const response = await fetch(url.href, { redirect: 'error', signal: controller.signal });
    if (!response.ok) { await response.body?.cancel(); throw new Error(`目录访问失败：HTTP ${response.status}`); }
    const body = await boundedHttpBody(response);
    if (!body) throw new Error('目录响应超过 512 KiB');
    const entries = [], seen = new Set();
    for (const child of listingLinks(body.toString('utf8'), url)) {
      if (child.href === url.href || seen.has(child.href)) continue;
      seen.add(child.href);
      const directory = child.pathname.endsWith('/');
      if (!directory && !SOURCE_EXTENSIONS.test(child.pathname)) continue;
      let name = child.pathname.slice(url.pathname.length);
      try { name = decodeURIComponent(name); } catch {}
      entries.push({ url: child.href, name, directory });
      if (entries.length >= 500) break;
    }
    entries.sort((a, b) => Number(b.directory) - Number(a.directory) || a.name.localeCompare(b.name));
    return { url: url.href, parent: url.pathname === '/' ? null : new URL('../', url).href, entries,
      note: entries.length ? '选择目录后将递归读取其中的 C/C++ 源码' : '未发现目录或 C/C++ 文件链接；请确认服务器提供目录索引' };
  } finally { clearTimeout(timer); }
}

async function collectHttpSource(connection, { signal, fetchImpl = globalThis.fetch } = {}) {
  if (typeof fetchImpl !== 'function') throw new Error('当前 Node.js 不支持 HTTP 源码采集，请使用 Node 18 或更高版本');
  const root = new URL(connection.source_url);
  if (!root.pathname.endsWith('/')) root.pathname += '/';
  const queue = [root], visited = new Set(), files = [], skipped = [];
  let total = 0, linksSeen = 0;
  const controller = new AbortController();
  const cancel = () => controller.abort();
  signal?.addEventListener('abort', cancel, { once: true });
  const timer = setTimeout(cancel, 60000);
  try {
  while (queue.length) {
    if (signal?.aborted) throw new Error('源码获取已取消');
    const url = queue.shift();
    if (visited.has(url.href)) continue;
    visited.add(url.href);
    if (++linksSeen > SOURCE_LIMIT_LINKS) { skipped.push({path: root.pathname, reason: 'directory entry limit reached'}); break; }
    let response;
    try { response = await fetchImpl(url.href, { redirect: 'error', signal: controller.signal, headers: { accept: 'text/html,text/plain,application/octet-stream' } }); }
    catch (error) { throw new Error(`HTTP 源码获取失败：${error.message || '连接失败'}`); }
    if (!response.ok) { await response.body?.cancel(); skipped.push({path: url.pathname, reason: `HTTP ${response.status}`}); continue; }
    const relative = url.pathname.slice(root.pathname.length);
    const data = await boundedHttpBody(response);
    if (!data) { skipped.push({path: relative || '.', reason: 'HTTP response size limit'}); continue; }
    const contentType = String(response.headers?.get?.('content-type') || '').toLowerCase();
    if (url.pathname.endsWith('/') || (!SOURCE_EXTENSIONS.test(url.pathname) && contentType.includes('text/html'))) {
      if (data.length > SOURCE_LIMIT_FILE_BYTES) { skipped.push({path: relative || '.', reason: 'directory listing too large'}); continue; }
      const html = data.toString('utf8');
      for (const child of listingLinks(html, url)) {
        if (!child.pathname.startsWith(root.pathname) || visited.has(child.href)) continue;
        if (child.pathname.endsWith('/') || SOURCE_EXTENSIONS.test(child.pathname)) queue.push(child);
      }
      continue;
    }
    if (!SOURCE_EXTENSIONS.test(url.pathname)) continue;
    if (!relative || relative.includes('..') || files.length >= SOURCE_LIMIT_FILES) { skipped.push({path: relative || '.', reason: files.length >= SOURCE_LIMIT_FILES ? 'file count limit' : 'invalid path'}); continue; }
    if (data.length > SOURCE_LIMIT_FILE_BYTES || total + data.length > SOURCE_LIMIT_BYTES) { skipped.push({path: relative, reason: 'source size limit'}); continue; }
    try {
      const content = new TextDecoder('utf-8', { fatal: true }).decode(data);
      if (content.includes('\0')) throw new Error('binary source');
      files.push({ path: relative, content }); total += data.length;
    } catch (error) { skipped.push({path: relative, reason: error.message}); }
  }
  if (!files.length) throw new Error('HTTP 源码目录中未读取到 C/C++ 源码文件');
  return { files, skipped, bytes: total };
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', cancel);
  }
}
export async function collectSource(connection, { signal, execute = exec } = {}) {
  if (connection.kind === 'http') return collectHttpSource(connection, { signal });
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
  const manifest = { snapshot_id: id, connection_id: connection.id, source_url: connection.source_url || null, architecture: connection.architecture,
    created_at: new Date().toISOString(), files: documents.map(({ content, ...info }) => info), skipped: collected.skipped };
  await writeFile(resolve(root, 'manifest.json'), JSON.stringify(manifest), { flag: 'wx', mode: 0o400 });
  return { ...manifest, documents, sourceDir };
}
