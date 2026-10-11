import { readFile } from 'node:fs/promises';
import { resolve, isAbsolute, posix } from 'node:path';
import { fileURLToPath } from 'node:url';

const defaultFile = fileURLToPath(new URL('../../../data/source-scan/connections.json', import.meta.url));
export function sourceTarget(value) {
  if (typeof value !== 'string' || !value.trim() || /[\s\x00-\x1f]/.test(value)) throw new Error('请填写 HTTP/HTTPS 或 tcp://主机:端口 运行地址');
  const url = new URL(value);
  if (!['http:', 'https:', 'tcp:'].includes(url.protocol) || !url.hostname || url.username || url.password || url.hash) throw new Error('程序运行地址无效');
  if (url.protocol === 'tcp:' && (!url.port || url.pathname && url.pathname !== '/' || url.search)) throw new Error('TCP 地址须为 tcp://主机:端口');
  return url.protocol === 'tcp:' ? `tcp://${url.host}` : url.href;
}
export function deploymentHost(target) { return new URL(sourceTarget(target)).hostname.replace(/^\[|\]$/g, '').toLowerCase(); }
export async function loadSourceConnections(filename = process.env.SOURCE_SCAN_CONNECTIONS_FILE || defaultFile) {
  let parsed;
  try { parsed = JSON.parse(await readFile(resolve(filename), 'utf8')); }
  catch (error) {
    if (error.code === 'ENOENT') return [];
    throw new Error('源码连接配置无法读取或不是有效 JSON');
  }
  if (!Array.isArray(parsed)) throw new Error('源码连接配置必须为数组');
  const ids = new Set();
  return parsed.map(item => {
    if (!item || !/^[a-zA-Z0-9_-]{1,64}$/.test(item.id || '') || ids.has(item.id)) throw new Error('源码连接标识无效或重复');
    ids.add(item.id);
    const kind = item.kind || 'ssh';
    if (!['local', 'ssh'].includes(kind)) throw new Error('源码来源须为 local 或 ssh');
    if (typeof item.source_root !== 'string' || !isAbsolute(item.source_root) || posix.normalize(item.source_root) === '/' || /[\x00-\x1f]/.test(item.source_root)) throw new Error('源码目录须为明确的绝对路径，不能使用根目录');
    const targets = (item.targets || []).map(sourceTarget);
    if (!targets.length) throw new Error('每个源码项目须配置 targets 运行地址列表');
    const value = { id: item.id, name: String(item.name || item.id), kind, source_root: item.source_root,
      targets: [...new Set(targets)], architecture: String(item.architecture || 'unknown') };
    if (kind === 'local') return value;
    const host = String(item.host || '');
    if (!/^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}$/.test(host)) throw new Error('源码 SSH 主机无效');
    if (!/^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$/.test(item.username || '')) throw new Error('源码 SSH 用户名无效');
    if (!isAbsolute(item.identity_file || '') && !isAbsolute(item.password_file || '')) throw new Error('请配置后端本机的 identity_file 或 password_file 绝对路径');
    if (item.identity_file && item.password_file) throw new Error('密钥和密码文件只能选择一种');
    if (item.known_hosts_file && !isAbsolute(item.known_hosts_file)) throw new Error('known_hosts_file 须为绝对路径');
    const port = item.port ?? 22;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('源码 SSH 端口无效');
    return { ...value, host, port, username: item.username, identity_file: item.identity_file,
      password_file: item.password_file, known_hosts_file: item.known_hosts_file };
  });
}
export async function resolveSourceConnection(id, target, connections) {
  const items = connections || await loadSourceConnections();
  const connection = items.find(item => item.id === id);
  if (!connection) throw new Error('请选择已配置的源码项目；在测试程序后端配置 connections.json');
  if (!connection.targets.includes(sourceTarget(target))) throw new Error('运行地址未绑定到所选源码项目');
  return connection;
}
export function publicSourceConnection(item) {
  return { id: item.id, name: item.name, kind: item.kind, targets: item.targets, architecture: item.architecture };
}
