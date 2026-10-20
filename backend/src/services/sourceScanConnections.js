import {sourceAnalysisOptions} from './sourceScanPolicy.js';
import {sourceSubdir} from './sourceRemoteDirectory.js';
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
export function httpSourceConnection(target, value) {
  const runtime = new URL(sourceTarget(target));
  if (!['http:', 'https:'].includes(runtime.protocol)) throw new Error('HTTP 源码目录需要 HTTP/HTTPS 运行目标；TCP 程序请使用已配置的源码项目');
  let url;
  try {
    if (typeof value !== 'string' || !value.trim() || /[\x00-\x20]/.test(value.trim())) throw new Error();
    if (!value.trim().startsWith('/') && !/^https?:\/\//i.test(value.trim())) throw new Error();
    url = new URL(value.trim(), runtime.origin + '/');
    if (url.username || url.password || url.search || url.hash) throw new Error();
  } catch { throw new Error('请填写源码目录 URL 或 /开头的目录路径'); }
  if (url.origin !== runtime.origin) throw new Error('HTTP 源码目录必须与运行目标使用同一协议、主机和端口');
  if (!url.pathname.endsWith('/')) url.pathname += '/';
  return { id: 'task-http-source', name: '任务指定的 HTTP 源码目录', kind: 'http', source_url: url.href,
    targets: [runtime.href], architecture: 'unknown', analysis: sourceAnalysisOptions() };
}
export async function resolveTaskSource(parameters, target) {
  if (parameters.source_url) return httpSourceConnection(target, parameters.source_url);
  if (!parameters.connection_id) return null;
  const connection = await resolveSourceConnection(parameters.connection_id, target);
  return {...connection,source_subdir:sourceSubdir(parameters.source_subdir || '')};
}
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
    if (!['local', 'ssh', 'http'].includes(kind)) throw new Error('源码来源须为 local、ssh 或 http');
    const targets = (item.targets || []).map(sourceTarget);
    if (!targets.length) throw new Error('每个源码项目须配置 targets 运行地址列表');
    const value = { id: item.id, name: String(item.name || item.id), kind,
      targets: [...new Set(targets)], architecture: String(item.architecture || 'unknown'),analysis:sourceAnalysisOptions(item.analysis) };
    if (kind === 'http') {
      let sourceUrl;
      try {
        sourceUrl = new URL(String(item.source_url || ''));
        if (!['http:', 'https:'].includes(sourceUrl.protocol) || sourceUrl.username || sourceUrl.password || sourceUrl.hash || sourceUrl.search) throw new Error();
        if (!sourceUrl.pathname.endsWith('/')) sourceUrl.pathname += '/';
      } catch { throw new Error('HTTP 源码目录须为无认证的 http(s) URL'); }
      const sourceOrigin = sourceUrl.origin;
      if (!targets.some(target => new URL(target).origin === sourceOrigin)) throw new Error('HTTP 源码目录必须与运行目标使用同一协议、主机和端口');
      return { ...value, source_url: sourceUrl.href };
    }
    if (typeof item.source_root !== 'string' || !isAbsolute(item.source_root) || posix.normalize(item.source_root) === '/' || /[\x00-\x1f]/.test(item.source_root)) throw new Error('源码目录须为明确的绝对路径，不能使用根目录');
    if (kind === 'local') return { ...value, source_root: item.source_root };
    const host = String(item.host || '');
    if (!/^[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}$/.test(host)) throw new Error('源码 SSH 主机无效');
    if (!/^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$/.test(item.username || '')) throw new Error('源码 SSH 用户名无效');
    if (!isAbsolute(item.identity_file || '') && !isAbsolute(item.password_file || '')) throw new Error('请配置后端本机的 identity_file 或 password_file 绝对路径');
    if (item.identity_file && item.password_file) throw new Error('密钥和密码文件只能选择一种');
    if (item.known_hosts_file && !isAbsolute(item.known_hosts_file)) throw new Error('known_hosts_file 须为绝对路径');
    const port = item.port ?? 22;
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('源码 SSH 端口无效');
    return { ...value, source_root: item.source_root, host, port, username: item.username, identity_file: item.identity_file,
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
/** Resolve the source project from the same runtime address entered by the operator. */
export async function resolveSourceConnectionForTarget(target, connections) {
  const normalized = sourceTarget(target);
  const items = connections || await loadSourceConnections();
  const matches = items.filter(item => item.targets.includes(normalized));
  if (matches.length > 1) throw new Error('运行地址绑定了多个源码项目，请在 connections.json 中保持一个唯一映射');
  return matches[0] || null;
}
export function publicSourceConnection(item) {
  return { id: item.id, name: item.name, kind: item.kind, targets: item.targets, architecture: item.architecture, analysis: item.analysis,
    source_url: item.source_url || null };
}
