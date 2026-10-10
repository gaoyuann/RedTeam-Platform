import { resolveTargetProfile, refineTargetProfile } from './targetProfileResolver.js';

function basePath(pathname) {
  if (pathname.endsWith('/')) return pathname;
  return /\.[^/]+$/.test(pathname) ? pathname.replace(/[^/]*$/, '') : `${pathname}/`;
}

function assetPath(url, body) {
  const documentUrl = new URL(url);
  documentUrl.pathname = basePath(url.pathname);
  for (const match of body.matchAll(/(?:href|src)\s*=\s*["']([^"']+)["']/gi)) {
    try {
      const asset = new URL(match[1], documentUrl);
      const path = asset.pathname.match(/^(.*?)\/dvwa\/(?:css|js|images)\//i);
      if (asset.origin === url.origin && path) return `${path[1]}/`;
    } catch {}
  }
  return null;
}

function applicationPath(url, body = '') {
  const vulnerability = url.pathname.match(/^(.*?)\/vulnerabilities(?:\/|$)/);
  if (vulnerability) return `${vulnerability[1]}/`;
  if (/\/(?:login|index|security|setup|instructions|about)\.php$/i.test(url.pathname)) return basePath(url.pathname);
  const assets = assetPath(url, body);
  return assets && isWithinPath(url.pathname, assets) ? assets : basePath(url.pathname);
}

function isWithinPath(pathname, path) {
  return pathname === path.replace(/\/$/, '') || pathname.startsWith(path);
}

export function normalizeTarget(target) {
  const raw = typeof target === 'string' ? target.trim() : '';
  const profile = resolveTargetProfile(raw.replace(/^https?:/i, scheme => scheme.toLowerCase()));
  if (profile.target_class === 'local_hash' || !profile.host || raw.includes('/')) {
    if (!/^https?:\/\//i.test(raw)) return profile;
  }
  try {
    const url = new URL(/^https?:\/\//i.test(raw) ? raw : `http://${raw}`);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('Invalid target URL');
    const path = basePath(url.pathname);
    return { ...profile, host: url.hostname, port: Number(url.port || (url.protocol === 'https:' ? 443 : 80)),
      scheme: url.protocol.slice(0, -1), origin: url.origin,
      base_path: path, base_url: `${url.origin}${path.replace(/\/$/, '')}`, target_url: url.href,
      transport_class: /^https?:\/\//i.test(raw) ? 'web_url' : profile.target_class };
  } catch {
    return profile;
  }
}

export function buildDiscoveredProfile(target, results = []) {
  const initial = normalizeTarget(target);
  const scope = initial.target_url ? applicationPath(new URL(initial.target_url)) : '/';
  const valid = results.filter(result => {
    if (['raw_output', 'scan_error', 'lan_scope', 'lan_host_discovery', 'scan_evidence', 'network_context', 'network_link'].includes(result.result_type)) return false;
    let data;
    try { data = typeof result.result_data === 'string' ? JSON.parse(result.result_data) : result.result_data || {}; } catch { return false; }
    if (!data || typeof data !== 'object' || Array.isArray(data)) return false;
    if (!data.url) return !['http_probe', 'technology_detection'].includes(result.result_type);
    try {
      const url = new URL(data.url);
      if (url.origin !== initial.origin || url.username || url.password) return false;
      if (['http_probe', 'technology_detection'].includes(result.result_type)) {
        if (data.status_code !== undefined && (Number(data.status_code) < 200 || Number(data.status_code) >= 400 || !Number.isFinite(Number(data.status_code)))) return false;
        return isWithinPath(url.pathname, scope) || result.source_tool === 'http-discovery' && data.requested_url === initial.target_url;
      }
      return true;
    } catch { return false; }
  });
  const profile = refineTargetProfile(initial, valid);
  const observations = [];
  for (const result of valid) {
    let data;
    try { data = typeof result.result_data === 'string' ? JSON.parse(result.result_data) : result.result_data || {}; } catch { continue; }
    if (!['http_probe', 'technology_detection'].includes(result.result_type)) continue;
    if (!data.url) continue;
    let url;
    try { url = new URL(data.url); } catch { continue; }
    if (url.origin !== initial.origin) continue;
    if (data.status_code && (data.status_code < 200 || data.status_code >= 400)) continue;
    const technologies = Array.isArray(data.technologies) ? data.technologies : String(data.technologies || '').split(',');
    const title = String(data.title || '');
    const body = String(data.body || '');
    const brand = /Damn Vulnerable Web Application|\bDVWA\b/i.test(title);
    const assets = assetPath(url, body);
    const product = /Damn Vulnerable Web Application/i.test(body.replace(/<title[^>]*>[\s\S]*?<\/title>/gi, ''));
    const plugin = technologies.some(technology => /^(?:DVWA|Damn[ -]Vulnerable[ -]Web[ -]Application)$/i.test(
      String(typeof technology === 'string' ? technology.replace(/\[.*$/, '') : technology?.name || '').trim()));
    if (!(plugin || brand && (assets || product))) continue;
    const path = applicationPath(url, body);
    if (!isWithinPath(new URL(initial.target_url).pathname, path) && !(result.source_tool === 'http-discovery' && data.requested_url === initial.target_url)) continue;
    observations.push({ base_url: `${url.origin}${path.replace(/\/$/, '')}`, confidence: plugin ? 0.95 : 0.9,
      strength: brand && (assets || product) ? 2 : 1,
      evidence: { source_tool: result.source_tool, scan_task_id: result.scan_task_id || null,
        url: url.href, title, signals: [plugin && 'technology_plugin', brand && 'page_title', assets && 'product_assets', product && 'product_name'].filter(Boolean) } });
  }
  observations.sort((first, second) => second.strength - first.strength || second.base_url.length - first.base_url.length || second.confidence - first.confidence);
  const selected = observations[0];
  const supporting = observations.filter(observation => observation.base_url === selected?.base_url);
  const application = selected ? { name: 'dvwa', confidence: Math.max(...supporting.map(observation => observation.confidence)), base_url: selected.base_url } : null;
  const evidence = supporting.map(observation => observation.evidence);
  return { ...profile, ...(application ? { target_class: 'dvwa', is_dvwa: true,
    base_url: application.base_url, base_path: new URL(application.base_url + '/').pathname } : {}),
    application, evidence, source: application ? 'scan-evidence' : profile.source,
    detected_at: new Date().toISOString() };
}

export async function probeTarget(target, { request = fetch, timeoutMs = 8000, signal } = {}) {
  const profile = normalizeTarget(target);
  if (!profile.origin) throw new Error('HTTP discovery requires a single host or HTTP URL');
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  signal?.addEventListener('abort', onAbort, { once: true });
  if (signal?.aborted) onAbort();
  const timer = setTimeout(onAbort, timeoutMs);
  const results = [];
  try {
    let url = new URL(profile.target_url);
    for (let redirects = 0; redirects <= 5; redirects++) {
      if (url.origin !== profile.origin || url.username || url.password) throw new Error('HTTP discovery redirected outside the selected target');
      const response = await request(url, { signal: controller.signal, redirect: 'manual' });
      let body = '';
      const reader = response.body?.getReader();
      if (reader) {
        const decoder = new TextDecoder();
        let bytes = 0;
        try {
          while (bytes < 65536) {
            const chunk = await reader.read();
            if (chunk.done) break;
            body += decoder.decode(chunk.value.subarray(0, 65536 - bytes), { stream: true });
            bytes += chunk.value.length;
          }
        } finally { await reader.cancel(); }
      } else body = (await response.text()).slice(0, 65536);
      results.push({ result_type: 'http_probe', source_tool: 'http-discovery', severity: 'info', result_data: {
        url: url.href, requested_url: profile.target_url, status_code: response.status,
        title: body.match(/<title[^>]*>([\s\S]*?)<\/title>/i)?.[1]?.trim() || '', body,
      } });
      if (response.status >= 300 && response.status < 400 && response.headers.get('location')) {
        url = new URL(response.headers.get('location'), url);
        continue;
      }
      return results;
    }
    throw new Error('HTTP discovery redirect limit exceeded');
  } catch (error) {
    throw new Error(`HTTP discovery failed: ${error.cause?.message || error.message}`, { cause: error });
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', onAbort);
  }
}

export function loadTargetProfile(db, target, scanTaskIds = []) {
  const ids = (Array.isArray(scanTaskIds) ? scanTaskIds : String(scanTaskIds || '').split(',')).filter(Boolean);
  const fields = 'id, scan_task_id, target, scan_type, status, completed_at, started_at, created_at';
  const tasks = ids.length ? db.prepare(`SELECT ${fields} FROM scan_tasks
    WHERE scan_task_id IN (${ids.map(() => '?').join(',')})`).all(...ids) : db.prepare(`SELECT ${fields} FROM scan_tasks
    WHERE target = ? ORDER BY julianday(COALESCE(completed_at, started_at, created_at)) DESC, id DESC LIMIT 32`).all(target);
  const timestamp = task => {
    const value = task.completed_at || task.started_at || task.created_at || '';
    return Date.parse(value + (/[zZ]|[+-]\d\d:\d\d$/.test(value) ? '' : 'Z'));
  };
  const selected = tasks.filter(task => task.target === target && Date.now() - timestamp(task) >= 0
    && Date.now() - timestamp(task) < 30 * 60 * 1000)
    .sort((first, second) => timestamp(second) - timestamp(first) || second.id - first.id);
  let observed = false;
  const results = selected.flatMap(task => {
    const values = db.prepare('SELECT * FROM scan_results WHERE scan_task_id = ?').all(task.scan_task_id);
    const probes = task.scan_type === 'app_discovery' || values.some(result => ['http_probe', 'technology_detection'].includes(result.result_type));
    const omitProbes = observed;
    if (probes) observed = true;
    if (!['COMPLETED', 'PARTIAL'].includes(task.status)) return [];
    return omitProbes ? values.filter(result => !['http_probe', 'technology_detection'].includes(result.result_type)) : values;
  });
  return buildDiscoveredProfile(target, results);
}

export async function discoverTargetProfile(db, target, scanTaskIds = [], options = {}) {
  const profile = loadTargetProfile(db, target, scanTaskIds);
  if (profile.application || !profile.origin) return profile;
  const results = await probeTarget(target, options);
  return buildDiscoveredProfile(target, results);
}
