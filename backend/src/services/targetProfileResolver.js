/**
 * targetProfileResolver.js
 * Resolves a raw target string into a structured target profile.
 * Used by preflightGate.js to determine target_class for compatibility checks.
 *
 * Migrated from RedTeam-Edu: backend/src/runtime/targetProfileResolver.js
 *
 * Target classes:
 *   dvwa       — localhost / 127.0.0.1 / known DVWA ports
 *   local_ip   — private IP ranges (10.x, 192.168.x, 172.16-31.x)
 *   web_url    — http/https URL pointing to a web server
 *   local_hash — local file path (hash cracking)
 *   windows_ad — Windows/AD domain or hostname
 *   cloud      — cloud provider endpoints
 *   subdomain  — domain name for subdomain enumeration
 *   unknown    — cannot be classified
 */

const DVWA_HOSTS = new Set(['localhost', '127.0.0.1', '0.0.0.0']);
const DVWA_PORTS = new Set([8080, 80, 3000]);

const PRIVATE_IP_PATTERNS = [
  /^10\.\d+\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
];

const CLOUD_PATTERNS = [
  /amazonaws\.com/i,
  /azure\.com/i,
  /googleapis\.com/i,
  /digitalocean\.com/i,
  /cloud\./i,
];

const WINDOWS_PATTERNS = [
  /\.local$/i,
  /\.corp$/i,
  /\.internal$/i,
  /\.ad$/i,
  /^dc\d*/i,
  /^win\d*/i,
  /^server\d*/i,
];

// ── Application-level URL path patterns ───────────────────────────────────
const GRAPHQL_PATH_PATTERN   = /\/(graphql|gql)/i;
const REST_API_PATH_PATTERN  = /^\/?api\/v\d+\//i;
const WEB_APP_PATH_PATTERNS  = [/^\/?api\//i, /\/graphql/i, /\/v[12]\//i];

/**
 * Resolve a target string to a target profile object.
 * @param {string} target - raw target (URL, IP, hostname, file path)
 * @param {object} [hints] - optional hints from caller (e.g. playbook's targetType)
 * @param {string} [hints.preferredTargetClass] - if set, skip heuristic classification
 * @returns {{ target_class: string, host: string, port: number|null, is_dvwa: boolean, raw: string }}
 */
export function resolveTargetProfile(target, hints = {}) {
  if (!target || typeof target !== 'string') {
    return { target_class: 'unknown', host: '', port: null, is_dvwa: false, raw: target || '' };
  }

  const raw = target.trim();
  const preferredClass = hints.preferredTargetClass || null;

  // Local file path (hash cracking)
  if (raw.startsWith('/') || raw.startsWith('./') || raw.match(/^[A-Za-z]:\\/)) {
    return { target_class: 'local_hash', host: raw, port: null, is_dvwa: false, raw };
  }

  // Parse URL
  let parsed = null;
  try {
    const urlStr = raw.startsWith('http') ? raw : `http://${raw}`;
    parsed = new URL(urlStr);
  } catch (_) {
    // Not a valid URL
  }

  const host = parsed ? parsed.hostname : raw.split(':')[0];
  const port = parsed ? (parseInt(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80)) : (parseInt(raw.split(':')[1]) || null);

  // Preferred class override (trust playbook context over heuristic)
  // e.g. cloud playbook targeting localstack at 127.0.0.1:4566
  if (preferredClass === 'cloud' && DVWA_HOSTS.has(host)) {
    return { target_class: 'cloud', host, port, is_dvwa: false, raw };
  }

  // DVWA check
  if (DVWA_HOSTS.has(host) || (DVWA_PORTS.has(port) && DVWA_HOSTS.has(host))) {
    return { target_class: 'dvwa', host, port, is_dvwa: true, raw };
  }

  // If the playbook hints that this is a Windows/AD or Cloud target,
  // and the target is a bare private IP, trust the playbook's context
  if (preferredClass === 'windows_ad' && PRIVATE_IP_PATTERNS.some(p => p.test(host))) {
    return { target_class: 'windows_ad', host, port, is_dvwa: false, raw };
  }
  if (preferredClass === 'cloud' && PRIVATE_IP_PATTERNS.some(p => p.test(host))) {
    return { target_class: 'cloud', host, port, is_dvwa: false, raw };
  }

  // HTTP/HTTPS URL -- detect application-level classes from path patterns FIRST
  // (path-based classification like /graphql, /api/v1 takes priority over IP-based)
  if (raw.startsWith('http://') || raw.startsWith('https://')) {
    const pathName = parsed ? parsed.pathname : '';

    // GraphQL API endpoint
    if (GRAPHQL_PATH_PATTERN.test(pathName)) {
      return { target_class: 'graphql_api', host, port, is_dvwa: false, raw };
    }

    // REST API with versioned path (/api/v1/...)
    if (REST_API_PATH_PATTERN.test(pathName)) {
      return { target_class: 'rest_api', host, port, is_dvwa: false, raw };
    }

    // Web application with common API/version paths
    if (WEB_APP_PATH_PATTERNS.some(p => p.test(pathName))) {
      return { target_class: 'web_app', host, port, is_dvwa: false, raw };
    }

    // Generic web URL fallback (even for private IPs with HTTP URL)
    // If it's an http:// IP, it's more useful to classify as web_url than local_ip
    if (!PRIVATE_IP_PATTERNS.some(p => p.test(host))) {
      return { target_class: 'web_url', host, port, is_dvwa: false, raw };
    }
    // Private IP with HTTP URL but no special path → still useful as web_url
    return { target_class: 'web_url', host, port, is_dvwa: false, raw };
  }

  // Private IP (non-URL form, e.g. "192.168.1.1" or "10.0.0.5")
  if (PRIVATE_IP_PATTERNS.some(p => p.test(host))) {
    return { target_class: 'local_ip', host, port, is_dvwa: false, raw };
  }

  // Cloud
  if (preferredClass !== 'subdomain' && CLOUD_PATTERNS.some(p => p.test(host))) {
    return { target_class: 'cloud', host, port, is_dvwa: false, raw };
  }

  // Windows/AD domain patterns
  if (preferredClass !== 'subdomain' && WINDOWS_PATTERNS.some(p => p.test(host))) {
    return { target_class: 'windows_ad', host, port, is_dvwa: false, raw };
  }

  // Domain name (for subdomain enumeration)
  if (host.includes('.') && !host.match(/^\d+\.\d+\.\d+\.\d+$/)) {
    return { target_class: 'subdomain', host, port, is_dvwa: false, raw };
  }

  return { target_class: 'unknown', host, port, is_dvwa: false, raw };
}

/**
 * Derive preferredTargetClass from a playbook's targetType array.
 * Used by preflightGate and executionEngine to correctly classify
 * private IPs that point to AD/Cloud environments.
 * @param {string[]|string} targetType - playbook's targetType field
 * @returns {string|null}
 */
export function derivePreferredClass(targetType) {
  const types = Array.isArray(targetType) ? targetType : (targetType ? [targetType] : []);
  if (types.some(t => ['windows_host', 'ad_domain', 'windows_ad'].includes(t))) {
    return 'windows_ad';
  }
  if (types.some(t => t === 'cloud' || t === 'cloud_target')) {
    return 'cloud';
  }
  if (types.some(t => t === 'domain')) {
    return 'subdomain';
  }
  return null;
}

/**
 * Check if a playbook's targetType array is compatible with a resolved target_class.
 * Implements the compatibility matrix from the old preflightGate.
 * @param {string[]} targetTypes - playbook's targetType array
 * @param {string} targetClass - resolved target_class
 * @returns {{ ok: boolean, reason: string|null }}
 */
export function checkTargetTypeCompatibility(targetTypes, targetClass) {
  if (!targetTypes || targetTypes.length === 0) {
    return { ok: true, reason: null }; // no restriction
  }

  const compatible = targetTypes.some(t =>
    t === targetClass ||
    t === 'any' ||
    (t === 'dvwa' && (targetClass === 'dvwa' || targetClass === 'local_ip')) ||
    (t === 'web' && (targetClass === 'dvwa' || targetClass === 'web_url' || targetClass === 'local_ip')) ||
    (t === 'web_url' && (targetClass === 'dvwa' || targetClass === 'web_url' || targetClass === 'local_ip')) ||
    (t === 'local_file' && targetClass === 'local_hash') ||
    (['windows_host', 'ad_domain', 'windows_ad'].includes(t) && ['windows_ad', 'local_ip'].includes(targetClass)) ||
    (t === 'cloud' && ['cloud', 'local_ip'].includes(targetClass)) ||
    (t === 'domain' && targetClass === 'subdomain')
  );

  if (compatible) {
    return { ok: true, reason: null };
  }
  return {
    ok: false,
    reason: `targetType [${targetTypes.join(', ')}] not compatible with target_class '${targetClass}'`,
  };
}

/**
 * Refine a target profile based on scan results.
 * Can upgrade a target class (e.g., web_url -> rest_api if whatweb detects Swagger).
 * @param {object} initialProfile - The profile from resolveTargetProfile
 * @param {object[]} scanResults - Array of scan result objects from a scan execution
 * @returns {object} A new or updated target profile with possible class upgrade
 */
export function refineTargetProfile(initialProfile, scanResults) {
  if (!Array.isArray(scanResults) || scanResults.length === 0) {
    return { ...initialProfile, source: 'initial' };
  }

  let refinedClass = initialProfile.target_class;
  let source = 'initial';

  for (const result of scanResults) {
    const data = result.result_data || {};
    const detail = (data.detail || data.output || '').toLowerCase();

    // whatweb detected Swagger/OpenAPI  -> rest_api
    if (/swagger|openapi|\/v3\/api-docs/.test(detail)) {
      refinedClass = 'rest_api';
      source = 'whatweb-scan';
      break;
    }

    // whatweb detected GraphiQL/GraphQL Playground  -> graphql_api
    if (/graphiql|graphql playground|apollo studio/.test(detail)) {
      refinedClass = 'graphql_api';
      source = 'whatweb-scan';
      break;
    }

    // Generic SPA indicators from httpx/whatweb  -> spa_app
    if (/react|angular|vue|svelte|single.*page|spa/i.test(detail)) {
      refinedClass = 'spa_app';
      source = 'scan-detected';
      break;
    }

    // REST API detected via versioned endpoint patterns
    if (/api\/v\d/.test(detail)) {
      refinedClass = 'rest_api';
      source = 'api-pattern-scan';
      break;
    }
  }

  return {
    ...initialProfile,
    target_class: refinedClass,
    source,
  };
}

export default { resolveTargetProfile, derivePreferredClass, checkTargetTypeCompatibility, refineTargetProfile };
