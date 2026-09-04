/**
 * applicationTargetAdapter.js
 * Application Target Adapter -- 为应用程序级别的目标提供标准上下文。
 *
 * 适用于 target_class = 'web_app', 'rest_api', 'graphql_api', 'spa_app' 的目标。
 * 提供应用层上下文变量：API 路径、认证方式、GraphQL 端点等。
 */

export function buildApplicationContext(targetProfile, appMetadata = {}) {
  const host = targetProfile.host || 'localhost';
  const port = targetProfile.port || 80;
  const raw = targetProfile.raw || '';
  const scheme = raw.startsWith('https') ? 'https' : 'http';
  const portSuffix = (port === 80 || port === 443) ? '' : `:${port}`;
  const base = `${scheme}://${host}${portSuffix}`;

  return {
    // 基础字段
    host,
    port: String(port),
    scheme,
    base_url: base,
    target_url: base,
    target_class: targetProfile.target_class || 'web_app',

    // 应用层通用字段
    api_base_url: appMetadata.apiBasePath || `${base}/api`,
    auth_method: appMetadata.authMethod || 'unknown',   // basic/bearer/oauth2/jwt/cookie
    auth_endpoint: appMetadata.authEndpoint || null,
    content_type: appMetadata.contentType || 'application/json',

    // GraphQL 特有
    graphql_endpoint: appMetadata.graphqlEndpoint || (targetProfile.target_class === 'graphql_api' ? `${base}/graphql` : null),
    introspection_enabled: appMetadata.introspectionEnabled || false,

    // REST API 特有
    api_base_path: appMetadata.apiBasePath || '/api',
    swagger_url: appMetadata.swaggerUrl || `${base}/swagger-ui.html`,
    openapi_url: appMetadata.openapiUrl || `${base}/v3/api-docs`,

    // Web 通用路径
    login_url: `${base}/login`,
    admin_url: `${base}/admin`,
    signup_url: `${base}/signup`,

    // 字典路径
    wordlist_small: '/usr/share/wordlists/dirb/small.txt',
    wordlist_medium: '/usr/share/wordlists/dirb/common.txt',
    wordlist_small_users: '/usr/share/wordlists/metasploit/unix_users.txt',
    wordlist_small_passwords: '/usr/share/wordlists/metasploit/unix_passwords.txt',

    // 工具目录
    nuclei_template_dir: '/root/nuclei-templates',
    evidence_dir: '/tmp/redteam-output',

    domain: host,
  };
}

export function checkAppCompatibility(targetProfile) {
  const compatClasses = new Set(['web_app', 'rest_api', 'graphql_api', 'spa_app', 'web_url', 'local_ip']);
  if (compatClasses.has(targetProfile.target_class)) {
    return { ok: true, reason: null };
  }
  return {
    ok: false,
    reason: `Application Playbook requires target_class in [web_app, rest_api, graphql_api, spa_app, web_url, local_ip], got '${targetProfile.target_class}'`,
  };
}

export default { buildApplicationContext, checkAppCompatibility };
