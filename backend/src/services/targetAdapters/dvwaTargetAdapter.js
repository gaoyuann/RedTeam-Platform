/**
 * dvwaTargetAdapter.js
 * DVWA Target Adapter — 为 DVWA 靶机提供标准上下文字段。
 *
 * Migrated from RedTeam-Edu: backend/src/runtime/targetAdapters/dvwaTargetAdapter.js
 * Adapted: wordlist paths use container mount points (/usr/share/wordlists/)
 *
 * 输出的标准上下文（Standard Context）用于 commandTemplateRenderer 渲染变量。
 * 适用于 target_class = 'dvwa' 或 'local_ip' 的目标。
 */

/**
 * 构建 DVWA 标准上下文
 * @param {object} opts
 * @param {string} opts.host - 目标主机（如 "localhost", "172.17.0.2"）
 * @param {number} opts.port - 目标端口（如 8080, 80）
 * @param {string} [opts.scheme] - 协议（默认 "http"）
 * @param {string} [opts.dvwaCookie] - DVWA session cookie
 * @param {object} [opts.dvwaProfile] - Playbook 中的 dvwa_profile 字段
 * @returns {object} 标准上下文字典
 */
export function buildDvwaContext({ host, port, scheme = 'http', dvwaCookie, dvwaProfile = {} } = {}) {
  const h = dvwaProfile.host || host || 'localhost';
  const p = dvwaProfile.port || port || 8080;
  const s = dvwaProfile.scheme || scheme || 'http';
  const portSuffix = (p === 80 || p === 443) ? '' : `:${p}`;
  const base = dvwaProfile.base_url || `${s}://${h}${portSuffix}`;

  return {
    // 基础字段
    host: h,
    port: String(p),
    scheme: s,
    base_url: base,
    target_url: base,
    target_class: 'dvwa',

    // DVWA 专用字段
    login_url: dvwaProfile.login_url || `${base}/login.php`,
    dvwa_login_url: dvwaProfile.login_url || `${base}/login.php`,
    sqli_url: dvwaProfile.sqli_url || `${base}/vulnerabilities/sqli/?id=1&Submit=Submit`,
    dvwa_sqli_url: dvwaProfile.sqli_url || `${base}/vulnerabilities/sqli/?id=1&Submit=Submit`,
    dvwa_cookie: dvwaCookie || dvwaProfile.dvwa_cookie || 'PHPSESSID=placeholder; security=low',
    security_level: dvwaProfile.security_level || 'low',

    // 字典路径（容器挂载点）
    wordlist_small: '/usr/share/wordlists/dirb/small.txt',
    wordlist_medium: '/usr/share/wordlists/dirb/common.txt',
    wordlist_small_users: '/usr/share/wordlists/metasploit/unix_users.txt',
    wordlist_small_passwords: '/usr/share/wordlists/metasploit/unix_passwords.txt',

    // 工具目录
    nuclei_template_dir: '/root/nuclei-templates',
    evidence_dir: '/tmp/redteam-output',

    // 域名（DVWA 无真实域名，使用 host）
    domain: h,
  };
}

/**
 * 检查目标是否适合 DVWA 类 Playbook
 * @param {object} targetProfile - 由 targetProfileResolver 解析的目标
 * @returns {{ ok: boolean, reason: string|null }}
 */
export function checkDvwaCompatibility(targetProfile) {
  const compatClasses = new Set(['dvwa', 'local_ip', 'web_url']);
  if (compatClasses.has(targetProfile.target_class)) {
    return { ok: true, reason: null };
  }
  return {
    ok: false,
    reason: `DVWA Playbook requires target_class in [dvwa, local_ip, web_url], got '${targetProfile.target_class}'`,
  };
}

export default { buildDvwaContext, checkDvwaCompatibility };
