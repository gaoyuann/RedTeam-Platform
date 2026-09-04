/**
 * genericWebTargetAdapter.js
 * Generic Web Target Adapter — 为通用 HTTP/HTTPS Web 目标提供标准上下文。
 *
 * Migrated from RedTeam-Edu: backend/src/runtime/targetAdapters/genericWebTargetAdapter.js
 * Adapted: wordlist paths use container mount points
 *
 * 适用于 target_class = 'web_url' 或 'local_ip' 的目标。
 * 注意：DVWA 专属变量（dvwa_login_url, sqli_url 等）已移至 dvwaTargetAdapter，
 *       此适配器仅输出通用 Web 上下文。
 */

/**
 * 构建通用 Web 标准上下文
 * @param {object} targetProfile - 由 targetProfileResolver 解析的目标
 * @returns {object} 标准上下文字典
 */
export function buildWebContext(targetProfile) {
  const host = targetProfile.host || 'localhost';
  const port = targetProfile.port || 80;
  const raw = targetProfile.raw || '';
  const scheme = raw.startsWith('https') ? 'https' : 'http';
  const portSuffix = (port === 80 || port === 443) ? '' : `:${port}`;
  const base = `${scheme}://${host}${portSuffix}`;

  // SSH/remote credentials for Linux targets — configurable via env vars
  // REDTEAM_SSH_USER / REDTEAM_SSH_PASS override the defaults
  const username = process.env.REDTEAM_SSH_USER || targetProfile.username || 'root';
  const password = process.env.REDTEAM_SSH_PASS || targetProfile.password || 'qwer1234';

  return {
    host,
    port: String(port),
    scheme,
    base_url: base,
    target_url: base,
    target_class: targetProfile.target_class || 'web_url',
    username,
    password,

    // Web 通用路径（不包含任何 DVWA 专属路径，DVWA 变量在 dvwaTargetAdapter 中）
    login_url: `${base}/login`,
    admin_url: `${base}/admin`,
    api_base_url: `${base}/api`,
    signup_url: `${base}/signup`,
    reset_password_url: `${base}/reset-password`,

    // 字典路径（容器挂载点）
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

/**
 * 检查目标是否适合通用 Web Playbook
 */
export function checkWebCompatibility(targetProfile) {
  const compatClasses = new Set(['web_url', 'local_ip', 'dvwa']);
  if (compatClasses.has(targetProfile.target_class)) {
    return { ok: true, reason: null };
  }
  return {
    ok: false,
    reason: `Web Playbook requires target_class in [web_url, local_ip, dvwa], got '${targetProfile.target_class}'`,
  };
}

export default { buildWebContext, checkWebCompatibility };
