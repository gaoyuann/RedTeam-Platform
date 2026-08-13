/**
 * windowsHostTargetAdapter.js
 * Windows/AD Target Adapter — 为 Windows Active Directory 目标提供标准上下文。
 *
 * Migrated from RedTeam-Edu: backend/src/runtime/targetAdapters/windowsHostTargetAdapter.js
 * Adapted: wordlist paths use container mount points, evidence_dir uses /tmp/redteam-output
 *
 * 适用于 target_class = 'windows_ad' 的目标。
 * 此类 Playbook 在 DVWA/Web 目标上应返回 SKIPPED_TARGET_MISMATCH。
 */

/**
 * 构建 Windows/AD 标准上下文
 * @param {object} targetProfile - 由 targetProfileResolver 解析的目标
 * @returns {object} 标准上下文字典
 */
export function buildWindowsContext(targetProfile) {
  const host = targetProfile.host || '192.168.1.1';
  const port = targetProfile.port || 445;

  return {
    host,
    port: String(port),
    scheme: 'smb',
    base_url: `smb://${host}`,
    target_url: `smb://${host}`,
    target_class: 'windows_ad',

    // Windows/AD 专用字段
    domain: targetProfile.domain || 'WORKGROUP',
    smb_port: '445',
    winrm_port: '5985',
    ldap_port: '389',
    rdp_port: '3389',

    // 凭据（教学演示用默认值）
    username: 'administrator',
    password: 'Password123!',
    hash: '',

    // 字典路径（容器挂载点）
    wordlist_small: '/usr/share/wordlists/dirb/small.txt',
    wordlist_small_users: '/usr/share/wordlists/metasploit/unix_users.txt',
    wordlist_small_passwords: '/usr/share/wordlists/metasploit/unix_passwords.txt',

    // 工具目录
    evidence_dir: '/tmp/redteam-output',
    nuclei_template_dir: '/root/nuclei-templates',

    // 通用字段（保持兼容）
    login_url: '',
    dvwa_login_url: '',
    sqli_url: '',
    dvwa_sqli_url: '',
    dvwa_cookie: '',
  };
}

/**
 * 检查目标是否适合 Windows/AD Playbook
 */
export function checkWindowsCompatibility(targetProfile) {
  if (targetProfile.target_class === 'windows_ad') {
    return { ok: true, reason: null };
  }
  return {
    ok: false,
    reason: `Windows/AD Playbook requires target_class 'windows_ad', got '${targetProfile.target_class}'`,
  };
}

export default { buildWindowsContext, checkWindowsCompatibility };
