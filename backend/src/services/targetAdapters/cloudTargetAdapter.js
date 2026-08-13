/**
 * cloudTargetAdapter.js
 * Cloud Target Adapter — 为 AWS/Cloud 目标提供标准上下文。
 *
 * Migrated from RedTeam-Edu: backend/src/runtime/targetAdapters/cloudTargetAdapter.js
 * Adapted: wordlist paths use container mount points, evidence_dir uses /tmp/redteam-output
 *
 * 适用于 target_class = 'cloud' 的目标。
 * 此类 Playbook 在 DVWA/Web/Windows 目标上应返回 SKIPPED_TARGET_MISMATCH。
 */

/**
 * 构建 Cloud 标准上下文
 * @param {object} targetProfile - 由 targetProfileResolver 解析的目标
 * @returns {object} 标准上下文字典
 */
export function buildCloudContext(targetProfile) {
  const host = targetProfile.host || 'aws-account-id.example.com';

  return {
    host,
    port: '443',
    scheme: 'https',
    base_url: `https://${host}`,
    target_url: `https://${host}`,
    target_class: 'cloud',

    // Cloud/AWS 专用字段
    aws_region: 'us-east-1',
    aws_profile: 'default',
    aws_account_id: '123456789012',
    s3_bucket: 'target-bucket',

    // 字典路径（容器挂载点）
    wordlist_small: '/usr/share/wordlists/dirb/small.txt',
    wordlist_small_users: '/usr/share/wordlists/metasploit/unix_users.txt',
    wordlist_small_passwords: '/usr/share/wordlists/metasploit/unix_passwords.txt',

    // 工具目录
    evidence_dir: '/tmp/redteam-output',
    nuclei_template_dir: '/root/nuclei-templates',

    // 通用字段（保持兼容）
    domain: host,
    login_url: '',
    dvwa_login_url: '',
    sqli_url: '',
    dvwa_sqli_url: '',
    dvwa_cookie: '',
  };
}

/**
 * 检查目标是否适合 Cloud Playbook
 */
export function checkCloudCompatibility(targetProfile) {
  if (targetProfile.target_class === 'cloud') {
    return { ok: true, reason: null };
  }
  return {
    ok: false,
    reason: `Cloud Playbook requires target_class 'cloud', got '${targetProfile.target_class}'`,
  };
}

export default { buildCloudContext, checkCloudCompatibility };
