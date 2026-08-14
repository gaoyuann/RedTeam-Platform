/**
 * targetAdapters/index.js
 * Target Adapter 统一入口 — 根据 target_class 分发到对应 Adapter。
 *
 * Migrated from RedTeam-Edu: backend/src/runtime/targetAdapters/index.js
 *
 * 支持的 target_class：
 *   dvwa, local_ip, web_url  → dvwaTargetAdapter / genericWebTargetAdapter
 *   windows_ad               → windowsHostTargetAdapter
 *   cloud                    → cloudTargetAdapter
 *   local_hash, subdomain    → genericWebTargetAdapter (降级兼容)
 */

import { buildDvwaContext, checkDvwaCompatibility } from './dvwaTargetAdapter.js';
import { buildWebContext, checkWebCompatibility } from './genericWebTargetAdapter.js';
import { buildWindowsContext, checkWindowsCompatibility } from './windowsHostTargetAdapter.js';
import { buildCloudContext, checkCloudCompatibility } from './cloudTargetAdapter.js';

/**
 * 根据 targetProfile.target_class 构建标准上下文
 * @param {object} targetProfile - 由 targetProfileResolver 解析的目标
 * @param {object} [dvwaProfile] - Playbook 中的 dvwa_profile 字段（可选）
 * @returns {object} 标准上下文字典
 */
export function buildContextForTarget(targetProfile, dvwaProfile = {}) {
  switch (targetProfile.target_class) {
    case 'dvwa':
      return buildDvwaContext({
        host: targetProfile.host,
        port: targetProfile.port,
        dvwaProfile,
      });
    case 'local_ip':
    case 'linux_host':
    case 'web_url':
      // 如果有 dvwa_profile，优先使用 DVWA 上下文
      if (dvwaProfile && dvwaProfile.base_url) {
        return buildDvwaContext({ host: targetProfile.host, port: targetProfile.port, dvwaProfile });
      }
      return buildWebContext(targetProfile);
    case 'windows_ad':
      return buildWindowsContext(targetProfile);
    case 'cloud':
      return buildCloudContext(targetProfile);
    case 'local_hash':
    case 'subdomain':
    default:
      return buildWebContext(targetProfile);
  }
}

/**
 * 检查 Playbook 要求的目标类型与实际目标是否兼容
 * @param {string} requiredClass - Playbook 要求的 target_class
 * @param {object} targetProfile - 实际目标的 profile
 * @returns {{ ok: boolean, reason: string|null }}
 */
export function checkTargetCompatibility(requiredClass, targetProfile) {
  switch (requiredClass) {
    case 'dvwa':
    case 'local_ip':
    case 'linux_host':
    case 'web_url':
      return checkDvwaCompatibility(targetProfile);
    case 'windows_ad':
      return checkWindowsCompatibility(targetProfile);
    case 'cloud':
      return checkCloudCompatibility(targetProfile);
    default:
      return checkWebCompatibility(targetProfile);
  }
}

export default { buildContextForTarget, checkTargetCompatibility };
