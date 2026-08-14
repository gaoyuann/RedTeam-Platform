/**
 * commandTemplateRenderer.js
 * Command Template Renderer — 统一替换 argsTemplate 中的上下文变量。
 *
 * Migrated from RedTeam-Edu: backend/src/runtime/commandTemplateRenderer.js
 * Only the core rendering logic is migrated; context building is handled by targetAdapters.
 *
 * 支持的变量格式（由 targetAdapters 提供上下文）：
 *   {{host}}, {{port}}, {{base_url}}, {{target_url}}, {{login_url}},
 *   {{dvwa_login_url}}, {{sqli_url}}, {{dvwa_sqli_url}}, {{dvwa_cookie}},
 *   {{wordlist_small}}, {{wordlist_small_users}}, {{wordlist_small_passwords}},
 *   {{nuclei_template_dir}}, {{evidence_dir}}, {{domain}}, {{scheme}},
 *   {{target_class}}, {{username}}, {{password}}, {{domain}}, {{smb_port}},
 *   {{winrm_port}}, {{aws_region}}, {{aws_profile}}, {{s3_bucket}}, etc.
 */

// 必须阻断的未替换变量模式（渲染后检测）
const UNRESOLVED_PATTERNS = [
  /^<[a-z_]+>$/i,
  /\{\{[a-z_]+\}\}/i,
  /^target\.com$/i,
  /^target:\d+$/i,
  /^target$/i,
  /^example\.com$/i,
  /^CHANGE_ME$/,
  /^REPLACE_ME$/,
  /^http:\/\/target/i,
  /^https:\/\/target/i,
];

/**
 * 检查单个 token 是否为未替换变量
 * @param {string} token
 * @returns {boolean}
 */
export function isUnresolved(token) {
  if (typeof token !== 'string') return false;
  return UNRESOLVED_PATTERNS.some(p => p.test(token));
}

/**
 * 渲染单个 token，将 {{var}} 替换为 context[var]
 * @param {string} token
 * @param {object} context
 * @returns {string} 渲染后的 token
 */
function renderToken(token, context) {
  if (typeof token !== 'string') return String(token);
  return token.replace(/\{\{([a-z_]+)\}\}/gi, (match, key) => {
    const val = context[key];
    return val !== undefined ? String(val) : match; // 未找到则保留原始占位符
  });
}

/**
 * 渲染整个 argsTemplate 数组
 * @param {string[]} argsArray - 原始参数数组
 * @param {object} context - 上下文变量字典（由 buildContextForTarget 生成）
 * @returns {{ rendered: string[], unresolvedTokens: string[] }}
 */
export function renderCommand(argsArray, context) {
  if (!Array.isArray(argsArray)) argsArray = [];
  const rendered = [];
  const unresolvedTokens = [];

  for (const token of argsArray) {
    const tokenStr = String(token);
    const renderedToken = renderToken(tokenStr, context);

    // 检查渲染后是否仍有未替换变量
    if (isUnresolved(renderedToken)) {
      unresolvedTokens.push(renderedToken);
    }
    rendered.push(renderedToken);
  }

  return { rendered, unresolvedTokens };
}

/**
 * 验证 URL 格式是否合法
 * @param {string} url
 * @returns {boolean}
 */
export function isValidUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

export default { renderCommand, isUnresolved, isValidUrl };
