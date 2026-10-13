// Public errors must not expose provider response bodies (which may echo keys).
export function llmFailure(result) {
  const error = String(result?.error || '');
  const status = Number(error.match(/^LLM API (\d{3})\b/)?.[1]);
  let code = 'LLM_SERVICE_ERROR';
  let message = '模型服务调用失败，请检查服务地址和模型配置';
  if (/^No LLM API key/.test(error)) {
    code = 'LLM_NOT_CONFIGURED'; message = '未配置模型服务密钥，请在系统配置中设置';
  } else if (status === 401 || status === 403) {
    code = 'LLM_AUTH_ERROR'; message = '模型服务认证或权限校验失败，请检查密钥和模型访问权限';
  } else if (status === 402 || status === 429) {
    code = 'LLM_QUOTA_ERROR'; message = '模型服务额度不足或请求受限，请检查额度或稍后重试';
  } else if (/timed out/i.test(error)) {
    code = 'LLM_TIMEOUT'; message = '模型服务请求超时，请稍后重试';
  } else if (/^LLM request failed/.test(error)) {
    code = 'LLM_NETWORK_ERROR'; message = '无法连接模型服务，请检查服务地址和网络';
  } else if (/^LLM returned empty/.test(error)) {
    code = 'LLM_EMPTY_RESPONSE'; message = '模型服务返回空内容，请检查模型配置或重试';
  }
  return { ok: false, code, error: message };
}
