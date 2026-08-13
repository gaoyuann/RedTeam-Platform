import { getDb } from '../db/connection.js';

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MODEL = 'deepseek-chat';
const DEFAULT_BASE_URL = 'https://api.deepseek.com/v1';

async function getLlmConfig() {
  const db = getDb();
  const rows = db.prepare(
    "SELECT config_key, config_value FROM system_config WHERE category = 'llm'"
  ).all();

  const cfg = {};
  for (const row of rows) {
    try {
      cfg[row.config_key] = JSON.parse(row.config_value);
    } catch {
      cfg[row.config_key] = row.config_value;
    }
  }

  // Use 'default' key if present, otherwise first entry
  const entry = cfg.default || Object.values(cfg)[0] || {};

  return {
    apiKey: entry.key || process.env.LLM_API_KEY || process.env.OPENAI_API_KEY || process.env.DEEPSEEK_API_KEY || '',
    baseUrl: entry.url || process.env.LLM_BASE_URL || process.env.OPENAI_BASE_URL || DEFAULT_BASE_URL,
    model: entry.model || process.env.LLM_MODEL || process.env.OPENAI_MODEL || DEFAULT_MODEL,
  };
}

export async function callLlm(messages, options = {}) {
  const { apiKey, baseUrl, model } = await getLlmConfig();
  const timeoutMs = options.timeoutMs || DEFAULT_TIMEOUT_MS;

  if (!apiKey) {
    return { ok: false, error: 'No LLM API key configured. Set llm config in system_config or LLM_API_KEY env.' };
  }

  const url = `${baseUrl.replace(/\/$/, '')}/chat/completions`;
  const body = {
    model: options.model || model,
    messages,
    temperature: options.temperature ?? 0.4,
    max_tokens: options.maxTokens ?? 4096,
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text();
      return { ok: false, error: `LLM API ${res.status}: ${text.slice(0, 500)}` };
    }

    const data = await res.json();
    const content = data.choices?.[0]?.message?.content || '';
    return { ok: true, content, usage: data.usage };

  } catch (err) {
    if (err.name === 'AbortError') return { ok: false, error: 'LLM request timed out' };
    return { ok: false, error: `LLM request failed: ${err.message}` };
  } finally {
    clearTimeout(timer);
  }
}

// ── ReAct-specific LLM call ────────────────────────────────────────────
// Never rejects — always returns a safe fallback string so the ReAct
// engine never hangs on LLM failures.

const REACT_SYSTEM_PROMPT = '你是渗透测试执行代理。请严格按照 ReAct 格式输出 Observation 和 Thought（中文），以及 Action（XML）。保持简洁，Thought 不超过100字。';

export async function callLlmReact(prompt, options = {}) {
  const { apiKey, baseUrl, model } = await getLlmConfig();
  const timeoutMs = options.timeoutMs || 30_000;  // 30s default for ReAct

  if (!apiKey) {
    return 'Observation: LLM未配置，自动继续\nThought: 无LLM分析能力，按原计划执行\n<action type="continue" />';
  }

  const url = `${baseUrl.replace(/\/$/, '')}/chat/completions`;
  const body = {
    model: options.model || model,
    messages: [
      { role: 'system', content: REACT_SYSTEM_PROMPT },
      { role: 'user', content: prompt },
    ],
    temperature: options.temperature ?? 0.3,  // More deterministic
    max_tokens: options.maxTokens ?? 2048,
  };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    if (!res.ok) {
      const text = await res.text();
      console.warn(`[callLlmReact] HTTP ${res.status}: ${text.slice(0, 200)}`);
      return `Observation: LLM调用失败(HTTP ${res.status})，自动继续\n<action type="continue" />`;
    }

    const data = await res.json();
    const content = data.choices?.[0]?.message?.content || '';
    if (!content) {
      return 'Observation: LLM返回空内容，自动继续\n<action type="continue" />';
    }
    return content;

  } catch (err) {
    if (err.name === 'AbortError') {
      console.warn('[callLlmReact] Request timed out');
      return 'Observation: LLM请求超时，自动继续\n<action type="continue" />';
    }
    console.warn(`[callLlmReact] Error: ${err.message}`);
    return `Observation: LLM请求失败(${err.message})，自动继续\n<action type="continue" />`;
  } finally {
    clearTimeout(timer);
  }
}
