import { mkdirSync, writeFileSync } from 'fs';
import { join } from 'path';

export async function establishDvwaSession(options) {
  const controller = new AbortController();
  const onAbort = () => controller.abort();
  options.signal?.addEventListener('abort', onAbort, { once: true });
  if (options.signal?.aborted) onAbort();
  const timer = setTimeout(onAbort, options.timeoutMs || 30000);
  try {
    return await authenticate({ ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
    options.signal?.removeEventListener('abort', onAbort);
  }
}

async function authenticate({ baseUrl, username, password, securityLevel = 'low', outputDirectory, signal, request = fetch }) {
  const cookies = new Map();
  const origin = new URL(baseUrl).origin;
  async function send(path, options = {}) {
    let url = new URL(path, `${baseUrl.replace(/\/$/, '')}/`);
    for (let redirects = 0; redirects < 6; redirects++) {
      if (url.origin !== origin) throw new Error('DVWA authentication redirected outside the selected target');
      const response = await request(url, { ...options, signal, redirect: 'manual', headers: {
        ...options.headers, Cookie: [...cookies].map(([name, value]) => `${name}=${value}`).join('; '),
      } });
      const headers = response.headers.getSetCookie?.() || (response.headers.get('set-cookie') || '').split(/,(?=\s*[^;,=]+=[^;])/);
      for (const header of headers) {
        const pair = header.trim().split(';')[0];
        const separator = pair.indexOf('=');
        if (separator > 0) cookies.set(pair.slice(0, separator), pair.slice(separator + 1));
      }
      const text = await response.text();
      if (response.status >= 300 && response.status < 400 && response.headers.get('location')) {
        url = new URL(response.headers.get('location'), url);
        if ([301, 302, 303].includes(response.status)) options = {};
        continue;
      }
      if (!response.ok) throw new Error(`DVWA authentication HTTP ${response.status}`);
      return { text, url };
    }
    throw new Error('DVWA authentication redirect limit exceeded');
  }
  function tokenFrom(text) {
    const input = text.match(/<input\b[^>]*\bname\s*=\s*['"]user_token['"][^>]*>/i)?.[0];
    return input?.match(/\bvalue\s*=\s*['"]([^'"]+)['"]/i)?.[1] ||
      text.match(/<input\b[^>]*\bvalue\s*=\s*['"]([^'"]+)['"][^>]*\bname\s*=\s*['"]user_token['"]/i)?.[1];
  }
  const login = await send('login.php');
  const token = tokenFrom(login.text);
  if (!token) throw new Error('DVWA login CSRF token missing');
  await send('login.php', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username, password, Login: 'Login', user_token: token }).toString() });
  const security = await send('security.php');
  if (security.url.pathname.endsWith('/login.php')) throw new Error('DVWA credentials rejected');
  const securityToken = tokenFrom(security.text);
  if (!securityToken) throw new Error('DVWA security CSRF token missing');
  await send('security.php', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ security: securityLevel, seclev_submit: 'Submit', user_token: securityToken }).toString() });
  const verified = await send('vulnerabilities/sqli/');
  if (verified.url.pathname.endsWith('/login.php') || !cookies.get('PHPSESSID') ||
      !/logout\.php/i.test(verified.text) || /name\s*=\s*['"]password['"]/i.test(verified.text) ||
      cookies.get('security') !== securityLevel) {
    throw new Error('DVWA authenticated access was not verified');
  }
  mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
  const cookie = [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  writeFileSync(join(outputDirectory, 'session.json'), JSON.stringify({ cookie, verified_at: new Date().toISOString() }), { mode: 0o600 });
  return { cookie, success: true, exitCode: 0, stdout: 'DVWA authenticated session verified; security level configured; session isolated by run.', stderr: '', executionMode: 'http' };
}
