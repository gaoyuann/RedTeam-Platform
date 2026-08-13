/**
 * 输出解析器
 * 目标：把常用工具的文本输出转为结构化证据，便于规则/评估系统消费
 *
 * Ported from RedTeam-Edu: backend/src/hexstrike/parsers.js
 */

export function parseNmap(stdout = '') {
  const openPorts = [];
  // 例：80/tcp open  http
  const re = /^(\d+)\/(tcp|udp)\s+open\s+([^\s]+)?/gmi;
  let m;
  while ((m = re.exec(stdout)) !== null) {
    openPorts.push({ port: Number(m[1]), proto: m[2], service: (m[3] || '').trim() });
  }
  return { openPorts };
}

export function parseWhatweb(stdout = '') {
  // whatweb 常见输出：http://x [200 OK] Country[...], HTTPServer[nginx], X-Powered-By[PHP]
  const tech = [];
  const re = /\b([A-Za-z][A-Za-z0-9+._-]{1,30})\[[^\]]+\]/g;
  let m;
  while ((m = re.exec(stdout)) !== null) {
    tech.push(m[1]);
  }
  return { tech: Array.from(new Set(tech)).slice(0, 50) };
}

export function parseGobuster(stdout = '') {
  // gobuster dir 输出常见：/admin (Status: 301) [Size: 0]
  const hits = [];
  const re = /^(\/[^\s]+)\s+\(Status:\s*(\d{3})\)/gmi;
  let m;
  while ((m = re.exec(stdout)) !== null) {
    hits.push({ path: m[1], status: Number(m[2]) });
  }
  return { hits };
}

/**
 * parseSqlmap - 解析 sqlmap --batch 模式的 stdout 输出
 *
 * 提取以下信息：
 *   - injectable: 是否检测到注入点（boolean）
 *   - injectionTypes: 注入类型列表（如 ['boolean-based blind', 'UNION query']）
 *   - databases: 枚举到的数据库列表（如 ['dvwa', 'information_schema']）
 *   - dumpedTables: dump 到的表数据（[{ db, table, columns, rows, markdownTable }]）
 *   - crackedPasswords: 破解到的密码对（[{ hash, plaintext }]）
 *   - tamperUsed: 是否使用了 tamper 脚本（boolean）
 *   - wafBypassed: 是否成功绕过 WAF（boolean）
 *   - summary: 一行文字摘要
 */
export function parseSqlmap(stdout = '') {
  const result = {
    injectable: false,
    injectionTypes: [],
    databases: [],
    dumpedTables: [],
    crackedPasswords: [],
    tamperUsed: false,
    wafBypassed: false,
    summary: ''
  };

  if (!stdout) return result;

  // 1. 检测注入点
  if (/appears to be injectable|is vulnerable|identified the following injection point|the target URL is affected|the parameter .* is (vulnerable|injectable)/i.test(stdout)) {
    result.injectable = true;
  }

  // 2. 提取注入类型
  const injTypeRe = /\[INFO\]\s+target URL appears to be injectable using\s+(.+)/gi;
  const injTypeRe2 = /Type:\s+(boolean-based blind|time-based blind|UNION query|error-based|stacked queries|inline queries)/gi;
  let m;
  while ((m = injTypeRe.exec(stdout)) !== null) {
    result.injectionTypes.push(m[1].trim());
  }
  while ((m = injTypeRe2.exec(stdout)) !== null) {
    const t = m[1].trim();
    if (!result.injectionTypes.includes(t)) result.injectionTypes.push(t);
  }
  // 如果提取到了注入类型，即使 sqlmap 措辞未匹配 injectable 标志，也标记为已检测到注入点
  if (result.injectionTypes.length > 0) {
    result.injectable = true;
  }

  // 3. 提取数据库列表
  // 格式：[*] dvwa  或  [*] information_schema
  const dbRe = /^\[\*\]\s+([a-zA-Z0-9_]+)\s*$/gm;
  while ((m = dbRe.exec(stdout)) !== null) {
    const db = m[1].trim();
    if (!['available', 'databases', 'tables'].includes(db.toLowerCase())) {
      result.databases.push(db);
    }
  }
  // 备用：available databases [N]:
  if (result.databases.length === 0) {
    const dbSection = stdout.match(/available databases \[\d+\]:([\s\S]*?)(?=\[\d{2}:|$)/i);
    if (dbSection) {
      const lines = dbSection[1].split('\n');
      for (const line of lines) {
        const dbMatch = line.match(/\[\*\]\s+(\S+)/);
        if (dbMatch) result.databases.push(dbMatch[1].trim());
      }
    }
  }

  // 4. 解析 dump 表格
  const tableBlockRe = /Database:\s+(\S+)\s+Table:\s+(\S+)\s+\[(\d+) entr(?:y|ies)\]([\s\S]*?)(?=(?:Database:|do you want to dump|\[\d{2}:\d{2}:\d{2}\]|$))/gi;
  while ((m = tableBlockRe.exec(stdout)) !== null) {
    const db = m[1].trim();
    const table = m[2].trim();
    const entryCount = parseInt(m[3], 10);
    const block = m[4];

    const lines = block.split('\n').map(l => l.trim()).filter(l => l.startsWith('|'));
    if (lines.length < 2) continue;

    const columns = lines[0].split('|').map(c => c.trim()).filter(Boolean);
    const rows = [];
    for (let i = 1; i < lines.length; i++) {
      const cells = lines[i].split('|').map(c => c.trim()).filter(Boolean);
      if (cells.length === columns.length) {
        const row = {};
        columns.forEach((col, idx) => { row[col] = cells[idx]; });
        rows.push(row);
      }
    }

    const markdownTable = buildMarkdownTable(columns, rows);

    result.dumpedTables.push({
      db,
      table,
      entryCount,
      columns,
      rows,
      markdownTable
    });
  }

  // 5. 提取破解的密码
  const crackRe = /cracked password '([^']+)' for (?:hash|user) '([^']+)'/gi;
  while ((m = crackRe.exec(stdout)) !== null) {
    result.crackedPasswords.push({ plaintext: m[1], hash: m[2] });
  }
  const inlineRe = /([a-f0-9]{32})\s+\(([^)]+)\)/g;
  while ((m = inlineRe.exec(stdout)) !== null) {
    const hash = m[1];
    const plain = m[2];
    if (!result.crackedPasswords.find(p => p.hash === hash)) {
      result.crackedPasswords.push({ hash, plaintext: plain });
    }
  }

  // 6. 检测 tamper 使用
  if (/tamper script|using tamper|space2comment|randomcase|between/i.test(stdout)) {
    result.tamperUsed = true;
  }

  // 7. 检测 WAF 绕过
  if (/WAF\/IPS identified|bypassing WAF|tamper.*bypass/i.test(stdout)) {
    result.wafBypassed = true;
  }

  // 8. 生成摘要
  const parts = [];
  if (result.injectable) parts.push(`检测到 ${result.injectionTypes.length} 种注入类型`);
  if (result.databases.length > 0) parts.push(`枚举到 ${result.databases.length} 个数据库`);
  if (result.dumpedTables.length > 0) {
    const totalRows = result.dumpedTables.reduce((s, t) => s + (t.rows?.length || 0), 0);
    parts.push(`提取 ${result.dumpedTables.length} 张表 / ${totalRows} 条记录`);
  }
  if (result.crackedPasswords.length > 0) parts.push(`破解 ${result.crackedPasswords.length} 个密码哈希`);
  if (result.tamperUsed) parts.push('使用 tamper 脚本');
  if (result.wafBypassed) parts.push('成功绕过 WAF');
  result.summary = parts.join('；') || 'sqlmap 执行完毕';

  return result;
}

/**
 * 将列头数组和行对象数组转换为 GitHub Flavored Markdown 表格字符串
 */
function buildMarkdownTable(columns, rows) {
  if (!columns || columns.length === 0) return '';
  const header = '| ' + columns.join(' | ') + ' |';
  const separator = '| ' + columns.map(() => '---').join(' | ') + ' |';
  const dataRows = rows.map(row =>
    '| ' + columns.map(col => String(row[col] ?? '').replace(/\|/g, '\\|')).join(' | ') + ' |'
  );
  return [header, separator, ...dataRows].join('\n');
}

/**
 * parseHttpx - 解析 pd-httpx --json 模式的 stdout 输出
 *
 * 每行是一个 JSON 对象，包含 url, status_code, title, tech 等字段
 */
export function parseHttpx(stdout = '') {
  const results = [];
  const lines = stdout.trim().split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed);
      results.push({
        url: obj.url || obj.input || '',
        statusCode: obj.status_code || obj.status || null,
        title: obj.title || null,
        tech: obj.tech || [],
        contentLength: obj.content_length || null,
        webServer: obj.webserver || null
      });
    } catch {
      // 非 JSON 行，尝试解析普通文本格式
      // 格式 1：http://example.com [200] [Title]
      const plainRe = /^(https?:\/\/\S+)\s+\[(\d{3})\](?:\s+\[([^\]]*)\])?/;
      const pm = trimmed.match(plainRe);
      if (pm) {
        results.push({
          url: pm[1],
          statusCode: parseInt(pm[2], 10),
          title: pm[3] || null,
          tech: []
        });
      } else if (/^https?:\/\/\S+$/.test(trimmed)) {
        // 格式 2：纯 URL（每行一个），httpx -silent 模式
        results.push({
          url: trimmed,
          statusCode: null,
          title: null,
          tech: []
        });
      }
    }
  }
  return results;
}

/**
 * parseAmass - 解析 amass enum -silent 的 stdout 输出
 *
 * 每行是一个子域名
 */
export function parseAmass(stdout = '') {
  const lines = stdout.trim().split('\n');
  const subdomains = lines.map(l => l.trim()).filter(Boolean);
  return { subdomains };
}

/**
 * parseNetexec - 解析 netexec smb 的 stdout 输出
 *
 * 解析 shares 列表和 users 列表
 */
export function parseNetexec(stdout = '') {
  const shares = [];
  const users = [];

  // 解析 shares：格式 SMB  192.168.1.x  445  HOSTNAME  SHARENAME  READ
  const shareRe = /SMB\s+[\d.]+\s+\d+\s+\S+\s+(\S+)\s+(READ|WRITE|READ,WRITE)/gi;
  let m;
  while ((m = shareRe.exec(stdout)) !== null) {
    shares.push({ name: m[1], permission: m[2] });
  }

  // 解析 users：格式 SMB  192.168.1.x  445  HOSTNAME  username
  const userRe = /SMB\s+[\d.]+\s+\d+\s+\S+\s+(\S+)\s*$/gm;
  while ((m = userRe.exec(stdout)) !== null) {
    const u = m[1].trim();
    if (u && !users.includes(u)) users.push(u);
  }

  return { shares, users };
}

/**
 * parseArjun - 解析 arjun 的 stdout 输出
 *
 * 解析发现的 HTTP 参数列表
 */
export function parseArjun(stdout = '') {
  const params = [];

  // 显式处理"未发现参数"的情况
  if (!stdout || /no parameters found|0 parameter|found 0/i.test(stdout)) {
    return { params, noParamsFound: true };
  }

  // Arjun 输出格式：[+] GET: param1, param2, param3
  const getMatch = stdout.match(/\[\+\]\s+GET:\s+(.+)/i);
  if (getMatch) {
    getMatch[1].split(',').map(p => p.trim()).filter(Boolean).forEach(p => {
      params.push({ method: 'GET', name: p });
    });
  }

  // [+] POST: param1, param2
  const postMatch = stdout.match(/\[\+\]\s+POST:\s+(.+)/i);
  if (postMatch) {
    postMatch[1].split(',').map(p => p.trim()).filter(Boolean).forEach(p => {
      params.push({ method: 'POST', name: p });
    });
  }

  // 备用：Parameters found: [param1, param2]
  const altMatch = stdout.match(/Parameters found:\s+\[([^\]]+)\]/i);
  if (altMatch && params.length === 0) {
    altMatch[1].split(',').map(p => p.trim().replace(/['"]/g, '')).filter(Boolean).forEach(p => {
      params.push({ method: 'GET', name: p });
    });
  }

  return { params, noParamsFound: params.length === 0 };
}

/**
 * parseResponder - Parses the output of Responder.py
 *
 * Extracts captured NTLM hashes from the stdout or log files.
 */
export function parseResponder(stdout = '') {
  const capturedHashes = [];

  // Regex for the detailed block format in stdout
  const blockRe = /[SMB] NTLMv2-SSP Hash captured:[\s\S]*?User:\s*(\S+)[\s\S]*?Domain:\s*(\S+)[\s\S]*?NT_Hash:\s*([a-f0-9]+)[\s\S]*?JTR_Format:\s*(\S+)/gi;
  let m;
  while ((m = blockRe.exec(stdout)) !== null) {
    capturedHashes.push({
      username: m[1].trim(),
      domain: m[2].trim(),
      ntlmHash: m[3].trim(),
      jtrFormat: m[4].trim(),
      source: 'stdout_block'
    });
  }

  // Regex for the one-liner format found in log files
  // e.g., Admin::WORKGROUP:1122334455667788:1234567890abcdef1234567890abcdef:aad3b435b51404eeaad3b435b51404ee
  const lineRe = /^([a-zA-Z0-9_.-]+)::([a-zA-Z0-9_.-]+):([a-f0-9]{16}):([a-f0-9]{32,}):([a-f0-9]{16})/gm;
  while ((m = lineRe.exec(stdout)) !== null) {
    const hash = m[4];
    // Avoid duplicates if already captured from block format
    if (!capturedHashes.some(h => h.ntlmHash.includes(hash))) {
      capturedHashes.push({
        username: m[1].trim(),
        domain: m[2].trim(),
        ntlmHash: hash,
        jtrFormat: 'netntlmv2', // Assume netntlmv2 for this format
        source: 'log_line'
      });
    }
  }

  return { capturedHashes };
}

/**
 * parseJohn - Parses the output of `john --show`
 *
 * Extracts cracked passwords from the output.
 */
export function parseJohn(stdout = '') {
  const crackedPasswords = [];

  // Format: user:password:uid:gid:gecos:home:shell
  // or just: password
  const lines = stdout.trim().split('\n');
  for (const line of lines) {
    const parts = line.trim().split(':');
    if (parts.length >= 2) {
       if(parts[0] && parts[1]){
          crackedPasswords.push({ user: parts[0], password: parts[1] });
       }
    } else if (parts.length === 1 && parts[0]) {
      crackedPasswords.push({ user: null, password: parts[0] });
    }
  }

  return { crackedPasswords };
}

/**
 * parseEvilWinrm - Parses the output of Evil-WinRM.
 *
 * Extracts the user and current working directory from the shell prompt.
 */
export function parseEvilWinrm(stdout = '') {
  let user = null;
  let cwd = null;

  // Prompt format: *Evil-WinRM* PS C:\Users\Administrator\Documents>
  const promptMatch = stdout.match(/\*Evil-WinRM\* PS ([^>]+)>/);
  if (promptMatch) {
    cwd = promptMatch[1];
    const userMatch = cwd.match(/Users\\([^\\]+)/);
    if (userMatch) {
      user = userMatch[1];
    }
  }

  return { user, cwd };
}

/**
 * parseCurl - 解析 curl -i/-v 的 stdout 输出
 *
 * 提取 HTTP 状态码、响应头中的 Server、Title 等信息
 */
export function parseCurl(stdout = '') {
  if (!stdout) return { statusCode: null, title: null, server: null, contentType: null, location: null, cookies: [], contentLength: 0 };

  const statusMatch = stdout.match(/^HTTP\/[\d.]+\s+(\d{3})/im);
  const statusCode = statusMatch ? parseInt(statusMatch[1], 10) : null;

  const serverMatch = stdout.match(/^Server:\s*(.+)$/im);
  const server = serverMatch ? serverMatch[1].trim() : null;

  const titleMatch = stdout.match(/<title[^>]*>(.*?)<\/title>/is);
  const title = titleMatch ? titleMatch[1].trim() : null;

  const ctMatch = stdout.match(/^Content-Type:\s*(.+)$/im);
  const contentType = ctMatch ? ctMatch[1].trim() : null;

  const cookies = [];
  const cookieRe = /^Set-Cookie:\s*(.+)$/gim;
  let cm;
  while ((cm = cookieRe.exec(stdout)) !== null) {
    cookies.push(cm[1].trim());
  }

  const locMatch = stdout.match(/^Location:\s*(.+)$/im);
  const location = locMatch ? locMatch[1].trim() : null;

  return { statusCode, title, server, contentType, location, cookies, contentLength: stdout.length };
}
