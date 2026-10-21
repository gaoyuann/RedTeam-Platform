// Nikto appends dictionary paths to its target. A page (including PATH_INFO
// behind a script) is not an application directory, even if it returns HTTP 200.
export function webDirectoryScanBlockReason(target, { endpoint = false } = {}) {
  let url, path;
  try {
    url = new URL(target);
    path = decodeURIComponent(url.pathname);
  } catch {
    return '通用 Web 扫描需要有效的网站或应用目录 URL';
  }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password)
    return '通用 Web 扫描需要无内嵌凭据的 HTTP/HTTPS 入口';
  if (endpoint) return '已发现表单、API 或带参数页面；需专项检查，不作为目录字典扫描基址';
  if (url.search || url.hash || /%(?:2f|5c)/i.test(url.pathname) || /[%\\;]/.test(path))
    return '带参数或路径含糊的页面不能作为目录扫描入口；请指定授权范围内的应用目录';
  if (!path.endsWith('/') || /\.(?:php\d*|phtml|pht|phar|asp|aspx|ashx|asmx|jsp|jspx|cgi|fcgi|pl|py|rb|do|action|shtml|html?|json|xml)(?:\/|$)/i.test(path))
    return '页面或接口不能作为目录字典扫描入口；请指定以 / 结尾的网站或应用目录，不会自动扩大到父目录';
  return null;
}

// Extract only entry identities, never field values or credentials. Empty or
// omitted form actions submit to the current page; unquoted attributes are valid.
export function webPageEntries(body, page) {
  const entries = [];
  const decode = value => value.replace(/&(?:amp|quot|apos|lt|gt|#\d+|#x[0-9a-f]+);/gi, entity => {
    const key=entity.slice(1,-1).toLowerCase();
    if(key[0]!=='#') return {amp:'&',quot:'"',apos:"'",lt:'<',gt:'>'}[key];
    const code=key[1]==='x'?parseInt(key.slice(2),16):Number(key.slice(1));
    return code>0 && code<=0x10ffff?String.fromCodePoint(code):'';
  });
  const html=String(body || '').replace(/<!--[\s\S]*?-->|<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,'');
  for(const match of html.matchAll(/<(form|a)\b[^>]*>/gi)) {
    const form=match[1].toLowerCase()==='form';
    const attr=match[0].match(form?/\saction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i:/\shref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    if(!form && !attr) continue;
    const value=attr?decode(attr[1] ?? attr[2] ?? attr[3] ?? ''):page;
    entries.push({kind:form?'form':'web_path',value:value || page});
  }
  // Login forms can submit to another endpoint; the displayed page is still a page.
  if(/<input\b[^>]*\stype\s*=\s*(?:"password"|'password'|password(?=[\s>]))/i.test(html))
    entries.push({kind:'form',value:page});
  return entries;
}

// These scanners' extra options must not override the checked target, root,
// cookies, or calibration. Keep an explicit small set of presentation/rate options.
export function directoryExtraArgsBlockReason(tool, extra) {
  if(!extra) return null;
  if(typeof extra!=='string') return '目录扫描附加参数必须为字符串';
  const args=extra.trim().split(/\s+/).filter(Boolean);
  const flags=tool==='nikto'?{'-maxtime':/^\d+$/, '-timeout':/^\d+$/, '-Pause':/^\d+(?:\.\d+)?$/, '-Display':/^[1-4VEP]+$/}
    :{'-rate':/^\d+$/, '-t':/^\d+$/, '-timeout':/^\d+$/, '-maxtime':/^\d+$/};
  for(let i=0;i<args.length;i++) {
    const rule=flags[args[i]];
    if(!rule || !rule.test(args[++i] || '')) return '目录扫描附加参数不支持覆盖目标、目录、认证或过滤设置；请使用专用字段';
  }
  return null;
}

export function directoryOptionsBlockReason(tool, target, parameters = {}) {
  const extra=directoryExtraArgsBlockReason(tool,parameters.extra_args);
  if(extra) return extra;
  const url=new URL(target);
  if(parameters.ports && String(parameters.ports)!==String(url.port || (url.protocol==='https:'?443:80)))
    return '目录扫描端口必须与目标 URL 一致；请在 URL 中指定单一端口，不能覆盖响应对照目标';
  if(parameters.cookie && (typeof parameters.cookie!=='string' || /[\r\n]/.test(parameters.cookie) || parameters.cookie.length>4096))
    return '目录扫描 Cookie 格式无效';
  // The installed adapter used -C (CGI directories), not a cookie option.
  // Do not pretend an authenticated baseline matches an unauthenticated scan.
  if(tool==='nikto' && parameters.cookie)
    return '当前 Nikto 适配器无法保证 Cookie 与响应对照一致；请使用显式认证专项验证，未执行目录扫描';
  return null;
}
