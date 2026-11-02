const privateKey=/-----BEGIN [^-]*PRIVATE KEY-----/i;
const placeholder=value=>!value || /^(?:<[-\w]+>|\$?\{[\w.]+\}|\[redacted\])$/i.test(value);
const demoValue=value=>/^(?:demo|dummy|example|test|fixture|mock)(?:[-_](?:session|value|token|cookie|id|data))?$/i.test(value);

function safeCookieLiteral(value) {
  if(placeholder(value) || demoValue(value) || /^(?:cookie|set-cookie|PHPSESSID|JSESSIONID|sessionid|secure|httponly|samesite)$/i.test(value))return true;
  const parts=value.split(';').map(part=>part.trim()).filter(Boolean);
  return parts.length>0 && parts.every(part=>{
    if(/^(?:secure|httponly)$/i.test(part))return true;
    const pair=part.match(/^([^=\s]+)=(.*)$/);
    if(!pair)return false;
    // Attribute values are configuration; session values require an explicit
    // placeholder or a clearly named synthetic value for the local simulation.
    if(/^(?:path|domain|expires|max-age|samesite)$/i.test(pair[1]))return true;
    return placeholder(pair[2].trim()) || demoValue(pair[2].trim());
  });
}

// Source code may manipulate credentials without containing a credential value.
// Inspect literal assignments/headers instead of rejecting variable expressions,
// comparisons or calls such as cookie = SimpleCookie(). Never rewrite code.
export function hasHardcodedCodeCredentials(source) {
  if(privateKey.test(source))return true;
  const assignments=/\b(?:\w+_)?(password|passwd|secret|authorization|api[_-]?key|access[_-]?token|cookie)["']?\s*(?:\]\s*)?(?::|=(?!=))\s*(?:[rubf]{1,2})?("""|'''|["'])((?:\\[\s\S]|(?!\2)[\s\S])*?)\2/gi;
  for(const match of source.matchAll(assignments)) {
    const value=match[3].trim();
    if(placeholder(value))continue;
    if(/^cookie$/i.test(match[1]) && safeCookieLiteral(value))continue;
    if(/^authorization$/i.test(match[1]) && /^(?:Bearer|Basic)(?:\s+(?:<[-\w]+>|\$?\{[\w.]+\}))?$/i.test(value))continue;
    return true;
  }
  const cookieItems=/\bcookies?\s*\[\s*(["'])([^"']+)\1\s*\]\s*=(?!=)\s*(?:[rubf]{1,2})?("""|'''|["'])((?:\\[\s\S]|(?!\3)[\s\S])*?)\3/gi;
  for(const match of source.matchAll(cookieItems)) {
    if(/^(?:secure|httponly|samesite|path|domain|expires|max-age)$/i.test(match[2]))continue;
    if(!safeCookieLiteral(match[4].trim()))return true;
  }
  // Raw HTTP headers can be embedded inside a string rather than assigned to
  // a cookie/authorization variable. Inspect their literal contents as well.
  const strings=/("""|'''|["'])((?:\\[\s\S]|(?!\1)[\s\S])*?)\1/g;
  for(const match of source.matchAll(strings)) {
    const value=match[2];
    if(/\bBearer\s+[a-z0-9._~+\/-]+=*/i.test(value))return true;
    const fields=value.matchAll(/\b(?:password|passwd|secret|api[_-]?key|access[_-]?token)\s*[=:]\s*([^\s&;,]+)/gi);
    for(const field of fields)if(!placeholder(field[1]))return true;
    const headers=value.matchAll(/\b(?:Set-Cookie|Cookie):[ \t]*([^\r\n\\]*)/gi);
    for(const header of headers)if(!safeCookieLiteral(header[1].trim()))return true;
  }
  return false;
}
