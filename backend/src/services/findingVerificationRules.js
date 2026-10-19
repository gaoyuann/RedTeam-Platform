import { parseResultData } from './scanResultCatalog.js';

export const builtinVerificationPlans = [
  {id:'f08-web-headers-v1',kind:'headers',version:1,name:'Web 防护响应头检查',description:'复核指定 HTML 入口的防护响应头配置',
    success_criteria:'成功且完整的 HTML 响应中缺少指定防护头；点击劫持同时核对 CSP frame-ancestors 替代控制。',expected_evidence:'响应状态、内容类型及防护头',cleanup:'只读请求，无需目标清理'},
  {id:'f08-cookie-flags-v1',kind:'cookie',version:1,name:'Cookie 安全属性检查',description:'只检查扫描记录指明的 Cookie 名称与属性，不保存 Cookie 值',
    success_criteria:'本次完整响应设置了同名 Cookie，且缺少扫描指明的 HttpOnly 或 HTTPS Secure 属性。',expected_evidence:'Cookie 名称及安全属性，不含值',cleanup:'只读请求；不保存或复用响应 Cookie'},
  {id:'f08-directory-index-v1',kind:'directory',version:1,name:'目录索引暴露检查',description:'核对目录标题、父目录导航和同目录条目，不能仅凭 HTTP 200 判断',
    success_criteria:'成功且完整的 HTML 同时包含与本目录相符的索引标题、父目录导航及同目录文件或子目录链接。',expected_evidence:'目录标题、导航和条目的结构特征',cleanup:'只读请求，无需目标清理'},
];
export function findingRule(row, target) {
  const data=parseResultData(row.result_data) || {};
  const text=[data.finding,data.title,data.name].filter(v=>typeof v==='string').join(' ');
  if(row.source_tool!=='nikto' || !/^https?:\/\//i.test(target || '')) return null;
  let kind, attribute, cookie_name;
  if(/x-content-type-options/i.test(text) && /not (?:set|present)|missing|缺少|未设置/i.test(text)) {kind='headers';attribute='nosniff';}
  else if(/x-frame-options|anti.clickjacking/i.test(text) && /not (?:set|present)|missing|缺少|未设置/i.test(text)){kind='headers';attribute='frame';}
  else if(/directory indexing found|目录索引/i.test(text)){kind='directory';}
  else {
    const cookie=text.match(/\bCookie\s+([!#$%&'*+.^_`|~\w-]{1,128})\s+(?:created|set)\b/i);
    if(cookie && /without|missing|未设置|缺少/i.test(text)) {
      cookie_name=cookie[1];kind='cookie';
      if(/httponly/i.test(text))attribute='httponly';
      else if(/\bsecure\b/i.test(text) && target.startsWith('https:'))attribute='secure';
      else return null;
    } else return null;
  }
  const template=builtinVerificationPlans.find(p=>p.kind===kind);
  return {id:template.id,version:template.version,kind,attribute:attribute || null,cookie_name:cookie_name || null,
    target,limitations:kind==='directory'?'仅确认目录索引暴露，不证明敏感文件泄露。':'仅确认本次入口响应的指定配置缺陷，不证明利用或越权成功。'};
}
function cspFrameControl(value) {
  if(!value)return 'absent';
  if(Array.isArray(value))return 'uncertain';
  const policies=String(value).split(',');
  let found=false;
  for(const policy of policies) {
    const directives=policy.split(';').map(v=>v.trim()).filter(Boolean);
    const frames=directives.filter(v=>/^frame-ancestors(?:\s|$)/i.test(v));
    if(frames.length>1)return 'uncertain';
    if(!frames.length)continue;
    const sources=frames[0].split(/\s+/).slice(1);found=true;
    if(sources.length===1 && ["'none'","'self'"].includes(sources[0].toLowerCase()))return 'effective';
    return 'uncertain';
  }
  return found?'uncertain':'absent';
}
function directoryFeatures(html, target) {
  const url=new URL(target),path=decodeURIComponent(url.pathname);
  if(!url.pathname.endsWith('/'))return null;
  const title=html.match(/<title[^>]*>\s*Index of\s+([^<]+)<\/title>/i)?.[1]?.trim();
  if(!title || title.replace(/&amp;/g,'&')!==path)return {title:false};
  const links=[...html.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)].map(match=>({href:match[1].replace(/&amp;/g,'&'),label:match[2].replace(/<[^>]*>/g,'').trim()}));
  let parent=false,child=false;
  for(const link of links) {
    let dest;try{dest=new URL(link.href,url);}catch{continue;}
    if(dest.origin!==url.origin)continue;
    if(dest.pathname===new URL('../',url).pathname && (/Parent Directory/i.test(link.label)||link.href==='../'))parent=true;
    if(!link.href.startsWith('?') && dest.pathname.startsWith(url.pathname) && dest.pathname!==url.pathname && !dest.search && !dest.hash)child=true;
  }
  return {title:true,parent,child};
}
export function evaluateFindingRule(rule, evidence, attempt, plan) {
  const out={rule_id:rule.id,rule_version:rule.version,conclusion:'inconclusive',evidence_ids:[],reason:'缺少符合方案归属的完整响应',limitations:rule.limitations};
  if(attempt.state!=='completed' || !attempt.stop_confirmed)return {...out,reason:'执行未完整完成或实际停止未确认'};
  const step=plan.steps.find(s=>s.step_id===rule.step_id);
  if(!step)return out;
  const records=evidence.filter(e=>e.tool_id==='target-request' && e.step_index===step.step_index);
  for(const e of records) {
    let data,obs;try{data=JSON.parse(e.evidence_data);obs=JSON.parse(e.raw_stdout);}catch{continue;}
    if(!data || typeof data!=='object' || !obs || typeof obs!=='object')continue;
    const link=data.finding_verification;
    if(!link || link.attempt_id!==attempt.id || link.revision!==attempt.revision || link.verification_id!==attempt.verification_id
      || link.finding_id!==plan.finding_id || link.fingerprint!==attempt.fingerprint || data.success!==true || data.exit_code!==0
      || obs.url!==rule.target || obs.method!=='GET' || !obs.connected || obs.complete!==true || obs.truncated
      || !Number.isInteger(obs.status_code) || obs.status_code<200 || obs.status_code>=300
      || rule.kind!=='cookie' && !/\btext\/html\b/i.test(obs.response_headers?.['content-type'] || ''))continue;
    out.evidence_ids=[e.id];const headers=obs.response_headers || {};
    if(/<input\b[^>]*type\s*=\s*["']?password\b/i.test(obs.response || ''))return {...out,reason:'响应为认证页面，不能代替原检查对象'};
    if(rule.kind==='headers') {
      if(rule.attribute==='nosniff') {
        const value=headers['x-content-type-options'];
        if(value && !/^nosniff$/i.test(String(value).trim()))return {...out,reason:'响应头值不明确，需要人工复核'};
        return {...out,conclusion:value?'not_verified':'confirmed',reason:value?'本次响应已包含 nosniff 防护':'指定 HTML 响应缺少 X-Content-Type-Options 防护头'};
      }
      const xfo=headers['x-frame-options'];const csp=cspFrameControl(headers['content-security-policy']);
      if(xfo && /^(DENY|SAMEORIGIN)$/i.test(String(xfo).trim()) || csp==='effective')return {...out,conclusion:'not_verified',reason:'存在有效框架嵌入防护'};
      if(xfo || csp==='uncertain')return {...out,reason:'框架嵌入策略存在模糊或未支持语法，需人工复核'};
      return {...out,conclusion:'confirmed',reason:'本次响应同时缺少 X-Frame-Options 和有效 CSP frame-ancestors'};
    }
    if(rule.kind==='cookie') {
      if(obs.cookie_attributes_complete!==true || !Array.isArray(obs.cookie_attributes)
          || obs.cookie_attributes.some(c=>!c || typeof c.name!=='string'))return {...out,reason:'Cookie 属性采集不完整或格式无效，需要人工复核'};
      const cookies=obs.cookie_attributes.filter(c=>c.name===rule.cookie_name);
      if(!cookies.length)return {...out,reason:'本次响应未设置扫描指出的同名 Cookie'};
      const values=new Set(cookies.map(c=>c[rule.attribute]));
      if(values.size!==1 || ![true,false].includes([...values][0]))return {...out,reason:'同名 Cookie 属性不一致，需要人工复核'};
      const secure=[...values][0];return {...out,conclusion:secure?'not_verified':'confirmed',reason:`同名 Cookie ${rule.cookie_name} ${secure?'已设置':'缺少'} ${rule.attribute} 属性（不含值）`};
    }
    if(rule.kind==='directory') {
      let features;try{features=directoryFeatures(obs.response || '',rule.target);}catch{return {...out,reason:'目录入口编码或结构无法可靠解析'};}
      if(!features)return {...out,reason:'检查入口不是明确的目录路径'};
      const matched=features.title&&features.parent&&features.child;
      return {...out,conclusion:matched?'confirmed':'not_verified',reason:matched?'完整 HTML 包含对应目录标题、父目录导航和同目录条目':'本次完整 HTML 未同时满足目录索引的全部判据'};
    }
  }
  return out;
}
