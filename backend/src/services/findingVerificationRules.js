import { parseResultData } from './scanResultCatalog.js';

export const builtinVerificationPlans = [
  {id:'f08-web-headers-v1',kind:'headers',version:1,name:'Web 防护响应头检查',description:'复核指定 HTML 入口的防护响应头配置',
    success_criteria:'成功且完整的 HTML 响应中缺少指定防护头；点击劫持同时核对 CSP frame-ancestors 替代控制。',expected_evidence:'响应状态、内容类型及防护头',cleanup:'只读请求，无需目标清理'},
  {id:'f08-cookie-flags-v1',kind:'cookie',version:1,name:'Cookie 安全属性检查',description:'只检查扫描记录指明的 Cookie 名称与属性，不保存 Cookie 值',
    success_criteria:'本次完整响应设置了同名 Cookie，且缺少扫描指明的 HttpOnly 或 HTTPS Secure 属性。',expected_evidence:'Cookie 名称及安全属性，不含值',cleanup:'只读请求；不保存或复用响应 Cookie'},
  {id:'f08-directory-index-v1',kind:'directory',version:2,name:'目录索引暴露检查',description:'核对目录标题、父目录导航和同目录条目，不能仅凭 HTTP 200 判断',
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
function directoryFeatures(html, target, version) {
  const url=new URL(target),path=decodeURIComponent(url.pathname);
  if(!url.pathname.endsWith('/'))return null;
  const title=html.match(/<title[^>]*>\s*Index of\s+([^<]+)<\/title>/i)?.[1]?.trim().replace(/&amp;/g,'&') || null;
  const ambiguous=value=>/\/\/|\\|%(?:25)*(?:2f|5c)/i.test(value);
  if(version===2 && (/\\/.test(target.split(/[?#]/)[0]) || ambiguous(url.pathname) || ambiguous(path) || title && ambiguous(title)))throw new Error('Ambiguous directory path');
  const equivalent=(a,b)=>a===b || version===2 && (a+'/'===b || b+'/'===a);
  const titleMatches=Boolean(title && equivalent(title,path));
  const links=[...html.matchAll(/<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)].map(match=>({href:match[1].replace(/&amp;/g,'&'),label:match[2].replace(/<[^>]*>/g,'').trim()}));
  let parent=false,child=false;
  for(const link of links) {
    let dest;try{dest=new URL(link.href,url);}catch{continue;}
    if(version===2) {
      let decoded;try{decoded=decodeURIComponent(dest.pathname);}catch{continue;}
      if(/\\/.test(link.href.split(/[?#]/)[0]) || ambiguous(dest.pathname) || ambiguous(decoded))continue;
    }
    if(dest.origin!==url.origin)continue;
    if(dest.pathname===new URL('../',url).pathname && (/Parent Directory/i.test(link.label)||link.href==='../'))parent=true;
    if(!link.href.startsWith('?') && dest.pathname.startsWith(url.pathname) && dest.pathname!==url.pathname && !dest.search && !dest.hash)child=true;
  }
  return {title:titleMatches,parent,child,target_path:path,title_path:title && /^\/[^\s<>"'?#]*$/.test(title)?title.slice(0,1000):null};
}
const supportedRule=rule=>builtinVerificationPlans.some(p=>p.id===rule.id && p.kind===rule.kind)
  && (rule.kind==='directory'?[1,2].includes(rule.version):rule.version===1);
function linkedObservation(rule,e,attempt,plan) {
  const step=plan.steps?.find(s=>s.step_id===rule.step_id);
  if(!step || e.tool_id!=='target-request' || e.step_index!==step.step_index)return null;
  let data,obs;try{data=JSON.parse(e.evidence_data);obs=JSON.parse(e.raw_stdout);}catch{return null;}
  if(!data || typeof data!=='object' || !obs || typeof obs!=='object' || Array.isArray(obs))return null;
  const link=data.finding_verification;
  if(!link || link.attempt_id!==attempt.id || link.revision!==attempt.revision || link.verification_id!==attempt.verification_id
    || link.finding_id!==plan.finding_id || link.fingerprint!==attempt.fingerprint
    || attempt.pipeline_id && link.pipeline_id!==attempt.pipeline_id || obs.url!==rule.target || obs.method!=='GET')return null;
  return {data,obs};
}
const validResponse=(data,obs,rule)=>data.success===true && data.exit_code===0 && obs.connected===true && obs.complete===true && !obs.truncated
  && Number.isInteger(obs.status_code) && obs.status_code>=200 && obs.status_code<300
  && (rule.kind==='cookie' || /\btext\/html\b/i.test(obs.response_headers?.['content-type'] || ''));

// Read-only explanation of a frozen directory rule, derived from the original evidence.
// It deliberately carries no response body, Cookie values or new saved judgement.
export function directoryEvidenceCriteria(rule,evidence,attempt,plan) {
  if(rule?.kind!=='directory')return null;
  const checks=[
    {id:'response_valid',label:'响应有效性',status:'unknown',detail:'无法可靠还原符合方案归属的响应'},
    {id:'directory_title',label:'对应目录标题',status:'unknown',detail:'无法判断'},
    {id:'parent_navigation',label:'父目录导航',status:'unknown',detail:'无法判断'},
    {id:'same_directory_entry',label:'同目录条目',status:'unknown',detail:'无法判断'}
  ];
  const result={kind:'directory',rule_id:rule.id,rule_version:rule.version,source:'saved_evidence',evidence_ids:[evidence.id],target_path:null,title_path:null,checks};
  try{result.target_path=decodeURIComponent(new URL(rule.target).pathname).slice(0,1000);}catch{return result;}
  if(!supportedRule(rule)){checks[0].detail='不支持此规则版本，不能可靠还原判据';return result;}
  const linked=linkedObservation(rule,evidence,attempt,plan);
  if(!linked)return result;
  const {data,obs}=linked;
  if(!validResponse(data,obs,rule)) {
    const knownFailure=data.success===false || Number.isInteger(data.exit_code) && data.exit_code!==0
      || obs.connected===false || obs.complete===false || obs.truncated===true
      || Number.isInteger(obs.status_code) && (obs.status_code<200 || obs.status_code>=300)
      || typeof obs.response_headers?.['content-type']==='string' && !/\btext\/html\b/i.test(obs.response_headers['content-type']);
    checks[0]={...checks[0],status:knownFailure?'failed':'unknown',detail:knownFailure?'响应失败、非成功 HTML 或采集不完整，不能用于自动确认':'响应有效性字段不完整，无法判断'};
    return result;
  }
  if(typeof obs.response!=='string'){checks[0].detail='缺少原始 HTML，无法可靠还原判据';return result;}
  if([204,205,206].includes(obs.status_code) || !obs.response.trim()
      || obs.response_headers?.['content-range']!==undefined) {
    checks[0].detail='无内容或部分页面不能可靠还原完整文档判据';return result;
  }
  if(/<input\b[^>]*type\s*=\s*["']?password\b/i.test(obs.response)) {
    checks[0]={...checks[0],status:'failed',detail:'响应为认证页面，不能代替原检查对象'};return result;
  }
  checks[0]={...checks[0],status:'passed',detail:'成功且完整的 HTML 响应'};
  let features;try{features=directoryFeatures(obs.response,rule.target,rule.version);}catch{checks[1].detail='目录入口编码或结构无法可靠解析';return result;}
  if(!features){checks[1].detail='检查入口不是明确的目录路径';return result;}
  result.target_path=features.target_path;result.title_path=features.title_path;
  for(const [index,key] of [[1,'title'],[2,'parent'],[3,'child']])checks[index]={...checks[index],status:features[key]?'passed':'failed',detail:features[key]?'已满足':'未发现符合当前规则的特征'};
  if(!features.title)checks[1].detail=features.title_path?'目录标题路径与请求路径不匹配':'未发现对应目录索引标题';
  return result;
}
export function evaluateFindingRule(rule, evidence, attempt, plan) {
  const out={rule_id:rule.id,rule_version:rule.version,conclusion:'inconclusive',evidence_ids:[],reason:'缺少符合方案归属的完整响应',limitations:rule.limitations};
  if(!supportedRule(rule))return {...out,reason:'不支持此规则版本，需要人工复核'};
  if(attempt.state!=='completed' || !attempt.stop_confirmed)return {...out,reason:'执行未完整完成或实际停止未确认'};
  const step=plan.steps.find(s=>s.step_id===rule.step_id);
  if(!step)return out;
  const records=evidence.filter(e=>e.tool_id==='target-request' && e.step_index===step.step_index);
  for(const e of records) {
    const linked=linkedObservation(rule,e,attempt,plan);
    if(!linked || !validResponse(linked.data,linked.obs,rule))continue;
    const {obs}=linked;
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
      if(rule.version===2 && typeof obs.response!=='string')return {...out,reason:'缺少原始 HTML，无法可靠还原判据'};
      let features;try{features=directoryFeatures(obs.response || '',rule.target,rule.version);}catch{return {...out,reason:'目录入口编码或结构无法可靠解析'};}
      if(!features)return {...out,reason:'检查入口不是明确的目录路径'};
      const matched=features.title&&features.parent&&features.child;
      const missing=[[features.title,'对应目录标题'],[features.parent,'父目录导航'],[features.child,'同目录条目']].filter(([present])=>!present).map(([,label])=>label);
      return {...out,conclusion:matched?'confirmed':'not_verified',reason:matched?'完整 HTML 包含对应目录标题、父目录导航和同目录条目'
        :rule.version===2?`本次完整 HTML 未满足：${missing.join('、')}`:'本次完整 HTML 未同时满足目录索引的全部判据'};
    }
  }
  return out;
}
