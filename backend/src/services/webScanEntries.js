import {createHash} from 'node:crypto';
export const privateField = name => /pass|token|csrf|session|cookie|secret|auth|api.?key/i.test(name);
const decode = s => String(s).replace(/&(?:amp|quot|apos|lt|gt|#\d+|#x[0-9a-f]+);/gi,e=>{
  const v=e.slice(1,-1).toLowerCase();if(v[0]!=='#')return {amp:'&',quot:'"',apos:"'",lt:'<',gt:'>'}[v];
  const n=v[1]==='x'?parseInt(v.slice(2),16):Number(v.slice(1));return n>0&&n<=0x10ffff?String.fromCodePoint(n):'';
});
export function attributes(tag) {
  const out={};for(const m of tag.matchAll(/([\w:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g))out[m[1].toLowerCase()]=decode(m[2]??m[3]??m[4]);return out;
}
export function allowedPage(value, base, allowUrl) {
  try {
    const u=new URL(value,base), b=new URL(base);
    const path=decodeURIComponent(u.pathname);
    if(u.origin!==b.origin || u.username || u.password || !allowUrl(u.href) || /%[0-9a-f]{2}/i.test(u.pathname) ||
      /(?:logout|logoff|reset|setup|install|delete|remove|truncate|security\.php)/i.test(path) ||
      /[\\\0]/.test(path) || /%(?:2f|5c|25)/i.test(u.pathname))return null;
    if([...u.searchParams].some(([k,v])=>/^(?:logout|reset|delete|remove|install)$/i.test(k) || /^(?:action|op|operation|mode)$/i.test(k) && /logout|reset|delete|remove|install|setup/i.test(v)))return null;
    u.hash='';return u;
  }catch{return null;}
}
export function entryFromUrl(url, method='GET', kind='link', reason=null, parameters=null) {
  const u=new URL(url);const names=[...new Set(u.searchParams.keys())].sort();
  const unsafe=names.some(privateField) || [...u.searchParams.values()].some(v=>/[\r\n\0*]/.test(v) || v.length>512) || names.some(n=>! /^[\w.-]{1,80}$/.test(n));
  const duplicate=names.some(n=>u.searchParams.getAll(n).length!==1);
  const missing=names.some(n=>!u.searchParams.get(n));
  const requestUrl=u.href;u.search='';u.hash='';
  const id='entry_'+createHash('sha256').update(JSON.stringify([requestUrl,method,names,kind])).digest('hex').slice(0,24);
  return {id,url:u.href,method,kind,parameters:parameters??names,reason:reason || (unsafe||duplicate?'参数含敏感字段、重复字段或不支持的输入':missing?'缺少查询参数默认输入值':null),requestUrl};
}
export function discoverWebEntries(html, page, allowUrl) {
  const source=String(html).replace(/<!--[\s\S]*?-->|<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi,'');
  const entries=[];
  for(const m of source.matchAll(/<a\b[^>]*>/gi)) {
    const a=attributes(m[0]);if(!a.href)continue;
    const u=allowedPage(a.href,page,allowUrl);if(u)entries.push(entryFromUrl(u.href,'GET','link',/<base\b/i.test(source)?'页面基址语义首轮未支持':null));
  }
  for(const m of source.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi)) {
    const a=attributes(m[1]),method=(a.method||'GET').toUpperCase();
    const u=allowedPage(a.action||page,page,allowUrl);if(!u)continue;
    u.search='';let reason=method!=='GET'?'首轮不支持 POST 或其他方法表单':null;
    const fields=[];const seeds=[];const submitted=new Set();let submitters=0;
    if(/<base\b|<fieldset\b[^>]*\bdisabled\b/i.test(source))reason='页面基址或禁用字段组的提交语义首轮未支持';
    for(const input of m[2].matchAll(/<input\b[^>]*>/gi)) {
      const f=attributes(input[0]);if(!f.name || /\bdisabled(?:\s|=|>)/i.test(input[0]))continue;
      const type=(f.type||'text').toLowerCase();
      if(f.form || f.formaction || f.formmethod || !['text','hidden','submit','checkbox','radio','password','file','reset','button','image'].includes(type))reason='表单控件或提交覆盖语义首轮未支持';
      if(type==='submit' && ++submitters>1)reason='多个提交按钮需明确选择，首轮未支持';
      if(['reset','button','image','file'].includes(type)) {if(type==='file')reason='上传表单未支持';continue;}
      if(['checkbox','radio'].includes(type) && !/\bchecked(?:\s|=|>)/i.test(input[0]))continue;
      if(privateField(f.name)||type==='password')reason='认证或动态令牌表单不自动提交';
      if(submitted.has(f.name))reason='重复字段未支持';submitted.add(f.name);
      if(type!=='submit')fields.push(f.name);
      if(type==='text' && f.name==='id' && !f.value){f.value='1';seeds.push({parameter:'id',basis:'normal_control_1'});}
      if(!['submit','hidden','checkbox','radio'].includes(type) && !f.value)reason='缺少表单默认输入值';
      u.searchParams.append(f.name,f.value??(['checkbox','radio'].includes(type)?'on':''));
    }
    for(const select of m[2].matchAll(/<select\b([^>]*)>([\s\S]*?)<\/select\s*>/gi)) {
      const f=attributes(select[1]);if(!f.name)continue;
      if(/\bdisabled(?:\s|=|$)/i.test(select[1]))continue;
      if(privateField(f.name))reason='认证或动态令牌表单不自动提交';
      const opts=[...select[2].matchAll(/<option\b([^>]*)>([^<]*)/gi)];
      const chosen=opts.find(o=>/\bselected\b/i.test(o[1]))||opts[0];
      if(/<optgroup\b|\bdisabled\b/i.test(select[2]) || opts.filter(o=>/\bselected\b/i.test(o[1])).length>1 || f.form)reason='选项禁用、分组或关联控件语义首轮未支持';
      if(!chosen || /\bmultiple\b/i.test(select[1])){reason='缺少唯一默认选择';continue;}
      if(submitted.has(f.name))reason='重复字段未支持';submitted.add(f.name);
      fields.push(f.name);u.searchParams.append(f.name,attributes(chosen[1]).value??decode(chosen[2]).trim());
    }
    if(/<textarea\b/i.test(m[2]))reason='多行表单首轮未支持';
    if(/<button\b|\bform\s*=/i.test(m[2]) || /<input\b[^>]*\bform\s*=/i.test(source))reason='关联控件或按钮提交语义首轮未支持';
    entries.push({...entryFromUrl(u.href,method,'form',reason,fields),normal_controls:seeds});
  }
  return entries.slice(0,100);
}
export function publicEntry(e) {return {id:e.id,url:e.url,method:e.method,kind:e.kind,parameters:e.parameters,reason:e.reason,normal_controls:e.normal_controls||[],source_evidence_id:e.source_evidence_id,inspected:!!e.inspected};}
