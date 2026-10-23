import {createHash} from 'node:crypto';
import {allowedPage,privateField} from './webScanEntries.js';
const requests=new Map();
export function validatePostRequests(target,items,allowUrl){
 if(!Array.isArray(items)||!items.length||items.length>5)throw Error('POST 请求须为 1 至 5 个明确模板');
 return items.map(item=>{
  if(!item||Object.keys(item).some(k=>!['url','encoding','fields','parameters','read_only_confirmed'].includes(k))||item.read_only_confirmed!==true||!['form','json'].includes(item.encoding))throw Error('POST 请求需要只读查询确认及明确编码');
  if(typeof item.url!=='string'||!item.url.trim()||item.url!==item.url.trim()||item.url.length>2048||!/^https?:\/\//i.test(item.url))throw Error('POST 入口必须是明确的绝对 HTTP/HTTPS URL');
  const original=new URL(item.url);
  if(original.username||original.password||item.url.includes('#')||item.url.includes('?'))throw Error('POST 入口不能包含凭据、查询或片段');
  const u=allowedPage(item.url,target,allowUrl);if(!u||u.search||u.hash)throw Error('POST 入口不在允许范围或含查询');
  if(!item.fields||typeof item.fields!=='object'||Array.isArray(item.fields))throw Error('仅支持平面字段对象');
  const pairs=Object.entries(item.fields);if(!pairs.length||pairs.length>16)throw Error('POST 字段数无效');
  for(const [key,value] of pairs)if(!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(key)||privateField(key)||['__proto__','constructor','prototype'].includes(key)||typeof value!=='string'||!value||value.length>256||/[\r\n\0*]/.test(value))throw Error('字段含凭据、动态令牌或不支持的值');
  if(!Array.isArray(item.parameters)||!item.parameters.length||new Set(item.parameters).size!==item.parameters.length||item.parameters.some(p=>!Object.hasOwn(item.fields,p)))throw Error('检测参数必须属于明确模板');
  const body=item.encoding==='json'?JSON.stringify(item.fields):new URLSearchParams(pairs).toString();
  const id='post_'+createHash('sha256').update(JSON.stringify([u.href,item.encoding,body,item.parameters])).digest('hex').slice(0,24);
  return {id,url:u.href,requestUrl:u.href,method:'POST',kind:'authorized_request',parameters:[...item.parameters],reason:null,body,encoding:item.encoding,contentType:item.encoding==='json'?'application/json':'application/x-www-form-urlencoded'};
 });
}
export function putPostRequests(id,owner,target,value,allowUrl){if(requests.has(id))throw Error('已有本次 POST 模板');const entries=validatePostRequests(target,value,allowUrl);const timer=setTimeout(()=>clearPostRequests(id),15*60*1000);timer.unref();requests.set(id,{owner,entries,timer});}
export function getPostRequests(id,owner){const v=requests.get(id);return v?.owner===owner?v.entries.map(e=>({...e,parameters:[...e.parameters]})):[];}
export function clearPostRequests(id){const v=requests.get(id);if(v){clearTimeout(v.timer);for(const e of v.entries)e.body='';requests.delete(id);}}

// Track template values only in the live scanner. Never turn a redacted identity
// back into a request URL. Generated hashes are identifiers, not reflected data.
export function createPostRedactor(entries) {
 const values=new Set();
 for(const e of entries){
  const fields=e.encoding==='json'?JSON.parse(e.body):Object.fromEntries(new URLSearchParams(e.body));
  for(const value of Object.values(fields)){
   values.add(value);values.add(encodeURIComponent(value));values.add(encodeURIComponent(encodeURIComponent(value)));
   values.add(new URLSearchParams({v:value}).toString().slice(2));
  }
 }
 const sorted=[...values].filter(Boolean).sort((a,b)=>b.length-a.length);
 const replace=text=>sorted.reduce((s,v)=>s.split(v).join('[已隐藏]'),text);
 const generated=new Set(['id','entry_id','check_id','tool_run_id','request_sha256','output_sha256','rule_id','method','state','status','detection_status','action','mode','parameter_location','encoding']);
 const scrub=(value,key='')=>generated.has(key)?value:Array.isArray(value)?value.map(v=>scrub(v)):value&&typeof value==='object'?Object.fromEntries(Object.entries(value).map(([k,v])=>[k,scrub(v,k)])):typeof value==='string'?text(value):value;
 function text(value){
  if(/^https?:\/\//i.test(value)){try{const u=new URL(value);return u.origin+replace(value.slice(u.origin.length));}catch{}}
  return replace(value);
 }
 return {scrub,identitySafe:value=>scrub(value)===value,close(){values.clear();sorted.length=0;}};
}
