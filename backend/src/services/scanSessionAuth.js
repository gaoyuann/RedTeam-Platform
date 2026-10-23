// Ephemeral session material is never part of pipeline config or scan parameters.
const sessions=new Map();
export function putScanSessionAuth(id,owner,target,value){
 const url=new URL(target);
 if(url.pathname.includes('%') || !['http:','https:'].includes(url.protocol)||url.username||url.password||url.search||url.hash)throw Error('临时会话要求无凭据的 HTTP/HTTPS 应用入口');
 if(!value||Object.keys(value).some(k=>!['type','value'].includes(k))||!['cookie','bearer'].includes(value.type)||typeof value.value!=='string'||!value.value.trim()||value.value.length>4096||/[\r\n\0]/.test(value.value))throw Error('临时会话格式无效');
 if(value.type==='cookie'&&!value.value.split(';').every(p=>/^\s*[\w.-]+=[^;]*$/.test(p)))throw Error('Cookie 格式无效');
 if(value.type==='bearer'&&!/^[A-Za-z0-9._~+\/-]+=*$/.test(value.value))throw Error('Bearer Token 格式无效');
 if(sessions.has(id))throw Error('已有临时会话');
 const timer=setTimeout(()=>clearScanSessionAuth(id),15*60*1000);timer.unref();
 sessions.set(id,{owner,origin:url.origin,path:url.pathname,...value,timer});
}
export function scanSessionAuth(id,owner){const v=sessions.get(id);return v?.owner===owner?{type:v.type,value:v.value,origin:v.origin,path:v.path}:null;}
export function clearScanSessionAuth(id){const v=sessions.get(id);if(v){clearTimeout(v.timer);v.value='';sessions.delete(id);}}
export function sessionAllows(auth,url){const u=new URL(url);return u.origin===auth.origin&&(u.pathname===auth.path||u.pathname.startsWith(auth.path.endsWith('/')?auth.path:auth.path+'/'));}
export function scrubSession(auth,value){
 if(!auth)return value;
 const secrets=[auth.value,...(auth.type==='cookie'?auth.value.split(';').map(p=>p.slice(p.indexOf('=')+1).trim()):[])].filter(Boolean);
 const scrub=v=>Array.isArray(v)?v.map(scrub):v&&typeof v==='object'?Object.fromEntries(Object.entries(v).map(([k,x])=>[k,scrub(x)])):typeof v==='string'?secrets.reduce((s,secret)=>[secret,encodeURIComponent(secret)].reduce((x,k)=>x.split(k).join('[已隐藏]'),s),v):v;
 return scrub(value);
}
