import { createHash, randomUUID } from 'node:crypto';
import { webDirectoryScanBlockReason, webPageEntries } from './webScanPolicy.js';

// No redirect following, no candidate-by-candidate crawling. At most three
// bounded GETs establish whether path existence can be inferred at this base.
export async function checkWebDirectory(target, { request, allowUrl = () => true, cookie, allowMissingBase = false } = {}) {
  const evidence = [];
  const blocked = reason => ({ allowed:false, reason, evidence });
  const shape=webDirectoryScanBlockReason(target);
  if(shape) return blocked(shape);
  const base=new URL(target);
  const nonce=randomUUID();
  const urls=[base.href,new URL(`__rt_missing_${nonce}`,base).href,new URL(`__rt_missing_${nonce}.php`,base).href];
  for(let i=0;i<urls.length;i++) {
    const url=urls[i];
    if(!allowUrl(url)) return blocked('目录响应对照超出授权范围，未执行目录扫描');
    let result, data;
    try {
      result=await request({url,method:'GET',timeout_ms:5000,...(cookie?{headers:{cookie}}:{})});
      data=JSON.parse(result.stdout || '{}');
    } catch { return blocked('目录响应对照失败，无法确认入口有效性，未执行目录扫描'); }
    if(result.aborted) return blocked('目录响应对照已取消');
    if(!result.success || data.complete!==true || data.truncated || typeof data.response!=='string'
      || !Number.isInteger(data.status_code) || data.status_code<100 || data.status_code>599)
      return blocked('目录响应对照不完整或超时，未执行目录扫描；请核对连通性和响应大小');
    const item={role:i===0?'base':'missing_path',status:data.status_code,
      bytes:Buffer.byteLength(data.response),sha256:createHash('sha256').update(data.response).digest('hex')};
    evidence.push(item);
    const headers=data.response_headers || {};
    if(i===0) {
      if(data.status_code>=400 && !(allowMissingBase && [404,410].includes(data.status_code))) return blocked('目录入口不可达或需要认证，未执行目录扫描');
      const selfForm=webPageEntries(data.response,url).some(entry=>{
        try {const action=new URL(entry.value,url);return entry.kind==='form' && action.origin===base.origin && action.pathname===base.pathname;}catch{return false;}
      });
      if(selfForm || /\b(?:json|xml)\b/i.test(headers['content-type'] || ''))
        return blocked('入口响应为表单、登录页或 API，需专项检查，不执行目录字典扫描');
    }
  }
  // Even changing CSRF tokens cannot make two successful nonexistent paths
  // useful existence evidence. Do not claim these paths or vulnerabilities exist.
  if(evidence.slice(1).some(item=>![404,410].includes(item.status)))
    return blocked('随机不存在路径未返回明确的 404/410，可能为软 404、登录跳转或通配路由；已停止目录扫描以避免大量假命中');
  return {allowed:true,reason:null,evidence};
}
