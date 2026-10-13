// Bounded observable comparisons; matching output remains subject to human review.
export function sameComparisonRequest(left,right) {
  return !!left && !!right && left.url===right.url && (left.method || 'GET')===(right.method || 'GET');
}

export function normalizeEvidenceCriteria(value) {
  if(value===undefined) return null; // Old generated playbooks remain readable.
  if(!value || !['response_contains','status_code','response_differs'].includes(value.kind)
    || typeof value.limitations!=='string' || !value.limitations.trim() || value.limitations.length>2000) throw new Error('验证判定缺少类型或限制');
  const criteria={kind:value.kind,limitations:value.limitations};
  if(value.kind==='response_contains') {
    if(typeof value.value!=='string' || !value.value.trim() || Buffer.byteLength(value.value)>512) throw new Error('验证判定文本须为1至512字节');
    criteria.value=value.value;
  }
  if(value.kind==='status_code') {
    if(!Number.isInteger(value.value) || value.value<100 || value.value>599) throw new Error('验证判定状态码无效');
    criteria.value=value.value;
  }
  return criteria;
}

export function evaluateEvidenceCriteria(criteria,result,baseline) {
  if(!criteria) return null;
  const decision={status:'inconclusive',kind:criteria.kind,review_required:true,runtime_verified:false,limitations:criteria.limitations};
  let observation;
  try {observation=JSON.parse(result.stdout || '{}');} catch {return {...decision,reason:'请求没有结构化响应'};}
  if(!result.success || !observation.connected) return {...decision,reason:'请求失败，不能据此判断漏洞'};
  if(observation.truncated) return {...decision,reason:'响应被截断，无法完成可靠比较'};
  let matched;
  if(criteria.kind==='response_contains') matched=String(observation.response || '').includes(criteria.value);
  else if(criteria.kind==='status_code') {
    if(!Number.isInteger(observation.status_code)) return {...decision,reason:'当前协议没有HTTP状态码'};
    matched=observation.status_code===criteria.value;
  } else {
    if(!baseline || baseline.success===false || !baseline.connected || baseline.truncated || !sameComparisonRequest(baseline,observation) || baseline.response===undefined)
      return {...decision,reason:'缺少同一URL和请求方法的成功且完整的正常对照'};
    matched=baseline.response!==observation.response;
  }
  return {...decision,status:matched?'matched':'not_matched',reason:matched?'观察结果符合预案判定条件，仍需复核因果关系':'本次观察未满足预案判定条件，不能据此认定缺陷已修复'};
}
