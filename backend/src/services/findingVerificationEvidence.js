// Build a bounded public observation before any text redaction/truncation.
// Never expose response bodies, request credentials or response Cookie values.
export function verificationObservation(evidence) {
  if(evidence.tool_id!=='target-request' || /credential|password|session|cookie/i.test(evidence.evidence_type || ''))return null;
  let value;try{value=JSON.parse(evidence.raw_stdout);}catch{return null;}
  if(!value || typeof value!=='object' || Array.isArray(value))return null;
  const out={};
  for(const key of ['url','method','protocol'])if(typeof value[key]==='string')out[key]=value[key].slice(0,2000);
  for(const key of ['connected','complete','truncated','cookie_attributes_complete'])if(typeof value[key]==='boolean')out[key]=value[key];
  for(const key of ['status_code','received_bytes'])if(Number.isSafeInteger(value[key]) && value[key]>=0)out[key]=value[key];
  out.response_headers={};
  for(const key of ['content-type','x-content-type-options','x-frame-options','content-security-policy']) {
    const field=value.response_headers?.[key];
    if(typeof field==='string')out.response_headers[key]=field.slice(0,1000);
  }
  if(Array.isArray(value.cookie_attributes))out.cookie_attributes=value.cookie_attributes.slice(0,20).filter(c=>c && typeof c.name==='string').map(c=>({
    name:c.name.slice(0,128),...(typeof c.httponly==='boolean'?{httponly:c.httponly}:{}),...(typeof c.secure==='boolean'?{secure:c.secure}:{})
  }));
  if(typeof value.response==='string' && /text\/html/i.test(value.response_headers?.['content-type'] || '')) {
    out.login_form_present=/<input\b[^>]*type\s*=\s*["']?password\b/i.test(value.response);
    out.observation_note='页面或表单特征仅说明暴露事实，不能证明可利用漏洞。';
  }
  return out;
}
