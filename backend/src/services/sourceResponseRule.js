export const SOURCE_RESPONSE_RULE='source-http-difference-v1';
export const sourceResponseSupported=rule=>rule?.id===SOURCE_RESPONSE_RULE && rule.version===1 && rule.kind==='source_response'
  && typeof rule.expected==='string' && rule.expected.trim().length>=8 && rule.expected.length<=256
  && typeof rule.step_id==='string' && typeof rule.baseline_step_id==='string' && rule.step_id!==rule.baseline_step_id;
export function makeSourceResponseRule(plan, expected) {
  if(typeof expected!=='string' || expected.trim().length<8 || expected.length>256)
    throw Object.assign(new Error('需要 8–256 字的具体响应特征，不能只用 HTTP 状态判断'),{status:422});
  if(plan.steps.length!==2 || plan.steps.some(s=>s.tool_id!=='target-request'))throw new Error('需要正常对照和验证两个请求');
  return {id:SOURCE_RESPONSE_RULE,version:1,kind:'source_response',target:plan.target,
    step_id:plan.steps[1].step_id,baseline_step_id:plan.steps[0].step_id,expected,
    limitations:'仅证明本次正常对照与验证输入的响应差异；不证明代码执行、浏览器脚本执行或其他未观察到的安全影响。'};
}
export function evaluateSourceResponse(rule,evidence,attempt,plan) {
  const base={rule_id:rule.id,rule_version:rule.version,conclusion:'inconclusive',evidence_ids:[],
    reason:'缺少同一次执行的完整对照与验证响应',limitations:rule.limitations};
  if(!sourceResponseSupported(rule) || attempt.state!=='completed' || !attempt.stop_confirmed)return base;
  const read=id=>{
    const step=plan.steps.find(s=>s.step_id===id);if(!step)return null;
    let spec;try{spec=JSON.parse(JSON.parse(step.args_template)[0]);}catch{return null;}
    for(const e of evidence) {
      if(e.step_index!==step.step_index || e.tool_id!=='target-request')continue;
      try {
        const data=JSON.parse(e.evidence_data),obs=JSON.parse(e.raw_stdout),link=data.finding_verification;
        if(link?.attempt_id!==attempt.id || link.verification_id!==attempt.verification_id || link.revision!==attempt.revision
          || link.fingerprint!==attempt.fingerprint || link.finding_id!==plan.finding_id
          || link.pipeline_id!==attempt.pipeline_id || !link.tool_started)continue;
        if(data.success!==true || data.exit_code!==0 || !obs.connected || !obs.complete || obs.truncated
          || obs.url!==spec.url || obs.method!==(spec.method || 'GET') || typeof obs.response!=='string'
          || !Number.isInteger(obs.status_code) || obs.status_code<200 || obs.status_code>=300
          || [204,205,206].includes(obs.status_code) || obs.response_headers?.['content-range'])continue;
        return {id:e.id,body:obs.response};
      } catch {}
    }
    return null;
  };
  const baseline=read(rule.baseline_step_id),probe=read(rule.step_id);
  if(!baseline || !probe)return base;
  base.evidence_ids=[baseline.id,probe.id];
  if(baseline.body.includes(rule.expected))return {...base,reason:'正常对照已包含预期特征，无法将其归因于验证输入'};
  return {...base,conclusion:probe.body.includes(rule.expected)?'confirmed':'not_verified',
    reason:probe.body.includes(rule.expected)?'正常对照不含预期特征，验证响应出现该特征；已复现指定响应差异':'两次请求完整完成，但验证响应未出现指定特征；本次未复现'};
}
