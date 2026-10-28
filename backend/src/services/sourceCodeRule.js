export const codeRuleSupported=rule=>rule?.id==='source-local-code-difference-v1' && rule.version===1 && rule.kind==='local_code'
  && typeof rule.expected==='string' && rule.expected.trim().length>=8 && rule.expected.length<=256
  && /^vc_[\w-]+$/.test(rule.artifact_id || '') && /^[a-f0-9]{64}$/.test(rule.artifact_hash || '')
  && typeof rule.step_id==='string' && typeof rule.baseline_step_id==='string' && rule.step_id!==rule.baseline_step_id;
export function makeCodeRule(plan) {
  return {id:'source-local-code-difference-v1',version:1,kind:'local_code',target:plan.target,expected:plan.code_payload.execution.expected_output,
    artifact_id:plan.code_payload.id,artifact_hash:plan.code_payload.hash,baseline_step_id:plan.steps[0].step_id,step_id:plan.steps[1].step_id,
    limitations:'仅证明已绑定本地模拟程序的运行输出差异，不证明真实部署目标存在或已触发该漏洞。'};
}
export function evaluateCodeRule(rule,evidence,attempt,plan) {
  const base={rule_id:rule.id,rule_version:rule.version,conclusion:'inconclusive',evidence_ids:[],reason:'缺少同一次执行的完整本地对照与验证证据',limitations:rule.limitations};
  if(!codeRuleSupported(rule) || attempt.state!=='completed' || !attempt.stop_confirmed)return base;
  const read=(id,phase)=>{
    const step=plan.steps.find(s=>s.step_id===id);
    for(const e of evidence)try {
      const data=JSON.parse(e.evidence_data),o=JSON.parse(e.raw_stdout),l=data.finding_verification;
      if(!step || e.step_index!==step.step_index || e.tool_id!=='source-code-runner' || !l?.tool_started || !l.artifact_consumed
        || l.attempt_id!==attempt.id || l.verification_id!==attempt.verification_id || l.finding_id!==plan.finding_id
        || l.pipeline_id!==attempt.pipeline_id || l.revision!==attempt.revision || l.fingerprint!==attempt.fingerprint
        || l.artifact_id!==rule.artifact_id || l.artifact_hash!==rule.artifact_hash
        || data.success!==true || data.exit_code!==0 || o.format!=='local-code-observation-v1' || o.mode!=='local_simulation'
        || o.artifact_id!==rule.artifact_id || o.artifact_hash!==rule.artifact_hash || o.phase!==phase
        || !o.complete || !o.compile?.ok || !o.run?.started || o.run.timed_out || o.run.truncated
        || typeof o.run.stdout!=='string' || typeof o.run.stderr!=='string' || !Number.isInteger(o.run.exit_code))continue;
      return {id:e.id,...o.run};
    }catch{}
    return null;
  };
  const baseline=read(rule.baseline_step_id,'baseline'),probe=read(rule.step_id,'probe');
  if(!baseline || !probe)return base;
  const includes=o=>(o.stdout+'\n'+o.stderr).includes(rule.expected);
  base.evidence_ids=[baseline.id,probe.id];
  if(baseline.exit_code!==0 || includes(baseline))return {...base,reason:'正常对照异常或已包含指定特征，不能归因于验证输入'};
  if(includes(probe))return {...base,conclusion:'confirmed',reason:'已执行绑定载荷；正常对照不含指定特征，验证运行出现该特征，仅复现本地模拟输出差异'};
  if(probe.exit_code!==0)return {...base,reason:'验证程序异常退出且没有指定特征，不能作为未复现结论'};
  return {...base,conclusion:'not_verified',reason:'本地对照与验证均完成，验证输出未出现指定特征；本次模拟未复现'};
}
