import {createHash} from 'node:crypto';

export const CODE_TOOL='source-code-runner';
const CODE_IMAGES={python:'rt-web',c:'rt-sast-c',cpp:'rt-sast-c'};
export function codeImage(language) {
  if(!Object.hasOwn(CODE_IMAGES,language))throw new Error('不支持的载荷执行语言');
  return CODE_IMAGES[language];
}
export const codeHash=value=>createHash('sha256').update(JSON.stringify(value)).digest('hex');
const fail=message=>{throw Object.assign(new Error(message),{status:422});};
const object=value=>value && typeof value==='object' && !Array.isArray(value);

export function normalizeCodeExecution(value,files) {
  if(!object(value) || Object.keys(value).some(k=>!['language','entrypoint','baseline','probe','expected_output','diagnostics'].includes(k)))fail('本地验证缺少受支持的执行说明，请重新生成载荷');
  const extensions={python:'.py',c:'.c',cpp:'.cpp'};
  if(!extensions[value.language] || typeof value.entrypoint!=='string' || !value.entrypoint.endsWith(extensions[value.language]) || !files.some(f=>f.filename===value.entrypoint))fail('执行语言或入口文件无效');
  const phase=spec=>{
    if(!object(spec) || Object.keys(spec).some(k=>!['args','stdin'].includes(k)) || !Array.isArray(spec.args) || spec.args.length>10
      || spec.args.some(a=>typeof a!=='string' || a.length>256 || /[\x00-\x1f]/.test(a)) || typeof spec.stdin!=='string' || spec.stdin.length>1000 || spec.stdin.includes('\0'))fail('正常对照或验证输入格式无效');
    return {args:spec.args,stdin:spec.stdin};
  };
  const baseline=phase(value.baseline),probe=phase(value.probe);
  if(JSON.stringify(baseline)===JSON.stringify(probe))fail('正常对照与验证输入必须不同');
  if(typeof value.expected_output!=='string' || value.expected_output.trim().length<8 || value.expected_output.length>256 || /[\x00-\x1f]/.test(value.expected_output))fail('需要 8–256 字的具体运行输出特征');
  if(value.diagnostics!==undefined && (!['none','asan_ubsan'].includes(value.diagnostics) || value.language==='python' && value.diagnostics!=='none'))fail('诊断模式不受支持');
  // Preserve hashes of existing manifests: absence keeps their prior sanitizer
  // requirement; new generation explicitly chooses a supported diagnostic mode.
  return {language:value.language,entrypoint:value.entrypoint,baseline,probe,expected_output:value.expected_output,
    ...(value.diagnostics!==undefined?{diagnostics:value.diagnostics}:{})};
}

export function normalizeCodeArtifact(result) {
  if(!object(result) || !Array.isArray(result.files) || !result.files.length || result.files.length>4)fail('本地验证源码文件无效');
  const names=new Set();
  const files=result.files.map(f=>{
    if(!object(f) || typeof f.filename!=='string' || !/^[\w-]+\.(?:py|c|cpp|h|hpp)$/.test(f.filename) || names.has(f.filename)
      || typeof f.source!=='string' || !f.source.trim() || f.source.length>24000)fail('本地验证文件名、内容或数量无效');
    names.add(f.filename);
    return {filename:f.filename,language:typeof f.language==='string'?f.language:'',source:f.source};
  });
  if(JSON.stringify(files).length>48000)fail('本地验证源码超过限制');
  return {mode:'local_simulation',files,execution:normalizeCodeExecution(result.execution,files)};
}

export function parseCodeInvocation(args) {
  if(!Array.isArray(args) || args.length!==1 || typeof args[0]!=='string' || args[0].length>400)fail('验证工具只接受冻结的载荷引用');
  let spec;try{spec=JSON.parse(args[0]);}catch{fail('载荷引用格式无效');}
  if(!object(spec) || Object.keys(spec).sort().join(',')!=='artifact_hash,artifact_id,phase'
    || !/^vc_[\w-]{1,100}$/.test(spec.artifact_id || '') || !/^[a-f0-9]{64}$/.test(spec.artifact_hash || '')
    || !['baseline','probe'].includes(spec.phase))fail('载荷引用或测试阶段无效');
  return spec;
}

export function readCodeArtifact(db,verificationId,id) {
  if(typeof id!=='string' || !/^vc_[\w-]{1,100}$/.test(id))fail('请选择已保存的本地验证载荷');
  const row=db.prepare("SELECT * FROM finding_verification_code WHERE id=? AND verification_id=? AND state='ready'").get(id,verificationId);
  if(!row)fail('所选载荷不属于当前漏洞或尚未生成完成');
  let result;try{result=JSON.parse(row.result);}catch{fail('载荷记录格式无效');}
  const finding=db.prepare('SELECT r.result_data FROM finding_verifications v JOIN scan_results r ON r.id=v.finding_id WHERE v.id=?').get(verificationId);
  if(!finding || result.source_fingerprint!==codeHash(finding.result_data))fail('载荷对应的源码发现已变化或缺少来源指纹，请重新生成载荷');
  const artifact=normalizeCodeArtifact(result);
  return {id:row.id,hash:codeHash(artifact),...artifact};
}

export function assertCodePlan(db,item,plan) {
  if(!plan.code_payload) {
    if(plan.steps?.some(s=>s.tool_id===CODE_TOOL))fail('代码执行必须从已保存载荷准备方案');
    return;
  }
  const frozen=plan.code_payload,current=readCodeArtifact(db,item.id,frozen.id);
  const finding=db.prepare('SELECT result_data FROM scan_results WHERE id=? AND scan_task_id=?').get(item.finding_id,item.scan_task_id);
  if(!finding || codeHash(finding.result_data)!==frozen.finding_hash || current.hash!==frozen.hash
    || codeHash(normalizeCodeArtifact(frozen))!==frozen.hash)fail('源码发现或载荷内容已变化，请重新准备测试');
  if(plan.steps?.length!==2)fail('本地验证需要正常对照与验证两个步骤');
  plan.steps.forEach((s,i)=>{
    const spec=parseCodeInvocation(typeof s.args_template==='string'?JSON.parse(s.args_template):s.args_template);
    if(s.tool_id!==CODE_TOOL || s.consumption!=='none' || s.payload_id || spec.artifact_id!==frozen.id || spec.artifact_hash!==frozen.hash
      || spec.phase!==['baseline','probe'][i])fail('执行步骤与冻结载荷不一致');
  });
}
