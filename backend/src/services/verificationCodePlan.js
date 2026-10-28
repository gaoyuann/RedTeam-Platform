import {verification,taskFinding,saveVerificationPlan,json} from './findingVerification.js';
import {readCodeArtifact,CODE_TOOL,codeHash,codeImage} from './verificationCodeArtifact.js';

// Preparation only. Compilation and execution happen exclusively after /start.
export function prepareVerificationCode(db,pipeline,actor,id,input) {
  const item=verification(db,pipeline,id);
  if(item.revision!==input.expected_revision || ['queued','running','cancelling','unknown'].includes(item.state))throw Object.assign(new Error('方案或执行状态已变化，请刷新'),{status:409});
  const finding=taskFinding(db,pipeline,item.finding_id),data=json(finding.result_data);
  const artifact=readCodeArtifact(db,id,input.artifact_id);
  const codePayload={format:'local-code-v1',...artifact,finding_hash:codeHash(finding.result_data)};
  return saveVerificationPlan(db,pipeline,actor,id,{
    expected_revision:item.revision,name:'本地模拟验证 · '+String(data.title || data.name || item.finding_id).slice(0,150),
    target:db.prepare('SELECT target FROM scan_tasks WHERE scan_task_id=?').get(item.scan_task_id).target,
    prerequisites:['复用现有 '+codeImage(artifact.execution.language)+' 工具镜像；执行时核验 Python 或对应编译器，不自动安装依赖',
      '诊断模式：'+(artifact.execution.diagnostics || (artifact.execution.language==='python'?'none':'asan_ubsan'))+'；需要诊断库但不可用时停止，不降低验证条件',
      '本次运行生成的本地模拟程序，不访问实际目标，也不证明部署程序存在漏洞'],
    missing_conditions:[],success_criteria:'正常对照不含指定输出特征，验证运行包含该特征：'+artifact.execution.expected_output,
    cleanup:'每个阶段使用独立、无网络、无宿主机挂载的临时容器，结束后移除容器',max_attempts:3,duration_ms:120000,
    steps:['baseline','probe'].map((phase,i)=>({name:i?'本地模拟验证输入':'本地模拟正常对照',tool_id:CODE_TOOL,consumption:'none',
      args_template:[JSON.stringify({artifact_id:artifact.id,artifact_hash:artifact.hash,phase})],
      description:'运行冻结载荷 '+artifact.id+' · '+artifact.execution.entrypoint,
      expected_evidence:'载荷哈希、编译结果、实际运行输出、退出状态及完整性'}))
  },{codePayload,provenance:{kind:'local_code',label:'已保存载荷的本地模拟验证'}});
}
