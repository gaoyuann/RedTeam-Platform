import {executionTargetsOverlap} from './taskScope.js';
// Version the default at creation; never silently reinterpret historical tasks.
export const isScanAgent = config => config?.scan_orchestrator?.mode === 'react';
export const isSourceTask = (config,target='') => config?.test_type==='source' ||
  config?.scan_mode==='source_assisted' || config?.source_connection_id || config?.source_path || config?.source_url ||
  config?.cscan_target || ['source','remote_directory','agent'].includes(config?.input_kind) || target.startsWith('/');
export function defaultScanAgent(config,target) {
  if(isSourceTask(config,target) || config.scan_parameters?.web?.mode==='react_sqli'){const next={...config};delete next.scan_orchestrator;return next;}
  return {...config,scan_orchestrator:{version:1,mode:'react'},require_approval:true};
}
export function scanAgentBusy(db,target,exceptId=null) {
  const active=db.prepare("SELECT pipeline_id,target FROM pipelines WHERE status IN ('running','awaiting_approval')").all();
  if(active.some(p=>p.pipeline_id!==exceptId&&executionTargetsOverlap(p.target,target)))return true;
  return db.prepare(`SELECT s.target FROM scan_tool_runs r JOIN scan_tasks s USING(scan_task_id)
    WHERE r.state='running' OR json_extract(r.outcome,'$.stopped')=0`).all().some(r=>executionTargetsOverlap(r.target,target));
}

export function validateScanAgentMode(config,target) {
  if(isScanAgent(config) && (isSourceTask(config,target)||config.scan_parameters?.web?.mode==='react_sqli'))
    throw Error('扫描调度模式与源码或历史专项模式冲突，请重新配置任务');
}
