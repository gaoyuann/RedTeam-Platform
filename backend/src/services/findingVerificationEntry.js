import { pipelineScans } from './scanResultQuery.js';
import { parseResultData } from './scanResultCatalog.js';
import { taskScope, isTargetInScope } from './taskScope.js';

// Resolve an existing observation to a request entry without making any network
// calls or guessing a protocol/port for a host-only task.
export function findingVerificationEntry(db, pipeline, finding) {
  const data=parseResultData(finding.result_data) || {};
  const scope=taskScope(pipeline);
  const scan=db.prepare('SELECT target,parameters FROM scan_tasks WHERE scan_task_id=?').get(finding.scan_task_id);
  const parameters=parseResultData(scan?.parameters) || {};
  if(data.evidence_origin==='cscan_report') {
    const runtime=parameters.runtime_target;
    if(typeof runtime==='string' && /^(?:https?|tcp):\/\//i.test(runtime) && isTargetInScope(scope,runtime))
      return {target:runtime,source:'declared_runtime_target',source_record_id:finding.id};
    return {target:null,source:'source_only',missing_conditions:['本项来自 CScan 源码报告，请单独提供范围内的程序运行入口和版本；源码访问地址不能直接作为验证目标。']};
  }
  if((parameters.input_kind==='remote_directory' || parameters.source_path || parameters.cscan_target?.startsWith('/')) && !parameters.runtime_target)
    return {target:null,source:'source_only',missing_conditions:['本项来自 CScan 源码报告，请先提供对应部署程序的真实运行入口和版本。']};
  const parse=value=>{
    if(typeof value!=='string' || !/^https?:\/\//i.test(value) || !isTargetInScope(scope,value))return null;
    try{return new URL(value);}catch{return null;}
  };
  const host=value=>{
    try{return new URL(value).hostname.toLowerCase();}catch{return String(value || '').replace(/^\[|\]$/g,'').toLowerCase();}
  };
  const scanHost=host(scan?.target || pipeline.target);
  for(const value of [data.url,data.location,data.endpoint]) {
    const url=parse(value);
    if(url && url.hostname.toLowerCase()===scanHost)
      return {target:url.href,source:'finding_url',source_record_id:finding.id};
  }
  let base=[parse(scan?.target),parse(pipeline.target)].find(url=>url && url.hostname.toLowerCase()===scanHost),
    source=base?'scan_or_task_url':null, sourceId=null;
  if(!base) {
    const ids=pipelineScans(db,pipeline).map(row=>row.scan_task_id);
    const observations=ids.length?db.prepare(`SELECT id,scan_task_id,result_data FROM scan_results
      WHERE scan_task_id IN (${ids.map(()=>'?').join(',')}) AND result_type='http_probe' ORDER BY id`).all(...ids):[];
    const origins=new Map();
    for(const record of observations) {
      const url=parse(parseResultData(record.result_data)?.url);
      if(!url || url.hostname.toLowerCase()!==scanHost)continue;
      if(!origins.has(url.origin))origins.set(url.origin,{url,id:record.id});
    }
    // More than one observed port/protocol needs an explicit choice rather than
    // silently choosing a different service on the same host.
    if(origins.size===1) {
      const observed=[...origins.values()][0];base=observed.url;source='observed_http_entry';sourceId=observed.id;
    }
  }
  if(base) {
    const path=typeof data.path==='string'?data.path.replace(/:$/,''):null;
    if(path) {
      if(!path.startsWith('/') || path.startsWith('//') || path.includes('\\'))
        return {target:null,source:'unresolved',missing_conditions:['扫描位置不是可核实的同服务路径，请确认具体 HTTP 入口。']};
      try {
        const entry=new URL(path,base);
        if(entry.origin!==base.origin || !isTargetInScope(scope,entry.href))
          return {target:null,source:'out_of_scope',missing_conditions:['发现的位置超出任务允许路径或命中排除项，请核对范围。']};
        return {target:entry.href,source,source_record_id:sourceId,finding_path:path};
      }catch {return {target:null,source:'unresolved',missing_conditions:['扫描路径格式无效，请确认具体 HTTP 入口。']};}
    }
    return {target:base.href,source,source_record_id:sourceId};
  }
  const original=scan?.target || pipeline.target;
  if(/^tcp:\/\//i.test(original) && isTargetInScope(scope,original))return {target:original,source:'scan_target'};
  return {target:original,source:'unresolved',missing_conditions:['尚无可唯一关联到本发现的协议、端口和完整入口，请确认该服务的测试地址。']};
}
