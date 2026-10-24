import {scanCscanTarget,normalizeCscanReportedFinding,parseCompletedCscanReport} from './cscanNative.js';
import {cscanTarget,cscanSourcePath,cscanNotes} from './cscanTarget.js';
import {taskScope} from './taskScope.js';

export function retainedCscanReport(db,scanTaskId) {
  const row=db.prepare('SELECT analysis FROM source_audits WHERE scan_task_id=?').get(scanTaskId);
  if(!row) return null;
  let coverage;try {coverage=JSON.parse(row.analysis);} catch {return null;}
  if(coverage?.engine!=='cscan' || !['remote_agent','service_path'].includes(coverage.input_mode)) return null;
  const raw=db.prepare("SELECT result_data FROM scan_results WHERE scan_task_id=? AND result_type='raw_output' ORDER BY id DESC")
    .all(scanTaskId).flatMap(row=>{try{return [JSON.parse(row.result_data)];}catch{return [];}}).find(raw=>raw?.report_source==='task_result'
      && typeof raw.report==='string' && raw.report.trim() && (raw.complete===true || coverage.report_format==='service_task_report'));
  return raw ? {coverage,raw} : null;
}

export async function auditCscanNative(task,{db,parameters,signal,nativeScan=scanCscanTarget,llm,sourceLocation='',reportOnly=false,runtimeTarget=null,runTool}) {
  const retained=reportOnly?retainedCscanReport(db,task.scan_task_id):null;
  if(reportOnly && !retained) throw new Error('没有可重新解析的完整 CScan 报告');
  if(retained) {
    parameters={...parameters,[retained.coverage.input_mode==='remote_agent'?'cscan_target':'source_path']:retained.coverage.source_target};
    sourceLocation=retained.coverage.source_location || '';
  }
  const agentMode=Boolean(parameters.cscan_target);
  const source=agentMode?cscanTarget(parameters.cscan_target):cscanSourcePath(parameters.source_path);
  const notes=cscanNotes(parameters.source_notes);
  const parent=task.pipeline_id?db.prepare('SELECT * FROM pipelines WHERE pipeline_id=? AND created_by=?').get(task.pipeline_id,task.created_by):null;
  const scope=parent?taskScope(parent):taskScope({target:source,config:{}});
  if(signal?.aborted) throw new Error('源码扫描已取消');
  if(!reportOnly && db.prepare('SELECT 1 FROM source_audits WHERE scan_task_id=?').get(task.scan_task_id))
    throw new Error('本任务已有 CScan 提交记录，请新建任务，避免重复扫描');
  let count=0;
  const store=(type,data,severity='info')=>{
    count++;
    return Number(db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool,captured_at) VALUES (?,?,?,?,?,?)')
      .run(task.scan_task_id,type,JSON.stringify(data),severity,'cscan',new Date().toISOString()).lastInsertRowid);
  };
  const coverage=retained?structuredClone(retained.coverage):{engine:'cscan',input_mode:agentMode?'remote_agent':'service_path',source_target:source,source_location:sourceLocation,source_read:false,
    source_version_verified:false,whole_project_complete:false,cscan_complete:false,
    cscan:{state:'preparing'},source_errors:[],parse_errors:[],rejected_findings:[],
    runtime_target:parameters.runtime_target || null,
    note:'源码读取和扫描由 CScan 完成。平台保存任务报告与可取得的工作目录源码副本；审计覆盖和运行版本仍需复核。'};
  if(!retained) db.prepare('INSERT INTO source_audits(scan_task_id,snapshot_id,connection_id,manifest,analysis,created_at) VALUES (?,?,?,?,?,?)')
    .run(task.scan_task_id,'cscan-report:'+task.scan_task_id,'cscan',JSON.stringify({kind:'service_report',source_target:source,source_location:sourceLocation,files:[]}),JSON.stringify(coverage),new Date().toISOString());
  const id=retained?db.prepare("SELECT id FROM scan_results WHERE scan_task_id=? AND result_type='source_coverage' ORDER BY id LIMIT 1").get(task.scan_task_id)?.id:store('source_coverage',coverage);
  if(!id) throw new Error('CScan 覆盖记录缺失');
  coverage.source_errors=[];coverage.parse_errors=[];coverage.rejected_findings=[];
  coverage.cscan_complete=false;coverage.ai_complete=false;
  const persist=()=>{
    db.prepare('UPDATE source_audits SET analysis=? WHERE scan_task_id=?').run(JSON.stringify(coverage),task.scan_task_id);
    db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify(coverage),id);
  };
  const outcomes=[];
  const imported=new Map();
  for(const row of db.prepare("SELECT id,result_data FROM scan_results WHERE scan_task_id=? AND result_type='source_finding'").all(task.scan_task_id)) {
    const data=JSON.parse(row.result_data);
    imported.set([data.file,data.start_line,data.cwe || data.title].join('|'),{id:row.id,data});
  }
  const rawRecords=new Map();
  const storeRaw=raw=>{
    if(signal?.aborted) throw new Error('源码扫描已取消');
    const key=JSON.stringify([raw.report_source,raw.source_task_ids,raw.source_subtask_ids]);
    if(rawRecords.has(key)) db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify(raw),rawRecords.get(key));
    else rawRecords.set(key,store('raw_output',raw));
  };
  const importFindings=(report)=>{
    if(report.source_access_reported==='unavailable') return;
    for(const [index,finding] of report.findings.entries()) {
      let data;
      try {
        data=normalizeCscanReportedFinding(finding,report.markdown,source);
      } catch(error) {
        const rejected={index,source_subtask_ids:finding.source_subtask_ids || report.source_subtask_ids || [],reason:error.message};
        if(!coverage.rejected_findings.some(item=>JSON.stringify(item)===JSON.stringify(rejected))) coverage.rejected_findings.push(rejected);
        continue;
      }
        const key=[data.file,data.start_line,data.cwe || data.title].join('|');
        const previous=imported.get(key);
        const ids=[...new Set([...(previous?.data.source_subtask_ids || []),...(finding.source_subtask_ids || report.source_subtask_ids || [])])];
        const taskIds=[...new Set([...(previous?.data.source_task_ids || []),...(finding.source_task_ids || report.source_task_ids || [])])];
        const evidence=structuredClone(previous?.data.report_evidence || []);
        const existing=evidence.find(item=>item.reason===data.reason);
        if(existing) existing.source_subtask_ids=[...new Set([...existing.source_subtask_ids,...(finding.source_subtask_ids || report.source_subtask_ids || [])])];
        else evidence.push({reason:data.reason,preconditions:data.preconditions,source_subtask_ids:finding.source_subtask_ids || report.source_subtask_ids || []});
        const merged={...(previous?.data || data),cscan_flow_id:report.flow_id,source_target:source,tool:'cscan',tools:['cscan'],
          source_subtask_ids:ids,source_task_ids:taskIds,report_evidence:evidence,
          suggestion:previous?.data.suggestion || data.suggestion,
          analyses:evidence.map(item=>({tool:'cscan',reason:item.reason,preconditions:item.preconditions,source_subtask_ids:item.source_subtask_ids}))};
        if(previous) db.prepare('UPDATE scan_results SET result_data=?,severity=? WHERE id=?').run(JSON.stringify(merged),merged.severity,previous.id);
        imported.set(key,{id:previous?.id || store('source_finding',merged,merged.severity),data:merged});
    }
  };
  try {
    if(!reportOnly && runtimeTarget && runTool) {
      let response;
      try {response=await runTool('target-request',[JSON.stringify({url:runtimeTarget})],{signal,timeout:15000,target:runtimeTarget});}
      catch(error) {response={success:false,error:error.message};}
      if(signal?.aborted) throw new Error('源码扫描已取消');
      let observation={};try {observation=JSON.parse(response.stdout || '{}');} catch {}
      store('application_observation',{...observation,response:String(observation.response || '').slice(0,8000),
        error:response.error || null,note:'单独声明的运行入口响应，不代表源码与部署版本一致或漏洞验证成功。'});
      outcomes.push({tool_id:'target-request',success:response.success,error:response.error || null});
    }
    const onProgress=state=>{
      coverage.cscan={...coverage.cscan,...state};persist();
    };
    let report;
    if(reportOnly) {
      await onProgress({state:'parsing',scan_complete:true});
      report={...await parseCompletedCscanReport(retained.raw.report,source,{llm,signal,sourceReports:retained.raw.source_reports}),
        flow_id:retained.raw.flow_id,finish_status:coverage.cscan.finish_status};
    } else {
      report=await nativeScan(source,{notes,sourceLocation,scope,signal,llm,onRawReport:storeRaw,onProgress,onSourceEvidence:snapshot=>{
        const manifest={...snapshot,files:snapshot.files.map(({content,...file})=>file)};
        db.transaction(()=>{
          const previous=new Map(db.prepare("SELECT result_data FROM scan_results WHERE scan_task_id=? AND result_type='source_file_copy' ORDER BY id").all(task.scan_task_id).map(row=>{const file=JSON.parse(row.result_data);return [file.path,file.sha256];}));
          for(const file of snapshot.files)if(previous.get(file.path)!==file.sha256)store('source_file_copy',{...file,flow_id:snapshot.flow_id,captured_at:snapshot.captured_at});
          db.prepare('UPDATE source_audits SET manifest=? WHERE scan_task_id=?').run(JSON.stringify(manifest),task.scan_task_id);
        })();
      }});
    }
    if(signal?.aborted) throw new Error('源码扫描已取消');
    if(!Array.isArray(report.findings) || report.findings.length>1000 || typeof report.markdown!=='string')
      throw new Error('CScan 任务报告格式无效');
    coverage.cscan={...coverage.cscan,flow_id:report.flow_id,state:'importing',scan_complete:true,finish_status:report.finish_status};
    coverage.report_format='service_task_report';coverage.parse_errors=report.parse_errors || [];
    if(!reportOnly) storeRaw({flow_id:report.flow_id,report:report.markdown,report_source:'task_result',complete:true,source_reports:report.source_reports || []});
    persist();
    coverage.source_access_reported=report.source_access_reported || 'unknown';
    if(coverage.source_access_reported==='unavailable') {
      // Retain earlier evidence but withdraw candidates contradicted by the
      // final source-access report, including existing verification references.
      for(const {id,data} of imported.values()) {
        db.prepare("UPDATE scan_results SET result_type='information',result_data=? WHERE id=?")
          .run(JSON.stringify({...data,verification_status:'source_unavailable'}),id);
      }
      const reason='CScan 未能取得目标源码，缺失条件见原始报告';
      coverage.source_errors.push(reason);coverage.cscan.state='source_unavailable';
      store('scan_error',{error:reason,flow_id:report.flow_id});
      outcomes.push({tool_id:'cscan-source-access',success:false,error:reason});
      persist();return {count,outcomes};
    }
    db.transaction(()=>{importFindings(report);persist();})();
    coverage.cscan_complete=(!agentMode || coverage.source_access_reported==='available')
      && !coverage.parse_errors.length && !coverage.rejected_findings.length;
    coverage.ai_complete=coverage.cscan_complete;
    coverage.cscan.state=coverage.parse_errors.length || coverage.rejected_findings.length?'report_error':'finished';
    outcomes.push({tool_id:'cscan',success:true});
    if(agentMode && coverage.source_access_reported==='unknown') {
      const reason='CScan 未明确报告已取得目标源码，源码审计尚未确认完成';
      coverage.source_errors.push(reason);outcomes.push({tool_id:'cscan-source-access',success:false,error:reason});
    }
    if(coverage.parse_errors.length || coverage.rejected_findings.length)
      outcomes.push({tool_id:'report-parser',success:false,error:'CScan 报告解析存在缺口，原始报告已保留'});
    if(report.finish_status==='unconfirmed') outcomes.push({tool_id:'cscan-finalize',success:false,error:'CScan Flow 结束尚未确认，请核对原 Flow'});
    if(coverage.cscan.stop_status==='unconfirmed') outcomes.push({tool_id:'cscan-stop',success:false,error:'CScan 原 Flow 停止尚未确认，请核对远端状态'});
  } catch(error) {
    coverage.source_errors.push(error.message);
    if(signal?.aborted) coverage.cscan.state='cancelled';
    else if(coverage.cscan.state==='importing') coverage.cscan.state='import_error';
    else if(coverage.cscan.state==='parsing') coverage.cscan.state='report_error';
    else if(!['error','timed_out','report_error'].includes(coverage.cscan.state)) coverage.cscan.state='error';
    store('scan_error',{error:error.message,flow_id:coverage.cscan.flow_id || null});
    outcomes.push({tool_id:'cscan',success:false,error:error.message});
  }
  persist();
  if(signal?.aborted) throw new Error('源码扫描已取消');
  return {count,outcomes};
}
