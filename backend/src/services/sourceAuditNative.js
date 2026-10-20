import {scanCscanTarget,normalizeCscanReportedFinding} from './cscanNative.js';
import {cscanSourcePath,cscanNotes} from './cscanTarget.js';

export async function auditCscanNative(task,{db,parameters,signal,nativeScan=scanCscanTarget,llm}) {
  const source=cscanSourcePath(parameters.source_path),notes=cscanNotes(parameters.source_notes);
  if(signal?.aborted) throw new Error('源码扫描已取消');
  if(db.prepare('SELECT 1 FROM source_audits WHERE scan_task_id=?').get(task.scan_task_id))
    throw new Error('本任务已有 CScan 提交记录，请新建任务，避免重复扫描');
  let count=0;
  const store=(type,data,severity='info')=>{
    count++;
    return Number(db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool,captured_at) VALUES (?,?,?,?,?,?)')
      .run(task.scan_task_id,type,JSON.stringify(data),severity,'cscan',new Date().toISOString()).lastInsertRowid);
  };
  const coverage={engine:'cscan',input_mode:'service_path',source_target:source,source_read:false,
    source_version_verified:false,whole_project_complete:false,cscan_complete:false,
    cscan:{state:'preparing'},source_errors:[],parse_errors:[],rejected_findings:[],
    note:'源码读取和扫描由 CScan 完成。平台接收任务报告，不采集源码；报告定位和版本尚需复核。'};
  db.prepare('INSERT INTO source_audits(scan_task_id,snapshot_id,connection_id,manifest,analysis,created_at) VALUES (?,?,?,?,?,?)')
    .run(task.scan_task_id,'cscan-report:'+task.scan_task_id,'cscan',JSON.stringify({kind:'service_report',source_target:source,files:[]}),JSON.stringify(coverage),new Date().toISOString());
  const id=store('source_coverage',coverage);
  const persist=()=>{
    db.prepare('UPDATE source_audits SET analysis=? WHERE scan_task_id=?').run(JSON.stringify(coverage),task.scan_task_id);
    db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify(coverage),id);
  };
  const outcomes=[];
  try {
    const report=await nativeScan(source,{notes,signal,llm,onProgress:state=>{
      coverage.cscan={...coverage.cscan,...state};persist();
    }});
    if(signal?.aborted) throw new Error('源码扫描已取消');
    if(!Array.isArray(report.findings) || report.findings.length>1000 || typeof report.markdown!=='string')
      throw new Error('CScan 任务报告格式无效');
    coverage.cscan={...coverage.cscan,flow_id:report.flow_id,state:'finished',finish_status:report.finish_status};
    coverage.report_format='service_task_report';coverage.parse_errors=report.parse_errors || [];
    store('raw_output',{flow_id:report.flow_id,report:report.markdown,report_source:'task_result'});
    const seen=new Set();
    for(const [index,finding] of report.findings.entries()) {
      try {
        const data=normalizeCscanReportedFinding(finding,report.markdown,source);
        const key=[data.file,data.start_line,data.cwe || data.title].join('|');
        if(seen.has(key)) continue;
        seen.add(key);
        store('source_finding',{...data,cscan_flow_id:report.flow_id,source_target:source,tool:'cscan',tools:['cscan'],
          analyses:[{tool:'cscan',reason:data.reason,preconditions:data.preconditions}]},data.severity);
      } catch(error) {coverage.rejected_findings.push({index,reason:error.message});}
    }
    coverage.cscan_complete=!coverage.parse_errors.length && !coverage.rejected_findings.length;
    coverage.ai_complete=coverage.cscan_complete;
    outcomes.push({tool_id:'cscan',success:true});
    if(!coverage.cscan_complete) outcomes.push({tool_id:'report-parser',success:false,error:'CScan 报告解析存在缺口，原始报告已保留'});
    if(report.finish_status==='unconfirmed') outcomes.push({tool_id:'cscan-finalize',success:false,error:'CScan Flow 结束尚未确认，请核对原 Flow'});
  } catch(error) {
    coverage.source_errors.push(error.message);
    if(signal?.aborted) coverage.cscan.state='cancelled';
    else if(!['error','timed_out','report_error'].includes(coverage.cscan.state)) coverage.cscan.state='error';
    store('scan_error',{error:error.message,flow_id:coverage.cscan.flow_id || null});
    outcomes.push({tool_id:'cscan',success:false,error:error.message});
  }
  persist();
  if(signal?.aborted) throw new Error('源码扫描已取消');
  return {count,outcomes};
}
