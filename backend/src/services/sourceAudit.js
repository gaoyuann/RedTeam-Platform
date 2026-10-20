import {resolveTaskSource} from './sourceScanConnections.js';
import {createSourceSnapshot} from './sourceSnapshot.js';
import {normalizeSourceFinding} from './sourceScanFindings.js';
import {sourceRuntimeMapping} from './sourceRuntimeMapping.js';
import {programExecutionTarget} from './programScan.js';
import {runCscan, relativeCscanPath, createCscanClient} from './cscanClient.js';
import {auditCscanNative} from './sourceAuditNative.js';

const active = new WeakMap();

// Both task pipelines and standalone program scans use this CScan-only entry.
export function auditSources(task, context) {
  let pending = active.get(context.db);
  if (!pending) {pending = new Map();active.set(context.db,pending);}
  if (pending.has(task.scan_task_id)) return pending.get(task.scan_task_id);
  const promise = (context.parameters?.source_path ? auditCscanNative(task,context) : audit(task,context))
    .finally(()=>pending.delete(task.scan_task_id));
  pending.set(task.scan_task_id,promise);
  return promise;
}

async function audit(task, {db, parameters = {}, signal, runTool, snapshot = createSourceSnapshot, cscan = runCscan}) {
  const previous = db.prepare('SELECT analysis FROM source_audits WHERE scan_task_id=?').get(task.scan_task_id);
  if (previous) throw new Error('本任务已有源码审计记录，请新建任务以保留 CScan Flow 和证据，避免重复提交');
  const insert = db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool,captured_at) VALUES (?,?,?,?,?,?)');
  let count = 0;
  const outcomes = [];
  const store = (type,data,severity = 'info') => {
    count++;
    return Number(insert.run(task.scan_task_id,type,JSON.stringify(data),severity,'cscan',new Date().toISOString()).lastInsertRowid);
  };
  const checkAbort = () => {if (signal?.aborted) throw new Error('源码扫描已取消');};
  checkAbort();
  let observation = {};
  const runtimeTarget = programExecutionTarget({...task,parameters});
  if (runtimeTarget) {
    let response;
    try {response = await runTool('target-request',[JSON.stringify({url:runtimeTarget})],{signal,timeout:15000,target:runtimeTarget});}
    catch {checkAbort();response = {success:false,error:'运行入口响应采集失败'};}
    checkAbort();
    outcomes.push({tool_id:'target-request',success:response.success,error:response.error});
    try {observation = JSON.parse(response.stdout || '{}');} catch {}
    observation.response = String(observation.response || '').slice(0,8000);
    store('application_observation',{...observation,error:response.error || null,note:'入口响应仅证明可访问性，不代表漏洞验证成功'});
  }
  if (!parameters.connection_id && !parameters.source_url) {
    store('source_coverage',{engine:'cscan',mode:'remote_only',source_read:false,files:0,ai_complete:false,
      note:'未提供源码，本次没有提交 CScan 源码扫描'});
    return {count,outcomes};
  }

  let source;
  try {
    const connection = await resolveTaskSource(parameters,task.target);
    source = await snapshot(connection,{signal});
    checkAbort();
  } catch (error) {
    checkAbort();
    outcomes.push({tool_id:'source-reader',success:false,error:error.message});
    store('scan_error',{error:error.message});
    store('source_coverage',{engine:'cscan',source_read:false,files:0,ai_complete:false,cscan_complete:false,
      source_errors:[error.message],note:'源码读取失败，未提交 CScan 扫描；入口响应不能代替源码覆盖'});
    return {count,outcomes};
  }
  outcomes.push({tool_id:'source-reader',success:true});
  const {documents,sourceDir,...manifest} = source;
  const coverage = {engine:'cscan',mode:'source_assisted',source_read:true,source_url:manifest.source_url || null,
    runtime_target:runtimeTarget || null,snapshot_id:source.snapshot_id,files:documents.length,skipped:manifest.skipped || [],
    input_scope:'bounded_cpp_snapshot',whole_project_complete:false,cscan_complete:false,ai_complete:false,
    reviewed_files:[],rejected_findings:[],source_errors:[],cscan:{state:'preparing'},
    note:'扫描由独立 CScan 服务完成；输入为采集到的 C/C++ 快照，未证明整个项目完整覆盖；源码发现仍需运行验证'};
  db.prepare('INSERT INTO source_audits(scan_task_id,snapshot_id,connection_id,manifest,analysis,created_at) VALUES (?,?,?,?,?,?)')
    .run(task.scan_task_id,source.snapshot_id,source.connection_id,JSON.stringify(manifest),JSON.stringify(coverage),new Date().toISOString());
  const coverageId = store('source_coverage',coverage);
  const persist = () => {
    db.prepare('UPDATE source_audits SET analysis=? WHERE scan_task_id=?').run(JSON.stringify(coverage),task.scan_task_id);
    db.prepare('UPDATE scan_results SET result_data=? WHERE id=?').run(JSON.stringify(coverage),coverageId);
  };
  let report;
  try {
    report = await cscan(source,{signal,onProgress:progress=>{
      coverage.cscan = {...coverage.cscan,...progress};persist();
    }});
    checkAbort();
    if (report.snapshot_id !== source.snapshot_id || !Array.isArray(report.findings) || report.findings.length > 1000)
      throw new Error('CScan 报告版本或发现格式无效');
    coverage.cscan = {...coverage.cscan,flow_id:report.flow_id,state:'finished'};
    coverage.report_format=report.report_format || 'json';
    coverage.report_source=report.report_source || 'work_directory';
    coverage.report_warnings=report.report_warnings || [];
    store('raw_output',{flow_id:report.flow_id,report:report.markdown || '',findings:report.findings,coverage:report.coverage,
      report_format:coverage.report_format,report_source:coverage.report_source});
    const seen = new Set();
    for (const [index,finding] of report.findings.entries()) {
      checkAbort();
      try {
        const path = value => relativeCscanPath(value,coverage.cscan.source_key);
        const citation = item => ({...item,file:path(item.file)});
        const assessment = finding.assessment === undefined ? undefined : {...finding.assessment,
          citations:finding.assessment.citations?.map(citation),counter_evidence:finding.assessment.counter_evidence?.map(citation)};
        const normalized = normalizeSourceFinding({...finding,file:path(finding.file),trace:finding.trace?.map(citation),assessment},documents);
        const key = [normalized.file,normalized.start_line,normalized.cwe || normalized.title].join('|');
        if (seen.has(key)) continue;
        seen.add(key);
        store('source_finding',{...normalized,snapshot_id:source.snapshot_id,tool:'cscan',tools:['cscan'],
          cscan_flow_id:report.flow_id,analyses:[{tool:'cscan',reason:normalized.reason,preconditions:normalized.preconditions}],
          runtime_mapping:sourceRuntimeMapping(normalized,observation,runtimeTarget)},normalized.severity);
      } catch (error) {
        coverage.rejected_findings.push({index,reason:error.message});
      }
    }
    const provided = new Set(documents.map(doc=>doc.path));
    const reviewed = report.coverage?.reviewed_files;
    const omitted = report.coverage?.omitted_files;
    const validCoverage = Array.isArray(reviewed) && reviewed.length <= documents.length
      && reviewed.every(path=>typeof path === 'string' && provided.has(path)) && new Set(reviewed).size === reviewed.length
      && Array.isArray(omitted) && omitted.length <= documents.length && omitted.every(path=>provided.has(path));
    coverage.reviewed_files = validCoverage ? reviewed : [];
    coverage.cscan_complete = validCoverage && report.coverage.complete === true && !omitted.length
      && reviewed.length === documents.length && !coverage.skipped.length && !coverage.rejected_findings.length;
    coverage.ai_complete = coverage.cscan_complete; // Compatibility with older consumers.
    coverage.coverage_basis = 'service_report_against_snapshot_inventory';
    outcomes.push({tool_id:'cscan',success:true});
    if(report.finish_status==='unconfirmed') outcomes.push({tool_id:'cscan-finalize',success:false,error:'扫描任务已完成，但 CScan Flow 结束尚未确认，请核对原 Flow'});
    if (!coverage.cscan_complete) outcomes.push({tool_id:'coverage',success:false,error:'CScan 分析覆盖或发现定位不完整，请查看覆盖记录'});
  } catch (error) {
    coverage.source_errors.push(error.message);
    if(signal?.aborted) coverage.cscan.state = 'cancelled';
    else if(coverage.cscan.state === 'finished') coverage.cscan.state = 'report_error';
    else if(!['error','report_error','timed_out'].includes(coverage.cscan.state)) coverage.cscan.state = 'error';
    store('scan_error',{error:error.message,flow_id:coverage.cscan.flow_id || null});
    outcomes.push({tool_id:'cscan',success:false,error:error.message});
    persist();checkAbort();
    return {count,outcomes};
  }
  persist();
  return {count,outcomes};
}

// A crashed backend cannot safely repeat createFlow. Reconcile its recorded
// flows on boot by stopping them and retaining their immutable task identities.
export async function recoverCscanAudits(db, {connect = createCscanClient} = {}) {
  const pending = [];
  for(const row of db.prepare('SELECT scan_task_id,analysis FROM source_audits').all()) {
    let coverage;
    try {coverage=JSON.parse(row.analysis);} catch {continue;}
    if(coverage.engine !== 'cscan') continue;
    const task=db.prepare('SELECT status FROM scan_tasks WHERE scan_task_id=?').get(row.scan_task_id);
    if(task?.status==='RUNNING' || ['preparing','submitting','created','running','waiting'].includes(coverage.cscan?.state)
      || coverage.cscan?.stop_status === 'unconfirmed' || coverage.cscan?.finish_status==='unconfirmed')
      pending.push({...row,coverage,finalizeOnly:task?.status!=='RUNNING' && coverage.cscan?.finish_status==='unconfirmed'});
  }
  if(!pending.length) return 0;
  let client;
  try {client=await connect();} catch { /* Persist that a remote stop was not confirmed. */ }
  const queue = [...pending];
  const worker = async () => {
    while(queue.length) {
      const {scan_task_id:id,coverage,finalizeOnly} = queue.shift();
      const remote = coverage.cscan;
      if(finalizeOnly) {
        if(client && /^\d+$/.test(String(remote.flow_id))) {
          try {await client.finish(String(remote.flow_id));remote.finish_status='acknowledged';remote.flow_status='finished';} catch {}
        }
        db.transaction(()=>{
          db.prepare('UPDATE source_audits SET analysis=? WHERE scan_task_id=?').run(JSON.stringify(coverage),id);
          db.prepare("UPDATE scan_results SET result_data=? WHERE scan_task_id=? AND result_type='source_coverage'").run(JSON.stringify(coverage),id);
        })();
        continue;
      }
      let stopped = false;
      const alreadyFinished=remote.flow_status==='finished' || ['acknowledged','already_finished'].includes(remote.finish_status);
      if(!alreadyFinished && /^\d+$/.test(String(remote.flow_id)) && client) {
        try {await client.stop(String(remote.flow_id));stopped=true;} catch {}
      }
      remote.state = 'interrupted';
      remote.stop_status = stopped ? 'acknowledged' : alreadyFinished ? 'not_required' : remote.flow_id ? 'unconfirmed' : 'not_requested';
      coverage.cscan_complete=false;coverage.ai_complete=false;
      const reason = remote.flow_id && !stopped && !alreadyFinished ? '服务重启，CScan 远端停止尚未确认，请核对原 Flow；不会自动重复提交'
        : remote.submission_uncertain ? '服务重启，CScan 提交结果不确定，请核对服务端 Flow；不会自动重复提交'
        : '服务重启前 CScan 扫描未完成，请新建任务';
      coverage.source_errors=[...new Set([...(coverage.source_errors || []),reason])].slice(-20);
      db.transaction(()=>{
        db.prepare('UPDATE source_audits SET analysis=? WHERE scan_task_id=?').run(JSON.stringify(coverage),id);
        db.prepare("UPDATE scan_results SET result_data=? WHERE scan_task_id=? AND result_type='source_coverage'").run(JSON.stringify(coverage),id);
        db.prepare("UPDATE scan_tasks SET status='FAILED',completed_at=?,error_message=? WHERE scan_task_id=? AND status='RUNNING'")
          .run(new Date().toISOString(),reason,id);
      })();
    }
  };
  await Promise.all(Array.from({length:Math.min(4,pending.length)},worker));
  return pending.length;
}
