import {parseResultData} from './scanResultCatalog.js';
import {parseCscanMarkdown} from './cscanReport.js';
import {normalizeCscanReportedFinding} from './cscanNative.js';
import {cscanReportHash} from './cscanProgress.js';

export function sourceScanPending(task) {
  return ['source_scan','program_scan'].includes(task?.scan_type) && ['PENDING','RUNNING'].includes(task.status);
}

// Old incremental findings and retained findings during report retry must not
// leak into the final table while the scan/parse/import operation is active.
export function visibleSourceScanRecords(task,rows) {
  return sourceScanPending(task) ? rows.filter(row=>row.result_type!=='source_finding') : rows;
}

export function sourceScanResultState(task,rows) {
  const coverage=rows.find(row=>row.result_type==='source_coverage');
  const data=parseResultData(coverage?.result_data) || {};
  if(task?.scan_type!=='source_scan' && !(task?.scan_type==='program_scan' && data.engine==='cscan')) return null;
  const pending=sourceScanPending(task);
  const remote=data.cscan || {};
  return {
    pending,
    phase:remote.state || String(task.status || '').toLowerCase(),
    findings_ready:!pending && ['COMPLETED','PARTIAL'].includes(task.status),
    findings_count:pending?0:rows.filter(row=>row.result_type==='source_finding').length,
    report_complete:remote.scan_complete===true || data.cscan_complete===true,
    task_progress:remote.task_progress || null,
    subtask_progress:remote.subtask_progress || null,
  };
}

// Read-only progress preview. Never assign database finding IDs or persist these
// records: final findings remain gated by complete report parsing/import.
export function sourceScanPreview(task,rows) {
  if(!sourceScanResultState(task,rows)) return null;
  const parameters=parseResultData(task.parameters) || {};
  const target=parameters.cscan_target || parameters.source_path || task.target;
  const findings=new Map(),parseErrors=new Set();let bytes=0,truncated=false,parsing=false;
  const reports=rows.filter(row=>row.result_type==='raw_output').map(row=>parseResultData(row.result_data))
    .filter(raw=>typeof raw?.report==='string');
  if(reports.some(raw=>/^\s*Source-Access:\s*unavailable\s*$/mi.test(raw.report)))
    return {findings:[],truncated:false,source_unavailable:true};
  for(const raw of reports) {
    bytes+=Buffer.byteLength(raw.report);
    if(bytes>2*1024*1024) {truncated=true;break;}
    const analysis=raw.progress_analysis;
    const current=analysis?.report_hash===cscanReportHash(raw.report);
    if(current) {
      parsing ||= analysis.state==='pending';
      for(const error of analysis.parse_errors || [])if(typeof error==='string')parseErrors.add(error);
    }
    let parsed;try {parsed=current && Array.isArray(analysis.findings) && (analysis.state==='complete' || analysis.findings.length)
      ?analysis.findings:parseCscanMarkdown(raw.report,null).findings;} catch {continue;}
    for(const finding of parsed) {
      let data;try {data=normalizeCscanReportedFinding(finding,raw.report,target);} catch {continue;}
      const key=[data.file,data.start_line,data.cwe || data.title].join('|');
      if(!findings.has(key) && findings.size>=1000) {truncated=true;break;}
      const previous=findings.get(key);
      findings.set(key,{...data,preview:true,
        source_task_ids:[...new Set([...(previous?.source_task_ids || []),...(raw.source_task_ids || [])])],
        source_subtask_ids:[...new Set([...(previous?.source_subtask_ids || []),...(raw.source_subtask_ids || [])])]});
    }
    if(truncated) break;
  }
  return {findings:[...findings.values()],truncated,source_unavailable:false,parsing,parse_errors:[...parseErrors]};
}
