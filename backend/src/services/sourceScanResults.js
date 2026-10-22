import {parseResultData} from './scanResultCatalog.js';

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
