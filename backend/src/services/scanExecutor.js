import { parseResults, createScanOutputCollector } from './scanResultParsers.js';
export { parseResults } from './scanResultParsers.js';
import { beginToolRun, finishToolRun, hasScanIntegrity } from './scanResultStore.js';
import { parseNmapResults, parseNmapInterfaces, topologyScanArgs, selectLanDiscoveryScope } from './nmapTopology.js';
import { getDb } from '../db/connection.js';
import { isTargetInScope, scopeBlockReason, taskScope, topologyDiscoveryScope } from './taskScope.js';
import { runTool } from '../tools/toolRunner.js';
import { getWsManager } from './wsManager.js';
import { normalizeTarget, probeTarget, buildDiscoveredProfile } from './targetDiscovery.js';
import { classifyToolResult, redactToolArgs } from '../tools/toolContracts.js';
import { auditSources } from './sourceAudit.js';
import {isProgramScan} from './programScan.js';
import {scanProgramAgent} from './programScanAgent.js';
import { webDirectoryScanBlockReason, directoryOptionsBlockReason } from './webScanPolicy.js';
import { checkWebDirectory } from './webDirectoryProbe.js';



// Track running scans to prevent duplicates
const runningScans = new Set();

// ── Module-level abort flags ───────────────────────────────────────────
// Allows external API (POST /api/scan-tasks/:scanTaskId/abort) to cancel a running scan.
const scanAbortFlags = new Map();

export function isScanActive(scanTaskId) { return runningScans.has(scanTaskId); }

export function requestScanAbort(scanTaskId) {
  scanAbortFlags.set(scanTaskId, true);
}

// Race a tool promise against an abort signal so operator abort is honoured
// even while a scan tool is mid-execution.
function raceScanWithAbort(toolPromise, scanTaskId, controller) {
  return new Promise((resolve) => {
    let done = false;
    const interval = setInterval(() => {
      if (scanAbortFlags.get(scanTaskId)) {
        if (!done) {
          clearInterval(interval);
          controller?.abort(); // Wait for the tool's bounded shutdown and buffered output.
        }
      }
    }, 500);
    toolPromise.then((r) => {
      if (!done) {
        done = true;
        clearInterval(interval);
        resolve(r);
      }
    }).catch((err) => {
      if (!done) {
        done = true;
        clearInterval(interval);
        resolve({ success: false, exitCode: -1, stdout: err.stdout || '', stderr: err.stderr || err.message, partialResults:err.partialResults || [], timedOut:!!err.timedOut, aborted:!!err.aborted, executionMode: 'error' });
      }
    });
  });
}

// ── Scan type → tool mapping ──────────────────────────────────────────
const SCAN_TOOL_MAP = {
  port_scan: 'nmap',
  topology_scan: 'nmap',
  vuln_scan: 'nuclei',
  // web_scan is handled specially: runs nikto then sqlmap (dual-step)
  brute_force: 'hydra',
  ad_scan: 'netexec',        // Active Directory domain enumeration
  cloud_scan: 'cloudmapper', // Cloud security audit
  // app_discovery and api_fuzz are handled specially (dual-step)
  auth_audit: 'nuclei',      // Nuclei with auth templates
  // source_scan is handled by the independent CScan service.
};

// ── Build tool arguments from scan parameters ─────────────────────────
export function buildArgs(scanType, target, parameters = {}) {
  if (scanType === 'topology_scan') return topologyScanArgs(target);
  const args = [];
  const { ports, timeout, extra_args, threads } = parameters;

  // 源码目标名 → 容器内路径（getVolumeMounts 将 data/source-targets 挂载到 /src:ro）
  if (scanType === 'source_scan_cppcheck' || scanType === 'source_scan_flawfinder') {
    if (!/^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$/.test(String(target))) throw new Error('源码项目名称无效');
    const safeName = String(target);
    const srcPath = `/src/${safeName}`;
    if (scanType === 'source_scan_cppcheck') {
      args.push('-q', '--enable=warning,portability,performance', '--xml', '--xml-version=2', srcPath);
    } else {
      args.push('--csv', '--minlevel=1', srcPath);
    }
    return args;
  }

  switch (scanType) {
    case 'port_scan': // nmap
      args.push('-Pn');  // skip host discovery — ICMP ping often fails in container networks
      if (ports || /^https?:\/\//i.test(target) || /^[^/]+:\d+$/.test(target)) args.push('-p', String(ports || normalizeTarget(target).port));
      if (threads && threads > 1) args.push('--min-parallelism', String(threads));
      args.push('-sV'); // version detection
      if (parameters.discover_topology) args.push('--traceroute');
      args.push(/^https?:\/\//i.test(target) || /^[^/]+:\d+$/.test(target) ? normalizeTarget(target).host.replace(/^\[|\]$/g, '') : target);
      break;

    case 'vuln_scan': // nuclei
      args.push('-no-color');  // disable ANSI color codes in output
      args.push('-u', target);
      args.push('-t', '/root/nuclei-templates');  // explicit template path matching volume mount
      if (ports) args.push('-p', String(ports));
      break;

    case 'web_scan_nikto': // nikto — general web vulnerability scan
      args.push('-h', target);
      args.push('-maxtime', '60');   // limit scan time
      if (ports) args.push('-port', String(ports));
      break;

    case 'web_scan_sqlmap': // sqlmap — SQL injection specialist
      args.push('-u', target);
      if (ports) args.push('--port', String(ports));
      args.push('--batch');          // non-interactive
      args.push('--level', '3');     // test level 3 (forms, cookies, headers)
      args.push('--risk', '2');      // medium risk (OR-based payloads)
      args.push('--random-agent');   // random User-Agent
      if (parameters.cookie) args.push('--cookie', String(parameters.cookie));
      break;

    case 'brute_force': // hydra or web-brute
      // For http-post-form: use web-brute.py (handles CSRF tokens)
      // For other services: use hydra directly
      const service = parameters.service || 'http-post-form';
      if (service === 'http-post-form') {
        // web-brute.py: script path + full target URL as positional args
        // Build full URL: if target is just IP/hostname, prepend http://
        // If form_definition contains a path (e.g. /login.php:...), extract and append it
        let bruteUrl = target;
        if (!bruteUrl.startsWith('http://') && !bruteUrl.startsWith('https://')) {
          bruteUrl = 'http://' + bruteUrl;
        }
        // Extract path from form_definition if present (format: /path:body:condition)
        const formDef = parameters.form_definition || '';
        const pathMatch = formDef.match(/^([^:]+)/);
        if (pathMatch && pathMatch[1].startsWith('/')) {
          // Append path to URL (avoid double slash)
          const path = pathMatch[1];
          if (!bruteUrl.endsWith('/')) {
            bruteUrl += path;
          } else {
            bruteUrl += path.slice(1);
          }
        } else if (!bruteUrl.includes('.php') && !bruteUrl.includes('.html') && !bruteUrl.includes('/login')) {
          // Default: try common login paths (generic, not DVWA-specific)
          bruteUrl += '/login';
        }
        args.push('/usr/local/bin/web-brute.py');
        args.push(bruteUrl);
        args.push('-L', parameters.user_list || '/usr/share/wordlists/common_users.txt');
        args.push('-P', parameters.pass_list || '/usr/share/wordlists/common_passwords.txt');
        args.push('--threads', String(threads || 4));
        if (parameters.form_action) args.push('--form-action', parameters.form_action);
        if (parameters.user_field) args.push('--user-field', parameters.user_field);
        if (parameters.pass_field) args.push('--pass-field', parameters.pass_field);
        if (parameters.fail_string) args.push('--fail-string', parameters.fail_string);
        if (parameters.success_string) args.push('--success-string', parameters.success_string);
        if (parameters.csrf_field) args.push('--csrf-field', parameters.csrf_field);
      } else {
        // Standard hydra for SSH/FTP/SMB/MySQL etc.
        const userList = parameters.user_list || '/usr/share/wordlists/common_users.txt';
        const passList = parameters.pass_list || '/usr/share/wordlists/common_passwords.txt';
        args.push('-L', userList);
        args.push('-P', passList);
        if (threads) args.push('-t', String(threads));
        args.push(target);
        args.push(service);
      }
      break;

    case 'ad_scan': // netexec SMB enumeration
      args.push('smb');
      args.push(target);
      if (parameters.username) args.push('-u', parameters.username);
      else args.push('-u', 'administrator');
      if (parameters.password) args.push('-p', parameters.password);
      else args.push('-p', 'Password123!');  // 教学默认值
      if (parameters.domain) args.push('-d', parameters.domain);
      break;

    case 'cloud_scan': // cloudmapper audit
      args.push('audit');
      args.push('--json');  // JSON output for parsing
      if (parameters.account_id) args.push('--account', parameters.account_id);
      if (parameters.region) args.push('--region', parameters.region);
      break;

    // ── Application target scan types ────────────────────────────────

    case 'app_discovery_whatweb': // whatweb — technology fingerprinting
      args.push(target);
      args.push('--no-errors');   // suppress error output
      break;

    case 'app_discovery_httpx': // httpx — HTTP probe
      args.push('-u', target);
      args.push('-sc');           // show status code
      args.push('-title');        // show page title
      args.push('-tech-detect'); // technology detection
      args.push('-sr');           // save response
      args.push('-json');
      break;

    case 'api_fuzz_arjun': // arjun — URL parameter discovery
      args.push('-u', target);
      args.push('-t', String(threads || 5));  // threads
      args.push('--passive');                  // passive + active discovery
      break;

    case 'api_fuzz_ffuf': // ffuf — API endpoint fuzzing
      // Use FUZZ keyword in URL path; default to /api/FUZZ
      const ffufWordlist = parameters.wordlist || '/usr/share/wordlists/dirb/common.txt';
      const ffufUrl = target.endsWith('/') ? `${target}api/FUZZ` : `${target}/api/FUZZ`;
      args.push('-u', ffufUrl);
      args.push('-w', ffufWordlist);
      args.push('-mc', '200,201,204,301,302,307,401,403');
      args.push('-json');
      args.push('-ac');          // auto-calibrate filtering
      if (parameters.cookie) args.push('-H', `Cookie: ${parameters.cookie}`);
      if (threads) args.push('-t', String(threads));
      break;

    case 'auth_audit': // nuclei — authentication security templates
      args.push('-no-color');
      args.push('-u', target);
      args.push('-t', '/root/nuclei-templates/technologies/');
      args.push('-t', '/root/nuclei-templates/vulnerabilities/generic/');
      // Include auth-related templates if they exist
      args.push('-include-templates', '/root/nuclei-templates/vulnerabilities/');
      args.push('-severity', 'info,low,medium,high,critical');
      if (parameters.auth_template) args.push('-t', parameters.auth_template);
      break;
  }

  // Append extra args (split by whitespace)
  if (extra_args) {
    const extra = typeof extra_args === 'string'
      ? extra_args.split(/\s+/).filter(Boolean)
      : [];
    args.push(...extra);
  }

  return args;
}

// ── Main entry: executeScan ───────────────────────────────────────────
export async function executeScan(scanTaskId) {
  if (runningScans.has(scanTaskId)) {
    return { ok: false, error: 'Scan is already executing' };
  }

  const db = getDb();

  const task = db.prepare(
    `SELECT scan_task_id, target, scan_type, parameters, status, created_by, ${hasScanIntegrity(db)?'pipeline_id':'NULL AS pipeline_id'} FROM scan_tasks WHERE scan_task_id = ?`
  ).get(scanTaskId);
  if (!task) return { ok: false, error: 'Scan task not found' };
  if (task.status === 'RUNNING') return { ok: false, error: 'Scan is already running' };

  if (isProgramScan(task.scan_type) && task.status !== 'PENDING') return {ok:false,error:'请新建程序测试任务以保留发现和验证证据'};

  if (task.status !== 'PENDING') return {ok:false,error:'请新建关联扫描重试，原结果保留'};

  const parent=task.pipeline_id ? db.prepare('SELECT * FROM pipelines WHERE pipeline_id=? AND created_by=?').get(task.pipeline_id,task.created_by) : null;
  const rejectScope = error => {
    db.prepare("UPDATE scan_tasks SET status='FAILED',completed_at=?,error_message=? WHERE scan_task_id=? AND status='PENDING'")
      .run(new Date().toISOString(),error,scanTaskId);
    return {ok:false,status:'FAILED',scanTaskId,error};
  };
  if(task.pipeline_id && !parent) return rejectScope('扫描任务归属无效');
  let parentConfig={}; try {parentConfig=JSON.parse(parent?.config || '{}');} catch {}
  const scope=parentConfig.task_scope ? taskScope(parent) : null;
  const scopedTarget=/^[^/]+:\d+$/.test(task.target) ? `tcp://${task.target}` : task.target;
  const blocked=scope ? scopeBlockReason(scope,scopedTarget,task.scan_type) : null;
  if(blocked) return rejectScope(blocked);
  let nativeSource;
  try {const params=JSON.parse(task.parameters || '{}');nativeSource=params.cscan_target || params.source_path;} catch {}
  if(scope && nativeSource) {
    const reason=scopeBlockReason(scope,nativeSource,'source_scan');
    if(reason) return rejectScope('CScan 源码路径：'+reason);
  }

  runningScans.add(scanTaskId);

  // Mark as RUNNING
  const now = new Date().toISOString();
  try {
  db.prepare("UPDATE scan_tasks SET status = 'RUNNING', started_at = ?, target_profile = NULL, target_class = ? WHERE scan_task_id = ?")
    .run(now, normalizeTarget(task.target).target_class, scanTaskId);

    let parameters = {};
    try { parameters = JSON.parse(task.parameters || '{}'); } catch {}
    const timeoutSec = parameters.timeout || 300;
    const timeoutMs = timeoutSec * 1000;

    const runAbortableTool = async (toolId, args, options) => {
      if (scanAbortFlags.get(scanTaskId)) return {success:false,aborted:true,exitCode:-2,stdout:'',stderr:'扫描被操作员中止'};
      const controller = new AbortController();
      const traceId=!options.onOutput?beginToolRun(db,scanTaskId,toolId,args.includes('--iflist')?'network_context':'lan_discovery'):null;
      const result=await raceScanWithAbort(runTool(toolId,args,{...options,signal:controller.signal}),scanTaskId,controller);
      if(traceId) finishToolRun(db,traceId,scanTaskId,toolId,result,{records:[],diagnostics:{parser_version:1,tool_reported_count:null,parsed_records:null,coverage:'auxiliary output retained'}});
      return {...result,toolRunId:traceId};
    };

    // Helper: run one tool, parse results, store them
    const insertResult = db.prepare(`
      INSERT INTO scan_results (scan_task_id, result_type, result_data, severity, confidence, mitre_technique_id, source_tool, captured_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const outcomes = [];
    function linkAuxiliaryResult(id, toolRunId, index) {
      if(!toolRunId) return;
      db.prepare('UPDATE scan_results SET tool_run_id=?,record_index=? WHERE id=?').run(toolRunId,index,id);
      db.prepare("UPDATE scan_tool_runs SET diagnostics=json_set(diagnostics,'$.persisted_records',(SELECT COUNT(*) FROM scan_results WHERE tool_run_id=?)) WHERE tool_run_id=?").run(toolRunId,toolRunId);
    }


    function recordFailure(toolId, error, result = {}) {
      const details = { error, exit_code: result.exitCode ?? null, timed_out: !!result.timedOut };
      insertResult.run(scanTaskId, 'scan_error', JSON.stringify(details), 'info', null, null, toolId, new Date().toISOString());
      outcomes.push({ tool_id: toolId, success: false, ...details });
    }

    async function runAndStore(scanType, toolId, target, params, timeout, { nonFatal = false } = {}) {
      if (scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');
      if (['web_scan_nikto','api_fuzz_ffuf'].includes(scanType)) {
        const normalized=normalizeTarget(target).target_url || target;
        const knownEndpoint=parent && db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='task_entries'").get()
          && db.prepare("SELECT 1 FROM task_entries WHERE pipeline_id=? AND value=? AND kind IN ('form','api_path') LIMIT 1").get(parent.pipeline_id,normalized);
        const reason=webDirectoryScanBlockReason(normalized,{endpoint:!!knownEndpoint}) || directoryOptionsBlockReason(toolId,normalized,params);
        if(reason) {recordFailure(toolId,reason);throw new Error(reason);}
        // Validate the actual fuzz base, not just the original website root.
        const probeBase=toolId==='ffuf'?new URL('api/',normalized).href:normalized;
        const gate=await checkWebDirectory(probeBase,{
          cookie:params.cookie,allowMissingBase:toolId==='ffuf',
          allowUrl:url=>!scope || isTargetInScope(scope,url),
          request:spec=>runAbortableTool('target-request',[JSON.stringify(spec)],{
            target:normalized,timeout:5000,onOutput:()=>{},
          }),
        });
        insertResult.run(scanTaskId,'scan_evidence',JSON.stringify({phase:'directory_preflight',tool:toolId,
          allowed:gate.allowed,reason:gate.reason,comparisons:gate.evidence}), 'info',null,null,toolId,new Date().toISOString());
        if(!gate.allowed) {recordFailure(toolId,gate.reason);throw new Error(gate.reason);}
        if(scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');
        target=normalized;
      }
      const args = buildArgs(scanType, target, params);
      const runId = beginToolRun(db,scanTaskId,toolId,scanType);
      const collector = createScanOutputCollector(scanType);
      let result;
      try {
        result = classifyToolResult(toolId, await runAbortableTool(toolId,args,{timeout,onOutput:collector.push}));
      } catch(error) {
        result={success:false,exitCode:-1,stdout:'',stderr:'',error:error.message};
      }
      if (scanAbortFlags.get(scanTaskId) || result.executionMode === 'aborted') result={...result,success:false,aborted:true,error:'扫描被操作员中止'};
      const parsed=collector.finish(result);
      for(const row of parsed.records) if(row.result_type==='scan_evidence') Object.assign(row.result_data,{args:redactToolArgs(args,toolId),executionMode:result.executionMode});
      if (['app_discovery_httpx','app_discovery_whatweb'].includes(scanType) && !parsed.records.some(r=>['http_probe','technology_detection'].includes(r.result_type)))
        result={...result,success:false,error:result.error || 'HTTP probe returned no reachable endpoints'};
      if (!result.success) parsed.records.push({result_type:nonFatal?'scan_warning':'scan_error',severity:'info',source_tool:toolId,
        result_data:{error:result.error,exit_code:result.exitCode,timed_out:!!result.timedOut,aborted:!!result.aborted,output_limit_exceeded:!!result.outputLimitExceeded}});
      parsed.diagnostics.evidence_truncated=!!result.outputLimitExceeded || !!parsed.diagnostics.evidence_truncated;
      // Store output and recognized records atomically before deciding task status.
      const count=finishToolRun(db,runId,scanTaskId,toolId,result,parsed);
      outcomes.push({tool_id:toolId,success:result.success,error:result.error,non_blocking:nonFatal,tool_run_id:runId});
      if(result.aborted) throw new Error('扫描被操作员中止');
      if (!result.success && scanType==='port_scan' && params.discover_topology && !result.timedOut
          && /traceroute|root|privileg|raw socket/i.test((result.stderr || '')+(result.error || ''))) {
        // Retain this attempt and its evidence before the fallback attempt.
        outcomes[outcomes.length-1].non_blocking=true;
        return count + await runAndStore(scanType,toolId,target,{...params,discover_topology:false},timeout,{nonFatal});
      }
      if(!result.success && !nonFatal) throw new Error(result.error || `${toolId} failed`);
      return count;
    }

    let totalResults = 0;
    let contextResults = 0;
    let networkContext = null;
    if (task.scan_type === 'topology_scan' || (task.scan_type === 'port_scan' && parameters.discover_topology)) {
      const context = await runAbortableTool('nmap', ['--iflist'], { timeout: 15000 });
      if (context.success || context.stdout) {
        const data = { ...parseNmapInterfaces(context.stdout), executionMode: context.executionMode };
        networkContext = data;
        const saved=insertResult.run(scanTaskId, 'network_context', JSON.stringify(data), 'info', null, null, 'nmap', new Date().toISOString());
        linkAuxiliaryResult(saved.lastInsertRowid,context.toolRunId,0);
        contextResults++;
      }
      if (!context.success && context.executionMode !== 'aborted') {
        insertResult.run(scanTaskId, 'scan_warning', JSON.stringify({ message: '未能读取扫描环境路由，仅展示探测结果' }), 'info', null, null, 'nmap', new Date().toISOString());
      }
    }
    if (scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');

    if (task.scan_type === 'topology_scan') {
      totalResults = await runAndStore('topology_scan', 'nmap', task.target, parameters, timeoutMs);
    } else if (task.scan_type === 'web_scan') {
      // ── General web scan with optional explicit injection endpoint ──
      try {
        totalResults += await runAndStore('web_scan_nikto', 'nikto', task.target, parameters, 120_000);
      } catch (err) {
        console.warn(`[Scan] nikto failed: ${err.message}`);
      }

      if (parameters.sqli_url) {
        console.log(`[Scan] web_scan SQL injection verification: ${parameters.sqli_url}`);
        try {
          const endpoint = new URL(parameters.sqli_url);
          if (endpoint.origin !== normalizeTarget(task.target).origin) throw new Error('SQL injection endpoint is outside the selected target');
          totalResults += await runAndStore('web_scan_sqlmap', 'sqlmap', endpoint.href, parameters, timeoutMs);
        } catch (err) {
          console.warn(`[Scan] sqlmap failed: ${err.message}`);
          if (!outcomes.some(outcome => outcome.tool_id === 'sqlmap')) recordFailure('sqlmap', err.message);
        }
      }
    } else if (task.scan_type === 'brute_force') {
      // ── Brute force: http-post-form → web-brute.py, others → hydra ──
      const service = parameters.service || 'http-post-form';
      if (service === 'http-post-form') {
        console.log(`[Scan] brute_force http-post-form: web-brute.py for ${task.target}`);
        totalResults = await runAndStore('brute_force', 'web-brute', task.target, parameters, timeoutMs);
      } else {
        console.log(`[Scan] brute_force ${service}: hydra for ${task.target}`);
        totalResults = await runAndStore('brute_force', 'hydra', task.target, parameters, timeoutMs);
      }
    } else if (isProgramScan(task.scan_type)) {
      const controller = new AbortController();
      const audit = await raceScanWithAbort((async () => {
        const context = {db, parameters, signal:controller.signal, runTool, parseResults};
        if (task.scan_type === 'source_scan') return auditSources(task, context);
        return scanProgramAgent(task,context);
      })(), scanTaskId, controller);
      if (!audit.outcomes) throw new Error(audit.stderr || '程序审计失败');
      totalResults += audit.count;
      outcomes.push(...audit.outcomes);
    } else if (task.scan_type === 'ad_scan') {
      // ── AD scan: netexec SMB enumeration ──
      console.log(`[Scan] ad_scan: netexec SMB for ${task.target}`);
      totalResults = await runAndStore('ad_scan', 'netexec', task.target, parameters, timeoutMs);
    } else if (task.scan_type === 'cloud_scan') {
      // ── Cloud scan: cloudmapper audit (optional: + pacu) ──
      console.log(`[Scan] cloud_scan step 1: cloudmapper for ${task.target}`);
      try {
        totalResults += await runAndStore('cloud_scan', 'cloudmapper', task.target, parameters, 120_000);
      } catch (err) {
        console.warn(`[Scan] cloudmapper failed: ${err.message}`);
      }
      // Optional: run pacu for AWS exploitation if credentials provided
      if (parameters.pacu_profile) {
        console.log(`[Scan] cloud_scan step 2: pacu for ${task.target}`);
        try {
          totalResults += await runAndStore('cloud_scan', 'pacu', task.target, parameters, timeoutMs);
        } catch (err) {
          console.warn(`[Scan] pacu failed: ${err.message}`);
        }
      }

    // ── Application target scan types ─────────────────────────────────
    } else if (task.scan_type === 'app_discovery') {
      if (scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');
      const httpRun=beginToolRun(db,scanTaskId,'http-discovery','app_discovery');
      const controller=new AbortController();
      const probes=await raceScanWithAbort(probeTarget(task.target,{signal:controller.signal,
        allowUrl:scope ? url=>isTargetInScope(scope,url) : undefined}),scanTaskId,controller);
      const records=Array.isArray(probes)?probes:probes.partialResults || [];
      const success=Array.isArray(probes) && !scanAbortFlags.get(scanTaskId);
      const httpResult={success,exitCode:success?0:-1,timedOut:!!probes.timedOut,aborted:!!scanAbortFlags.get(scanTaskId),error:success?null:probes.stderr || '扫描被操作员中止'};
      if(!success) records.push({result_type:'scan_error',source_tool:'http-discovery',severity:'info',result_data:{error:httpResult.error}});
      totalResults+=finishToolRun(db,httpRun,scanTaskId,'http-discovery',httpResult,{records,diagnostics:{parser_version:1,tool_reported_count:null,parsed_records:records.length}});
      outcomes.push({tool_id:'http-discovery',success,error:httpResult.error});
      if(httpResult.aborted) throw new Error('扫描被操作员中止');
      if(scope) {
        insertResult.run(scanTaskId,'scan_warning',JSON.stringify({message:'结构化任务范围启用：仅执行受控 HTTP 探测，跳过可能跟随链接或重定向的通用指纹工具'}),
          'info',null,null,'scope-gate',new Date().toISOString());
      } else {
      // ── Dual-step: whatweb (tech fingerprint) + httpx (HTTP probe) ──
      console.log(`[Scan] app_discovery step 1/2: whatweb for ${task.target}`);
      try {
        totalResults += await runAndStore('app_discovery_whatweb', 'whatweb', task.target, parameters, 120_000, { nonFatal: true });
      } catch (err) {
        console.warn(`[Scan] whatweb failed: ${err.message}`);
      }

      console.log(`[Scan] app_discovery step 2/2: httpx for ${task.target}`);
      try {
        totalResults += await runAndStore('app_discovery_httpx', 'httpx', task.target, parameters, 120_000);
      } catch (err) {
        console.warn(`[Scan] httpx failed: ${err.message}`);
      }
      }

    } else if (task.scan_type === 'api_fuzz') {
      // ── Dual-step: arjun (param discovery) + ffuf (endpoint fuzzing) ──
      console.log(`[Scan] api_fuzz step 1/2: arjun for ${task.target}`);
      try {
        totalResults += await runAndStore('api_fuzz_arjun', 'arjun', task.target, parameters, timeoutMs);
      } catch (err) {
        console.warn(`[Scan] arjun failed: ${err.message}`);
      }

      console.log(`[Scan] api_fuzz step 2/2: ffuf for ${task.target}`);
      try {
        totalResults += await runAndStore('api_fuzz_ffuf', 'ffuf', task.target, parameters, timeoutMs);
      } catch (err) {
        console.warn(`[Scan] ffuf failed: ${err.message}`);
      }

    } else if (task.scan_type === 'auth_audit') {
      // ── Single-step: nuclei with auth/vuln templates ──
      console.log(`[Scan] auth_audit: nuclei for ${task.target}`);
      totalResults = await runAndStore('auth_audit', 'nuclei', task.target, parameters, timeoutMs);

    } else {
      // ── Single-tool scan types ──
      const toolId = SCAN_TOOL_MAP[task.scan_type];
      if (!toolId) throw new Error(`Unknown scan type: ${task.scan_type}`);
      totalResults = await runAndStore(task.scan_type, toolId, task.target, parameters, timeoutMs);
    }

    if (scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');
    if (networkContext) {
      const targetHosts = db.prepare("SELECT result_data FROM scan_results WHERE scan_task_id = ? AND result_type = 'host_discovery'")
        .all(scanTaskId).map(row => JSON.parse(row.result_data)).filter(data => !data.traceTarget).map(data => data.host);
      const lanScope = selectLanDiscoveryScope(task.target, networkContext, targetHosts);
      const discoveryScope = lanScope.cidr ? topologyDiscoveryScope(scope, scopedTarget, lanScope.cidr) : null;
      let lanToolRunId=null,lanRecordIndex=0;
      const storeLanResult = (type, data) => {
        const saved=insertResult.run(scanTaskId, type, JSON.stringify(data), 'info', null, null, 'nmap', new Date().toISOString());
        linkAuxiliaryResult(saved.lastInsertRowid,lanToolRunId,lanRecordIndex++);
        contextResults++;
      };
      if (!lanScope.cidr) storeLanResult('scan_warning', { phase: 'lan-discovery', message: lanScope.reason });
      else if (!discoveryScope)
        storeLanResult('scan_warning',{phase:'lan-discovery',message:'局域网发现范围超出任务范围或命中排除项，未执行'});
      else {
        const args = ['-sn', '-n', '--reason', '-e', lanScope.device, '--max-retries', '1',
          ...(discoveryScope.excludes.length ? ['--exclude', discoveryScope.excludes.join(',')] : []), lanScope.cidr];
        try {
          const discovery = await runAbortableTool('nmap', args, { timeout: Math.min(timeoutMs, 120000) });
          lanToolRunId=discovery.toolRunId;
          storeLanResult('scan_evidence', { phase: 'lan-discovery', purpose: 'topology_only', args, output: discovery.stdout || '',
            error: discovery.stderr || discovery.error || '', executionMode: discovery.executionMode });
          const hosts = parseNmapResults(discovery.stdout || '').filter(row => row.result_type === 'host_discovery'
            && row.result_data.status === 'up' && isTargetInScope(discoveryScope, row.result_data.host));
          for (const host of hosts) storeLanResult('lan_host_discovery', { ...host.result_data, scope: lanScope.cidr });
          if (discovery.aborted || discovery.executionMode==='aborted' || scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');
          storeLanResult('lan_scope', { ...lanScope, purpose: 'topology_only', excludes: discoveryScope.excludes,
            complete: discovery.success === true && !discovery.timedOut });
          if (!discovery.success || discovery.timedOut) storeLanResult('scan_warning', { phase: 'lan-discovery',
            message: '局域网发现未完成，仅展示已响应主机；' + (discovery.error || discovery.stderr || '探测超时或失败') });
        } catch (error) {
          if (scanAbortFlags.get(scanTaskId)) throw error;
          storeLanResult('scan_warning', { phase: 'lan-discovery', message: '局域网发现失败：' + error.message });
        }
      }
    }
    totalResults = db.prepare('SELECT COUNT(*) n FROM scan_results WHERE scan_task_id=?').get(scanTaskId).n;
    if (scanAbortFlags.get(scanTaskId)) throw new Error('扫描被操作员中止');
    if (!outcomes.some(outcome => outcome.success)) throw new Error(outcomes.map(outcome => `${outcome.tool_id}: ${outcome.error}`).join('; ') || 'No scan tool succeeded');
    const finalStatus = outcomes.some(outcome => !outcome.success) ? 'PARTIAL' : 'COMPLETED';
    const warnings = outcomes.filter(outcome => !outcome.success).map(outcome => `${outcome.tool_id}: ${outcome.error || outcome.warning || 'scan failed'}`).join('; ');
    const completedAt = new Date().toISOString();
    const findings = db.prepare('SELECT * FROM scan_results WHERE scan_task_id = ?').all(scanTaskId);
    const discovered = buildDiscoveredProfile(task.target, findings);
    db.prepare('UPDATE scan_tasks SET status = ?, completed_at = ?, error_message = ?, target_class = ?, target_profile = ? WHERE scan_task_id = ?')
      .run(finalStatus, completedAt, warnings || null, discovered.target_class, JSON.stringify(discovered), scanTaskId);
    // WebSocket: notify scan completed (include operator info)
    const ws = getWsManager();
    const taskInfo = db.prepare('SELECT created_by FROM scan_tasks WHERE scan_task_id = ?').get(scanTaskId);
    if (ws) (isProgramScan(task.scan_type) ? (event,data)=>ws.broadcastProgram(taskInfo?.created_by,event,data) : (event,data)=>ws.broadcast(event,data))('scan:completed', {
      scanTaskId, status: finalStatus, resultsCount: totalResults, error: warnings || null,
      scanType: task.scan_type, target: task.target,
      userId: taskInfo?.created_by || null,
      username: taskInfo?.created_by || null,
    });

    return { ok: true, scanTaskId, status: finalStatus, resultsCount: totalResults, outcomes, targetProfile: discovered };

  } catch (err) {
    const isAbort = scanAbortFlags.get(scanTaskId);
    const usable = !isProgramScan(task.scan_type) && db.prepare("SELECT 1 FROM scan_results WHERE scan_task_id=? AND result_type NOT IN ('scan_error','scan_warning','scan_evidence','raw_output','network_context') LIMIT 1").get(scanTaskId);
    const finalStatus = isAbort ? 'CANCELLED' : usable ? 'PARTIAL' : 'FAILED';
    const completedAt = new Date().toISOString();
    db.prepare("UPDATE scan_tasks SET status = ?, completed_at = ?, error_message = ? WHERE scan_task_id = ?")
      .run(finalStatus, completedAt, err.message, scanTaskId);
    // WebSocket: notify scan failed/cancelled (include operator info)
    const ws = getWsManager();
    const taskInfo = db.prepare('SELECT created_by FROM scan_tasks WHERE scan_task_id = ?').get(scanTaskId);
    if (ws) (isProgramScan(task.scan_type) ? (event,data)=>ws.broadcastProgram(taskInfo?.created_by,event,data) : (event,data)=>ws.broadcast(event,data))('scan:completed', {
      scanTaskId, status: finalStatus, error: err.message,
      scanType: task.scan_type, target: task.target,
      userId: taskInfo?.created_by || null,
      username: taskInfo?.created_by || null,
    });

    return { ok: false, scanTaskId, status: finalStatus, error: err.message,resultsCount:db.prepare('SELECT COUNT(*) n FROM scan_results WHERE scan_task_id=?').get(scanTaskId).n };
  } finally {
    scanAbortFlags.delete(scanTaskId);
    runningScans.delete(scanTaskId);
  }
}
