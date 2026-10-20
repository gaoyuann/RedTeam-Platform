import {readFile} from 'node:fs/promises';
import {sourceTarget} from './sourceScanConnections.js';
import {parseTargetRequest} from '../tools/targetRequest.js';

export const isProgramScan = type => ['program_scan', 'source_scan'].includes(type);
export const isProgramMode = mode => ['program_dynamic', 'source_assisted'].includes(mode);
export const isProgramFinding = type => ['program_finding', 'source_finding'].includes(type);
export function programExecutionTarget(task) {
  let parameters = {};
  try {const value=task.parameters || task.config || {}; parameters=typeof value==='string' ? JSON.parse(value) : value;} catch {}
  if(parameters.source_path) return parameters.runtime_target || null;
  if(parameters.input_kind !== 'source') return task.target;
  if(parameters.runtime_target) return parameters.runtime_target;
  // Older task forms stored the declared application root separately from its
  // source directory. Do not interpret the source hosting URL itself as runtime.
  try {
    const target=new URL(sourceTarget(task.target)),source=new URL(sourceTarget(parameters.source_url));
    if(['http:','https:'].includes(target.protocol) && target.origin===source.origin
      && target.pathname==='/' && !target.search && source.pathname!=='/') return target.href;
  } catch {}
  return null;
}

export function programNetworkTarget(target) {
  if(/^tcp:\/\//i.test(target)) {
    const url=new URL(sourceTarget(target));
    return url.host;
  }
  return target;
}
const projectsFile = new URL('../../../data/program-tests/projects.json', import.meta.url);

// The catalogue describes deployed programs, not vulnerabilities or installed software inferred from an IP.
export async function loadProgramProjects(filename = process.env.PROGRAM_TEST_PROJECTS_FILE || projectsFile) {
  let items;
  try {items = JSON.parse(await readFile(filename, 'utf8'));}
  catch (error) {if (error.code === 'ENOENT') return []; throw new Error('程序测试项目配置无法读取');}
  if (!Array.isArray(items) || items.length > 100) throw new Error('程序项目配置须为最多100项的数组');
  const ids = new Set(), targets = new Set();
  return items.map(item => {
    const target = sourceTarget(item.target);
    if (!/^[\w-]{1,64}$/.test(item.id || '') || ids.has(item.id) || targets.has(target)) throw new Error('程序项目标识或运行入口重复/无效');
    ids.add(item.id); targets.add(target);
    const checks = item.checks || [];
    if (!Array.isArray(checks) || checks.length > 20) throw new Error('每个程序最多20个专项检测用例');
    const checkIds = new Set();
    for (const check of checks) {
      if (!/^[\w-]{1,64}$/.test(check.id || '') || checkIds.has(check.id) || !check.title) throw new Error('程序检测用例缺少唯一标识或名称');
      checkIds.add(check.id);
      for (const request of [check.baseline, check.probe]) parseTargetRequest([JSON.stringify(request)], target);
      if (JSON.stringify(check.baseline) === JSON.stringify(check.probe)) throw new Error('检测用例须包含不同的正常对照与验证输入');
      if (typeof check.match?.contains !== 'string' || !check.match.contains || check.match.contains.length > 1024) throw new Error('检测用例须定义具体响应判据');
    }
    return {id:item.id, name:String(item.name || item.id), target, version:String(item.version || '未登记'), checks};
  });
}

export const publicProgramProject = ({checks, ...project}) => ({...project, check_count:checks.length});

function observation(result) {try {return JSON.parse(result.stdout || '{}');} catch {return {};}}
function excerpt(value) {return String(value || '').slice(0, 12000);}

// Dynamic inspection uses real HTTP/TCP responses and tool results. It never synthesizes a vulnerability from an AI answer.
export async function scanProgram(task, {db, parameters = {}, signal, runTool, parseResults, projects, tools=['nikto','nuclei']}) {
  const insert = db.prepare('INSERT INTO scan_results(scan_task_id,result_type,result_data,severity,source_tool,captured_at) VALUES (?,?,?,?,?,?)');
  let count = 0, requests = 0, findings = 0;
  const outcomes = [], endpoints = new Set([sourceTarget(task.target)]), seen = new Set();
  const store = (type, data, tool = 'program-detector', severity = 'info') => {
    count++; return Number(insert.run(task.scan_task_id,type,JSON.stringify(data),severity,tool,new Date().toISOString()).lastInsertRowid);
  };
  const checkAbort = () => {if (signal?.aborted) throw new Error('程序扫描已取消');};
  const execute = async (tool, args, options = {}) => {
    checkAbort();
    let result;
    try {result = await runTool(tool,args,{...options,signal,target:task.target});}
    catch (error) {checkAbort(); result = {success:false,error:error.message};}
    checkAbort();
    outcomes.push({tool_id:tool,success:!!result.success,error:result.error || null});
    if (!result.success) store('scan_error',{error:result.error || result.stderr || '检测失败'},tool);
    return result;
  };
  const request = async spec => {
    parseTargetRequest([JSON.stringify(spec)],task.target);
    requests++;
    const result = await execute('target-request',[JSON.stringify(spec)],{timeout:15000});
    const data = observation(result);
    const evidenceId = store('application_observation',{...data,request:spec,response:excerpt(data.response),error:result.error || null},'target-request');
    return {result,data,evidenceId};
  };
  const finding = (data, tool, severity = 'medium') => {
    const key = [data.detector_id,data.url,data.parameter || ''].join('|');
    if (seen.has(key)) return;
    seen.add(key); findings++;
    store('program_finding',{...data,severity,verification_status:'needs_review',runtime_verified:false},tool,severity);
  };
  const root = await request({url:task.target});
  const http = /^https?:/i.test(task.target);
  let project;
  try {project = (projects || await loadProgramProjects()).find(item => item.target === sourceTarget(task.target));}
  catch (error) {outcomes.push({tool_id:'program-catalogue',success:false,error:error.message});store('scan_error',{error:error.message});}

  if (http && root.result.success) {
    const origin = new URL(task.target).origin;
    // Only inspect links/forms actually observed at this endpoint; do not guess other services or follow redirects.
    for (const match of String(root.data.response || '').matchAll(/(?:href|action)\s*=\s*["']([^"'#]+)["']/gi)) {
      try {
        const url = new URL(match[1].replace(/&amp;/g,'&'),task.target);
        if (url.origin === origin && !url.username && !url.password && !url.hash
            && !/\.(?:png|jpg|css|js|svg|ico|c|cpp|h|txt|s)$/i.test(url.pathname) && endpoints.size < 8) endpoints.add(url.href);
      } catch {}
    }
    for (const url of endpoints) {
      const observed = url === sourceTarget(task.target) ? root : await request({url});
      if (!observed.result.success) continue;
      const error = observed.data.response?.match(/(?:Traceback \(most recent call last\)|Fatal error:|SQL syntax[^\n<]{0,120}|Exception in thread[^\n<]{0,120})/i);
      if (error) finding({title:'程序错误信息泄露',detector_id:'runtime-error-disclosure',url,cwe:'CWE-209',
        reason:'运行响应包含具体错误诊断：'+error[0],evidence_ids:[observed.evidenceId],
        preconditions:'可访问此程序入口；错误信息不等于注入或内存漏洞成立',
        demonstration_supported:false,demonstration_reason:'尚缺可复现触发输入及正常对照'},'response-check','low');
    }
    // Generic tools remain candidates; template matches are not attack success.
    for (const [tool,type,args] of [
      ['nikto','web_scan_nikto',['-h',task.target,'-maxtime','60']],
      ['nuclei','vuln_scan',['-u',task.target,'-jsonl','-severity','low,medium,high,critical','-rl','5','-timeout','8','-retries','0','-exclude-tags','dos,fuzz,bruteforce','-no-interactsh']]
    ]) {
      if(!tools.includes(tool)) continue;
      const result = await execute(tool,args,{timeout:120000});
      store('raw_output',{output:excerpt((result.stdout || '')+'\n'+(result.stderr || ''))},tool);
      if (!result.success) continue;
      let rows = parseResults(type,result.stdout || '');
      if (tool === 'nuclei') {
        rows = String(result.stdout || '').split('\n').flatMap(line => {
          try {
            const item = JSON.parse(line);
            return [{result_type:'vulnerability',severity:item.info?.severity,
              result_data:{template_id:item['template-id'],name:item.info?.name,url:item['matched-at'] || item.host,
                description:item.info?.description,request:item.request,response:excerpt(item.response),
                matcher_name:item['matcher-name'],cwe:item.info?.classification?.['cwe-id']}}];
          } catch {return [];}
        });
      }
      for (const row of rows) {
        if (!['vulnerability','web_vuln','sql_injection'].includes(row.result_type) || row.severity === 'info') continue;
        const data = row.result_data || {};
        let url;
        try {url = new URL(data.url || data.path || task.target,task.target); if (url.origin !== origin) continue;} catch {continue;}
        finding({title:data.name || data.finding || data.template_id || data.message || data.description || '程序风险候选',
          detector_id:data.template_id || data.osvdb_id || tool+'-'+(data.finding || data.message || data.description || JSON.stringify(data)),
          url:url.href,reason:data.finding || data.message || data.description || JSON.stringify(data),tool_result:data,
          preconditions:'工具检测候选，须核对版本、输入点及真实影响',demonstration_supported:true},tool,row.severity || 'medium');
      }
    }
  }
  for (const check of project?.checks || []) {
    const baseline = await request(check.baseline), probe = await request(check.probe);
    if (!baseline.result.success || !probe.result.success) continue;
    const matched = String(probe.data.response || '').includes(check.match.contains)
      && !String(baseline.data.response || '').includes(check.match.contains)
      && (check.match.status_code === undefined || probe.data.status_code === check.match.status_code);
    store('program_check',{check_id:check.id,title:check.title,matched,evidence_ids:[baseline.evidenceId,probe.evidenceId]});
    if (matched) finding({title:check.title,detector_id:check.id,url:task.target,cwe:check.cwe || null,
      reason:'专项检测命中响应判据，正常对照没有该响应',preconditions:check.preconditions || '按已登记的程序版本和交互用例验证',
      evidence_ids:[baseline.evidenceId,probe.evidenceId],demonstration_supported:true,
      demonstration:{baseline:check.baseline,probe:check.probe,expected_evidence:check.match.contains}},'program-recipe',check.severity || 'medium');
  }
  const incomplete = !http && !(project?.checks.length);
  if (incomplete) outcomes.push({tool_id:'program-coverage',success:false,error:'TCP 入口已检查，但未登记协议专项检测用例，不能声明完成漏洞扫描'});
  store('program_coverage',{mode:'program_dynamic',project:project ? publicProgramProject(project) : null,
    target:task.target,requests,endpoints:[...endpoints],findings,checks:project?.checks.length || 0,
    detectors:outcomes,source_required:false,complete:!incomplete && outcomes.every(item => item.success),
    note:'服务可达和工具执行成功不等于漏洞成立；未检测的程序或漏洞类型不计入覆盖。'});
  return {count,outcomes};
}
