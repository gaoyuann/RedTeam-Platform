import { createHash } from 'node:crypto';
import { isTargetInScope, scopeBlockReason, taskScope } from './taskScope.js';
import { webDirectoryScanBlockReason, webPageEntries } from './webScanPolicy.js';

const id = (prefix, ...parts) => `${prefix}_${createHash('sha256').update(JSON.stringify(parts)).digest('hex').slice(0,24)}`;
const json = value => { try { return JSON.parse(value || '{}'); } catch { return {}; } };
const now = () => new Date().toISOString();
export const hasScanCoverage = db => Boolean(db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='task_checks'").get());

function addCheck(db, pipeline, {serviceId=null, entryId=null, type, scanType=null, target=null, state='planned', reason=null, sourceId=null}) {
  const checkId=id('check',pipeline.pipeline_id,serviceId,entryId,type,target);
  db.prepare(`INSERT OR IGNORE INTO task_checks
    (check_id,pipeline_id,service_id,entry_id,check_type,scan_type,target,state,reason,source_record_id,created_at,updated_at)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(checkId,pipeline.pipeline_id,serviceId,entryId,type,scanType,target,state,reason,sourceId,now(),now());
  return db.prepare('SELECT * FROM task_checks WHERE check_id=?').get(checkId);
}

function addEntry(db,pipeline,{serviceId=null,kind,value,state='observed',sourceId=null}) {
  const entryId=id('entry',pipeline.pipeline_id,kind,value);
  db.prepare(`INSERT OR IGNORE INTO task_entries(entry_id,pipeline_id,service_id,kind,value,state,source_record_id)
    VALUES (?,?,?,?,?,?,?)`).run(entryId,pipeline.pipeline_id,serviceId,kind,value,state,sourceId);
  return db.prepare('SELECT * FROM task_entries WHERE entry_id=?').get(entryId);
}

function normalizedUrl(value) {
  try {
    const url=new URL(value);
    if(!['http:','https:'].includes(url.protocol) || url.username || url.password || url.hash) return null;
    return url.href;
  } catch {return null;}
}

function classifyCheck(scope,target,scanType) {
  const bounded=/^[^/]+:\d+$/.test(target) ? `tcp://${target}` : target;
  const reason=scopeBlockReason(scope,bounded,scanType);
  if(!reason) return {state:'planned',reason:null};
  return {state:isTargetInScope(scope,bounded)?'missing_condition':'out_of_scope',reason};
}

export function beginCoverage(db,pipeline,initialScans) {
  if(!hasScanCoverage(db)) return [];
  const planned=[];
  for(const scan of initialScans) {
    const check=addCheck(db,pipeline,{type:scan.scan_type,scanType:scan.scan_type,target:scan.target,
      ...classifyCheck(taskScope(pipeline),scan.target,scan.scan_type)});
    if(check.state==='planned') planned.push(check);
  }
  return planned;
}

export function pendingChecks(db,pipelineId) {
  if(!hasScanCoverage(db)) return [];
  return db.prepare("SELECT * FROM task_checks WHERE pipeline_id=? AND state='planned' ORDER BY created_at,check_id").all(pipelineId);
}

export function markCheck(db,checkId,state,{scanTaskId=null,reason=null}={}) {
  if(!checkId || !hasScanCoverage(db)) return;
  db.prepare('UPDATE task_checks SET state=?,scan_task_id=COALESCE(?,scan_task_id),reason=?,updated_at=? WHERE check_id=?')
    .run(state,scanTaskId,reason,now(),checkId);
}

export function completeCoverage(db,pipelineId,reason='任务在检查完成前结束') {
  if(!hasScanCoverage(db)) return;
  db.prepare("UPDATE task_checks SET state='not_checked',reason=?,updated_at=? WHERE pipeline_id=? AND state IN ('planned','running')")
    .run(reason,now(),pipelineId);
}

function recordAsset(db,pipeline,host,state,sourceId) {
  const assetId=id('asset',pipeline.pipeline_id,host);
  db.prepare(`INSERT OR IGNORE INTO task_assets(asset_id,pipeline_id,host,state,source_record_id) VALUES (?,?,?,?,?)`)
    .run(assetId,pipeline.pipeline_id,host,state,sourceId);
  if(state==='reachable') db.prepare("UPDATE task_assets SET state='reachable' WHERE asset_id=?").run(assetId);
  return assetId;
}

function recordService(db,pipeline,assetId,port,protocol,name,sourceId,state='open') {
  const serviceId=id('service',pipeline.pipeline_id,assetId,port,protocol);
  db.prepare(`INSERT OR IGNORE INTO task_services(service_id,pipeline_id,asset_id,port,protocol,name,state,source_record_id)
    VALUES (?,?,?,?,?,?,?,?)`).run(serviceId,pipeline.pipeline_id,assetId,port,protocol,name,state,sourceId);
  return serviceId;
}

function serviceTarget(host,port,name,declared) {
  const explicit=normalizedUrl(declared);
  if(explicit) {
    const url=new URL(explicit);
    if(url.hostname.replace(/^\[|\]$/g,'')===host && Number(url.port || (url.protocol==='https:'?443:80))===port) return explicit;
  }
  if(!/https?|ssl\/http/i.test(name)) return null;
  const scheme=/https|ssl\/http|tls/i.test(name)?'https':'http';
  return `${scheme}://${host.includes(':')?`[${host}]`:host}:${port}/`;
}

export function observePortScan(db,pipeline,scanTaskId) {
  if(!hasScanCoverage(db)) return;
  const scope=taskScope(pipeline);
  const rows=db.prepare("SELECT id,result_type,result_data FROM scan_results WHERE scan_task_id=? AND result_type IN ('host_discovery','open_port') ORDER BY id").all(scanTaskId);
  for(const row of rows) {
    const data=json(row.result_data),host=String(data.host || '').trim();
    if(!host) continue;
    const scopeHost=scope.includes.some(value=>{
      try {return new URL(value).hostname.replace(/^\[|\]$/g,'')===host;} catch {return false;}
    });
    const allowed=isTargetInScope(scope,host) || scopeHost;
    const assetId=recordAsset(db,pipeline,host,allowed && (data.status==='up' || row.result_type==='open_port')?'reachable':allowed?'unknown':'out_of_scope',row.id);
    if(row.result_type!=='open_port' || data.state!=='open') continue;
    const port=Number(data.port), protocol=String(data.protocol || 'tcp').toLowerCase();
    if(!Number.isInteger(port) || port<1 || port>65535 || !['tcp','udp'].includes(protocol)) continue;
    const serviceId=recordService(db,pipeline,assetId,port,protocol,String(data.service || 'unknown').slice(0,200),row.id);
    addCheck(db,pipeline,{serviceId,type:'service_fingerprint',state:'completed',reason:'Nmap 开放端口与服务识别',sourceId:row.id});
    const webTarget=protocol==='tcp' ? serviceTarget(host,port,String(data.service || ''),pipeline.target) : null;
    if(!webTarget) {
      const entry=addEntry(db,pipeline,{serviceId,kind:'network_service',value:`${protocol}://${host.includes(':')?`[${host}]`:host}:${port}`,sourceId:row.id});
      addCheck(db,pipeline,{serviceId,entryId:entry.entry_id,type:'service_security',state:'unsupported',
        reason:'该服务尚无已接入的专项安全检查，端口识别不等于漏洞检查',sourceId:row.id});
      addCheck(db,pipeline,{serviceId,entryId:entry.entry_id,type:'web_application',state:'not_applicable',
        reason:'服务识别结果不是 HTTP/HTTPS，不安排 Web 检查',sourceId:row.id});
      continue;
    }
    const entry=addEntry(db,pipeline,{serviceId,kind:'web_url',value:webTarget,state:allowed?'observed':'out_of_scope',sourceId:row.id});
    addCheck(db,pipeline,{serviceId,entryId:entry.entry_id,type:'web_discovery',scanType:'app_discovery',target:webTarget,
      ...classifyCheck(scope,webTarget,'app_discovery'),sourceId:row.id});
  }
  // A declared HTTP entry remains eligible for a reachability check when
  // port fingerprinting produced no usable service evidence.
  const declared=normalizedUrl(pipeline.target);
  if(declared) {
    const url=new URL(declared),host=url.hostname.replace(/^\[|\]$/g,''),port=Number(url.port || (url.protocol==='https:'?443:80));
    const assetId=recordAsset(db,pipeline,host,'unknown',null);
    const serviceId=recordService(db,pipeline,assetId,port,'tcp','用户声明的 HTTP 入口',null,'unverified');
    const entry=addEntry(db,pipeline,{serviceId,kind:'web_url',value:declared,state:'declared'});
    addCheck(db,pipeline,{serviceId,entryId:entry.entry_id,type:'web_discovery',scanType:'app_discovery',target:declared,
      ...classifyCheck(scope,declared,'app_discovery')});
  }
}

function safeUrl(value,base) {
  try {
    const url=new URL(value,base);
    // Query values may contain sessions or API keys; the entry identity is its path.
    url.search='';url.hash='';
    return normalizedUrl(url.href);
  } catch {return null;}
}

export function observeWebScan(db,pipeline,check) {
  if(!hasScanCoverage(db) || !check?.scan_task_id) return;
  const scope=taskScope(pipeline),target=check.target;
  const records=db.prepare("SELECT id,result_type,result_data FROM scan_results WHERE scan_task_id=? AND result_type IN ('http_probe','technology_detection','api_endpoint','api_parameter') ORDER BY id")
    .all(check.scan_task_id);
  const complete=check.scan_status === undefined || check.scan_status === 'COMPLETED';
  const inScopeResponse=row=>row.result_type==='http_probe' && normalizedUrl(json(row.result_data).url)
    && isTargetInScope(scope,json(row.result_data).url);
  const responded=records.some(inScopeResponse);
  const reachable=complete && records.some(row=>{
    if(!inScopeResponse(row)) return false;
    const data=json(row.result_data),status=Number(data.status_code);
    return status>=200 && status<400;
  });
  const authRequired=complete && records.some(row=>inScopeResponse(row)
    && [401,403].includes(Number(json(row.result_data).status_code)));
  const budget=scope.discovery_budget;
  const canSchedule=complete && (check.scan_type!=='app_discovery' || reachable);
  const primary=new Set([safeUrl(target,target) || target]);
  const seenUrls=new Set(db.prepare("SELECT target FROM task_checks WHERE pipeline_id=? AND check_type='new_entry_check'")
    .all(pipeline.pipeline_id).map(row=>row.target));
  const discovered=[];
  const discover=(kind,value,base,sourceId)=>{
    const url=safeUrl(value,base);
    // Strip query values from saved identities, but retain their page semantics.
    if(url) discovered.push({kind,url,sourceId,hasQuery:Boolean(new URL(value,base).search)});
  };
  for(const row of records) {
    const data=json(row.result_data);
    if(['http_probe','api_endpoint'].includes(row.result_type)) {
      discover(row.result_type==='api_endpoint'?'api_path':'web_url',data.url,target,row.id);
    }
    if(row.result_type==='api_parameter' && data.parameter) {
      const entry=addEntry(db,pipeline,{serviceId:check.service_id,kind:'parameter',value:`${target}#parameter:${String(data.parameter).slice(0,100)}`,
        state:'observed',sourceId:row.id});
      addCheck(db,pipeline,{serviceId:check.service_id,entryId:entry.entry_id,type:'parameter_validation',state:'not_checked',
        reason:'参数已发现，缺少适用的逐参数验证条件',sourceId:row.id});
    }
    if(row.result_type==='http_probe' && typeof data.body==='string') {
      for(const entry of webPageEntries(data.body,data.url || target))
        discover(entry.kind,entry.value,data.url || target,row.id);
    }
  }
  // Preserve forms/API observations even when the same URL was first observed
  // as a redirect or link. Endpoint evidence takes precedence over URL shape.
  const endpointUrls=new Set(discovered.filter(item=>item.hasQuery || ['form','api_path'].includes(item.kind)).map(item=>item.url));
  if(check.scan_type==='app_discovery') {
    if(responded && check.service_id) {
      db.prepare("UPDATE task_services SET state='http_observed' WHERE service_id=? AND state='unverified'").run(check.service_id);
      db.prepare("UPDATE task_assets SET state='reachable' WHERE asset_id=(SELECT asset_id FROM task_services WHERE service_id=?)").run(check.service_id);
    }
    const state=reachable?'planned':authRequired?'missing_condition':!complete || responded?'not_checked':'unreachable';
    const reason=reachable?null:authRequired?'HTTP 入口需要认证，未提供可用角色与凭据':!complete
      ?'入口探测未完整完成，后续检查未执行':responded
        ?'HTTP 服务已响应，但入口未返回成功状态，后续检查未执行':'未取得范围内 HTTP 响应，后续检查未执行';
    const directoryReason=webDirectoryScanBlockReason(target,{endpoint:endpointUrls.has(safeUrl(target,target))});
    for(const [type,scanType] of [['web_security','web_scan'],['api_entry_discovery','api_fuzz']]) {
      const allowed=classifyCheck(scope,target,scanType);
      const planned=directoryReason && allowed.state==='planned'?{state:'not_checked',reason:directoryReason}:allowed;
      addCheck(db,pipeline,{serviceId:check.service_id,entryId:check.entry_id,type,scanType,target,
        state:reachable?planned.state:state,reason:reachable?planned.reason:reason,sourceId:records[0]?.id || check.source_record_id});
    }
    addCheck(db,pipeline,{serviceId:check.service_id,entryId:check.entry_id,type:'authenticated_roles',state:'missing_condition',
      reason:'认证角色和可用凭据提供方尚未配置；未进行认证检查',sourceId:records[0]?.id || check.source_record_id});
  }
  let scheduled=db.prepare("SELECT COUNT(*) n FROM task_checks WHERE pipeline_id=? AND check_type='new_entry_check' AND state IN ('planned','running','completed','partial','failed')").get(pipeline.pipeline_id).n;
  for(const item of discovered) {
    const inScope=isTargetInScope(scope,item.url);
    const entry=addEntry(db,pipeline,{serviceId:check.service_id,kind:item.kind,value:item.url,state:inScope?'observed':'out_of_scope',sourceId:item.sourceId});
    if(item.kind==='form') addCheck(db,pipeline,{serviceId:check.service_id,entryId:entry.entry_id,type:'form_input_validation',
      state:inScope?'missing_condition':'out_of_scope',reason:inScope?'尚无表单方法、字段及角色条件，未执行逐字段验证':'表单入口不在任务范围内',sourceId:item.sourceId});
    if(primary.has(item.url) || seenUrls.has(item.url)) continue;
    seenUrls.add(item.url);
    if(!inScope) {addCheck(db,pipeline,{serviceId:check.service_id,entryId:entry.entry_id,type:'new_entry_check',target:item.url,
      state:'out_of_scope',reason:'新入口不在任务范围内',sourceId:item.sourceId});continue;}
    if(!canSchedule) {addCheck(db,pipeline,{serviceId:check.service_id,entryId:entry.entry_id,type:'new_entry_check',target:item.url,
      state:'not_checked',reason:authRequired?'入口需要认证，未补充检查':'来源扫描未完整完成，未补充检查',sourceId:item.sourceId});continue;}
    const directoryReason=webDirectoryScanBlockReason(item.url,{endpoint:endpointUrls.has(item.url)});
    if(directoryReason) {addCheck(db,pipeline,{serviceId:check.service_id,entryId:entry.entry_id,type:'new_entry_check',target:item.url,
      state:'not_checked',reason:directoryReason,sourceId:item.sourceId});continue;}
    if(scheduled>=budget) {addCheck(db,pipeline,{serviceId:check.service_id,entryId:entry.entry_id,type:'new_entry_check',target:item.url,
      state:'not_checked',reason:'新入口检查预算已用尽',sourceId:item.sourceId});continue;}
    const allowed=classifyCheck(scope,item.url,'web_scan');
    const result=addCheck(db,pipeline,{serviceId:check.service_id,entryId:entry.entry_id,type:'new_entry_check',scanType:'web_scan',target:item.url,
      ...allowed,sourceId:item.sourceId});
    if(result.state==='planned') scheduled++;
  }
}

export function scanCoverage(db,pipelineId) {
  if(!hasScanCoverage(db)) return null;
  const table=(name,order)=>db.prepare(`SELECT * FROM ${name} WHERE pipeline_id=? ORDER BY ${order} LIMIT 501`).all(pipelineId);
  const assets=table('task_assets','host'),services=table('task_services','asset_id,port'),
    entries=table('task_entries','kind,value'),checks=table('task_checks','created_at,check_id');
  const counts=Object.fromEntries(['task_assets','task_services','task_entries','task_checks'].map(name=>[
    name.replace('task_',''),db.prepare(`SELECT COUNT(*) n FROM ${name} WHERE pipeline_id=?`).get(pipelineId).n]));
  const states=Object.fromEntries(db.prepare('SELECT state,COUNT(*) n FROM task_checks WHERE pipeline_id=? GROUP BY state').all(pipelineId)
    .map(row=>[row.state,row.n]));
  return {counts,states,truncated:Object.values(counts).some(n=>n>500),
    assets:assets.slice(0,500),services:services.slice(0,500),entries:entries.slice(0,500),checks:checks.slice(0,500)};
}

export function scanCoveragePage(db,pipelineId,{kind='services',after='',limit=100}={}) {
  if(!hasScanCoverage(db)) return {kind,rows:[],page:{total:0,returned:0,has_more:false,next_after:''}};
  const names={assets:['task_assets','asset_id'],services:['task_services','service_id'],
    entries:['task_entries','entry_id'],checks:['task_checks','check_id']};
  if(!Object.hasOwn(names,kind)) throw Object.assign(new Error('覆盖清单类型无效'),{status:400});
  const size=Number(limit);
  if(!Number.isSafeInteger(size) || size<1 || size>500 || typeof after!=='string' || after.length>64 || after && !/^[a-z]+_[a-f0-9]{24}$/.test(after))
    throw Object.assign(new Error('覆盖清单分页参数无效'),{status:400});
  const [table,key]=names[kind];
  const rows=db.prepare(`SELECT * FROM ${table} WHERE pipeline_id=? AND ${key}>? ORDER BY ${key} LIMIT ?`).all(pipelineId,after,size+1);
  const hasMore=rows.length>size;
  if(hasMore) rows.pop();
  return {kind,rows,page:{total:db.prepare(`SELECT COUNT(*) n FROM ${table} WHERE pipeline_id=?`).get(pipelineId).n,
    returned:rows.length,has_more:hasMore,next_after:rows.at(-1)?.[key] || after}};
}
