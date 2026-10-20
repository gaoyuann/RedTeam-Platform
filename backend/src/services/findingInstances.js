import { isTargetInScope, taskScope, normalizeTaskScope } from './taskScope.js';
import { createHash } from 'node:crypto';
import { scanCollection } from './scanResultQuery.js';
import { parseResultData, resultCategory } from './scanResultCatalog.js';
export const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
export const fail = (status,message) => { throw Object.assign(new Error(message),{status}); };
export const hasStatistics = db => !!db.prepare("SELECT 1 FROM sqlite_master WHERE name='finding_instances'").get();
const str = v => typeof v==='string' && v.trim() && v.length<=2000 && !/[\r\n\0]/.test(v) ? v.trim() : null;
export function canonicalTarget(value) {
  try {
    const target=normalizeTaskScope({},value).includes[0];
    if(target.includes('://') && new URL(target).search)return null;
    return target;
  } catch { return null; }
}
export function findingIdentity(row) {
  const d=parseResultData(row.result_data) || {};
  const rule=str(d.rule_id || d.template_id || d['template-id'] || d.template || d.cve);
  const tool=str(row.source_tool);
  if(!rule || !tool) return null;
  // Tool namespaces intentionally prevent unproven cross-tool equivalence.
  if(d.file || d.file_path) {
    const version=str(d.source_version || d.commit), file=str(d.file || d.file_path), line=Number(d.line || d.line_number);
    const target=canonicalTarget(d.target);
    if(!version || !file || !target || !Number.isSafeInteger(line) || line<1)return null;
    return {kind:'source',tool,rule,target,version,file,line};
  }
  if(d.url || d['matched-at'] || d.matched_at) {
    let u;try{u=new URL(d.url || d['matched-at'] || d.matched_at);}catch{return null;}
    if(!['http:','https:'].includes(u.protocol) || u.username || u.password || u.hash || u.search)return null;
    const method=str(d.method)?.toUpperCase();
    if(!method || !/^[A-Z]+$/.test(method))return null;
    const parameter=str(d.parameter), location=str(d.parameter_location);
    if(d.parameter!=null && !parameter || d.parameter_location!=null && !location || Boolean(parameter)!==Boolean(location))return null;
    return {kind:'web',tool,rule,url:u.href,method,parameter,location};
  }
  const host=str(d.host)?.toLowerCase(), port=Number(d.port), protocol=str(d.protocol)?.toLowerCase();
  if(!host || canonicalTarget(host)!==host || host.includes('/') || !Number.isInteger(port) || port<1 || port>65535 || !['tcp','udp'].includes(protocol))return null;
  return {kind:'service',tool,rule,host,port,protocol};
}
// UDP may match host/CIDR scope, but never a TCP-only endpoint scope.
export function identityInScope(identity,scope) {
  if(!identity)return false;
  const target=identity.kind==='web'?identity.url:identity.kind==='source'?identity.target
    :identity.protocol==='udp'?identity.host:`tcp://${identity.host.includes(':')?'['+identity.host+']':identity.host}:${identity.port}`;
  return isTargetInScope(scope,target);
}
export function statisticsScope(pipeline) {
  try { return taskScope(pipeline); } catch { return null; }
}
export function scopedFindingIdentity(row,pipeline) {
  const identity=findingIdentity(row);
  const scope=statisticsScope(pipeline);
  return scope && identityInScope(identity,scope)?identity:null;
}
export function currentCandidates(db,pipeline) {
  return scanCollection(db,pipeline).rows.filter(r=>resultCategory(r)==='vulnerability');
}
export function syncInstances(db,pipeline) {
  if(!hasStatistics(db))fail(409,'统计迁移尚未安装');
  return db.transaction(()=>{
    const rows=currentCandidates(db,pipeline);
    for(const row of rows) {
      const identity=scopedFindingIdentity(row,pipeline);
      if(!identity)continue;
      const encoded=JSON.stringify(identity), id='fi_'+hash([pipeline.pipeline_id,1,identity]).slice(0,32);
      db.prepare('INSERT OR IGNORE INTO finding_instances VALUES (?,?,?,?,?)').run(id,pipeline.pipeline_id,encoded,1,new Date().toISOString());
      db.prepare('INSERT INTO finding_instance_records VALUES (?,?,?,?) ON CONFLICT(pipeline_id,finding_id) DO UPDATE SET instance_id=excluded.instance_id,basis=excluded.basis WHERE instance_id!=excluded.instance_id').run(pipeline.pipeline_id,row.id,id,'exact_identity_v1');
    }
    return {processed:rows.length};
  })();
}
