import {isScanAgent} from './scanAgentConfig.js';
// Scan policy contains no credentials. Authentication is submitted only at start.
export const WEB_SCAN_LIMITS = Object.freeze({decisions:12,pages:20,checks:5,duration_ms:600000,model_ms:30000,tool_ms:120000});
export const isWebAgent = config => config?.scan_parameters?.web?.mode === 'react_sqli';
export function validateWebScanConfig(config, target) {
  const web=config?.scan_parameters?.web;
  if(web===undefined) return config;
  if(!web || Array.isArray(web) || Object.keys(web).some(k=>!['version','mode','auth_mode'].includes(k)) ||
      web.version!==1 || web.mode!=='react_sqli' || web.auth_mode!=='dvwa_ephemeral') throw new Error('Web 扫描配置无效');
  if(Object.keys(config.scan_parameters).some(k=>k!=='web')) throw new Error('AI Web 扫描不接受任意工具参数或认证值');
  if(config.execution_parameters && Object.keys(config.execution_parameters).length || config.test_type && config.test_type!=='web')
    throw new Error('AI Web 扫描不接受额外执行参数或其他测试类型');
  const url=new URL(target);
  if(!['http:','https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash)
    throw new Error('AI Web 扫描需要无凭据、无查询参数的 HTTP/HTTPS 应用入口');
  if(config.scan_mode || config.source_path || config.cscan_target || config.source_url || config.input_kind && config.input_kind!=='runtime')
    throw new Error('AI Web 扫描不能与程序或源码模式混用');
  // No automatic execution of the subsequent attack plan in this mode.
  config.require_approval=true;config.auto_execute=false;
  return config;
}
export function hasWebScanSchema(db) {
  return [['task_entries','metadata'],['scan_tasks','pipeline_id'],['scan_tool_runs','outcome'],['task_checks','entry_id']]
    .every(([table,column])=>db.prepare(`PRAGMA table_info(${table})`).all().some(c=>c.name===column));
}
// Serialize independent ephemeral sessions for an application origin, including unresolved tools.
export function webTargetBusy(db,target,exceptId=null) {
  const origin=new URL(target).origin;
  const same=value=>{try{return new URL(value).origin===origin;}catch{return false;}};
  if(db.prepare("SELECT pipeline_id,target,config FROM pipelines WHERE status IN ('running','awaiting_approval')").all()
    .some(p=>p.pipeline_id!==exceptId && (isWebAgent(JSON.parse(p.config||'{}'))||isScanAgent(JSON.parse(p.config||'{}'))) && same(p.target)))return true;
  return db.prepare(`SELECT s.target FROM scan_tool_runs r JOIN scan_tasks s USING(scan_task_id)
    WHERE r.state='running' OR json_extract(r.outcome,'$.stopped')=0`).all().some(s=>same(s.target));
}
const credentials=new Map();
export function putWebCredentials(id, owner, value) {
  if(credentials.has(id)) throw new Error('任务已有临时认证');
  if(!value || Object.keys(value).some(k=>!['username','password'].includes(k)) ||
    typeof value.username!=='string' || !value.username.trim() || value.username.length>128 ||
    typeof value.password!=='string' || !value.password || value.password.length>1024 || /[\r\n\0]/.test(value.username+value.password))
    throw new Error('请输入有效的临时登录信息');
  const timer=setTimeout(()=>clearWebCredentials(id),15*60*1000);timer.unref();
  credentials.set(id,{owner,username:value.username,password:value.password,timer});
}
export function takeWebCredentials(id, owner) {
  const value=credentials.get(id);
  if(!value || value.owner!==owner) throw new Error('临时认证不可用或后端已重启，请新建关联任务并重新输入');
  const result={username:value.username,password:value.password};clearWebCredentials(id);return result;
}
export function clearWebCredentials(id) {
  const value=credentials.get(id);if(value){clearTimeout(value.timer);value.password='';value.username='';credentials.delete(id);}
}
