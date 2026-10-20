import { hash, fail, findingIdentity, canonicalTarget, identityInScope } from './findingInstances.js';
import { isTargetInScope, taskScope } from './taskScope.js';
const keys=(v,allowed)=>{
  if(!v || typeof v!=='object' || Array.isArray(v) || Object.keys(v).some(k=>!allowed.includes(k)))fail(400,'基准含未声明字段或格式无效');
};
const text=v=>typeof v==='string' && v.trim()===v && v.length>0 && v.length<=200 && !/[\r\n\0]/.test(v);
export function validateBaseline(pipeline,input) {
  keys(input,['schema_version','environment_id','environment_version','assets_complete','vulnerabilities_complete','assets','vulnerabilities']);
  if(input.schema_version!==1 || !text(input.environment_id) || !text(input.environment_version)
    || typeof input.assets_complete!=='boolean' || typeof input.vulnerabilities_complete!=='boolean'
    || !Array.isArray(input.assets) || !Array.isArray(input.vulnerabilities)
    || input.assets.length>10000 || input.vulnerabilities.length>10000)fail(400,'基准版本、完整性或清单无效');
  const scope=taskScope(pipeline), ids=new Set(), locations=new Set();
  if(scope.environment_ref && scope.environment_ref!==input.environment_id)fail(409,'基准环境与任务环境引用不匹配');
  const assets=input.assets.map(a=>{
    keys(a,['id','target']);
    const target=canonicalTarget(a.target);
    if(!text(a.id) || !text(a.target) || !target || ids.has(a.id) || locations.has(target) || !isTargetInScope(scope,target))fail(400,'基准资产重复或不在任务范围内');
    try{const u=new URL(a.target);if(u.username || u.password || u.search || u.hash)fail(400,'基准入口不能包含认证、查询或片段');}catch(e){if(e.status)throw e;}
    ids.add(a.id);locations.add(target);return {id:a.id,target};
  }).sort((a,b)=>a.id.localeCompare(b.id));
  const vids=new Set(), identities=new Set();
  const vulnerabilities=input.vulnerabilities.map(v=>{
    keys(v,['id','asset_id','source_tool','location']);
    const fields=v.location;
    keys(fields,['rule_id','url','method','parameter','parameter_location','host','port','protocol','source_version','file','line']);
    if(Object.values(fields).some(value=>!['string','number'].includes(typeof value)))fail(400,'基准位置字段必须是字符串或数字');
    const kind=Object.hasOwn(fields,'file')?'source':Object.hasOwn(fields,'url')?'web':'service';
    const allowed={source:['rule_id','source_version','file','line'],web:['rule_id','url','method','parameter','parameter_location'],service:['rule_id','host','port','protocol']}[kind];
    keys(fields,allowed);
    for(const [key,value] of Object.entries(fields)) {
      if(['port','line'].includes(key)) {
        if(!Number.isSafeInteger(value) || value<1)fail(400,'基准行号或端口必须为正整数');
      } else if(typeof value!=='string' || !value.trim() || value.length>2000 || /[\r\n\0]/.test(value))fail(400,'基准位置文本无效');
    }
    const asset=assets.find(a=>a.id===v.asset_id);
    const identity=findingIdentity({source_tool:v.source_tool,result_data:{...fields,...(kind==='source'?{target:asset?.target}:{})}});
    if(!text(v.id) || !text(v.source_tool) || vids.has(v.id) || !asset || !identity)fail(400,'基准漏洞标识、资产引用或匹配位置无效');
    if(!identityInScope(identity,scope) || !identityInScope(identity,{includes:[asset.target],excludes:[]}))fail(400,'漏洞位置不属于声明资产');
    const key=hash(identity);if(identities.has(key))fail(400,'基准漏洞匹配身份重复');
    vids.add(v.id);identities.add(key);
    return {id:v.id,asset_id:v.asset_id,source_tool:v.source_tool,location:Object.fromEntries(Object.keys(v.location).sort().map(k=>[k,v.location[k]])),identity};
  }).sort((a,b)=>a.id.localeCompare(b.id));
  return {schema_version:1,environment_id:input.environment_id,environment_version:input.environment_version,
    assets_complete:input.assets_complete,vulnerabilities_complete:input.vulnerabilities_complete,assets,vulnerabilities};
}
export function baselineVersions(db,pipeline) {
  return db.prepare(`SELECT b.id,b.content_hash,b.imported_by,b.created_at,b.content,s.baseline_id=b.id AS active
    FROM task_baselines b LEFT JOIN task_baseline_selection s ON s.pipeline_id=b.pipeline_id
    WHERE b.pipeline_id=? ORDER BY b.id DESC`).all(pipeline.pipeline_id).map(r=>({...r,content:JSON.parse(r.content)}));
}
export function importBaseline(db,pipeline,actor,input,{preview=false}={}) {
  const content=validateBaseline(pipeline,input), encoded=JSON.stringify(content), digest=hash(content);
  return db.transaction(()=>{
    const versions=baselineVersions(db,pipeline);
    if(versions.some(v=>v.content.environment_id!==content.environment_id || v.content.environment_version!==content.environment_version))
      fail(409,'任务已绑定不同环境版本，请为新环境创建任务');
    if(preview)return {valid:true,content_hash:digest,assets:content.assets.length,vulnerabilities:content.vulnerabilities.length};
    db.prepare('INSERT OR IGNORE INTO task_baselines(pipeline_id,content,content_hash,imported_by,created_at) VALUES (?,?,?,?,?)')
      .run(pipeline.pipeline_id,encoded,digest,actor.sub,new Date().toISOString());
    const row=db.prepare('SELECT id FROM task_baselines WHERE pipeline_id=? AND content_hash=?').get(pipeline.pipeline_id,digest);
    db.prepare('INSERT INTO task_baseline_selection VALUES (?,?) ON CONFLICT(pipeline_id) DO UPDATE SET baseline_id=excluded.baseline_id').run(pipeline.pipeline_id,row.id);
    return {id:row.id,content_hash:digest,reused:versions.some(v=>v.id===row.id)};
  })();
}
