import { pipelineTopology } from './topologyProjection.js';
import { extractTopologyFromResults } from './topologyBuilder.js';
import { isTargetInScope, normalizeTaskScope } from './taskScope.js';
import {appendDeclaredTopologyEntries} from './topologyWebEntries.js';

const fail = (status, message) => { throw Object.assign(new Error(message), {status}); };

// Resolve against stored observations, never a client's editable graph. A LAN
// neighbor can seed a NEW, explicitly authorized task without widening its parent.
export function resolveTopologyTaskSource(db, actor, input, target, config) {
  if (input === undefined) return null;
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || typeof input.node_id !== 'string' || !input.node_id || input.node_id.length > 256
      || Boolean(input.pipeline_id) === Boolean(input.scan_task_id)
      || [input.pipeline_id,input.scan_task_id].some(value=>value!==undefined && (typeof value!=='string' || !value || value.length>128))) fail(400,'拓扑来源无效');
  let graph, reference;
  if (input.pipeline_id) {
    const parent=db.prepare('SELECT * FROM pipelines WHERE pipeline_id=?').get(input.pipeline_id);
    if (!parent || actor.role !== 'admin' && parent.created_by !== actor.sub) fail(404,'来源拓扑不存在或不可访问');
    graph=pipelineTopology(db,parent);
    reference={pipeline_id:parent.pipeline_id};
  } else {
    const scan=db.prepare('SELECT * FROM scan_tasks WHERE scan_task_id=?').get(input.scan_task_id);
    if (!scan || actor.role !== 'admin' && scan.created_by !== actor.sub) fail(404,'来源探测不存在或不可访问');
    if (!['COMPLETED','PARTIAL'].includes(scan.status) || !['topology_scan','port_scan'].includes(scan.scan_type))
      fail(409,'来源探测尚无可用主机结果');
    const rows=db.prepare('SELECT * FROM scan_results WHERE scan_task_id=? ORDER BY id').all(scan.scan_task_id);
    graph=appendDeclaredTopologyEntries(extractTopologyFromResults(scan.target,rows),[scan],rows);
    reference={scan_task_id:scan.scan_task_id};
  }
  const node=graph.nodes.find(node=>node.id===input.node_id);
  if (!node || ['network_segment','virtual-switch'].includes(node.deviceType)) fail(409,'请选择来源拓扑中的具体主机');
  const observed=node.provenance?.sources?.length || node.services?.some(service=>service.provenance?.sources?.length);
  // Standalone projections do not always annotate provenance on the node. They
  // are still server-built exclusively from stored scan evidence.
  if (input.pipeline_id && (!observed || ['manual','inferred'].includes(node.provenance?.kind)))
    fail(409,'该节点缺少可核实的主机探测证据');
  const host=node.ip || node.hostName;
  // Entries are reconstructed above from stored scan evidence. Only those
  // entries may authorize a hostname alias of the selected IP node.
  const entry=node.entries?.some(entry=>{
    if (entry.kind!=='web_url' || entry.state==='out_of_scope') return false;
    try { return new URL(entry.value).href===new URL(target).href; } catch { return false; }
  });
  const includes=[host];
  if (entry) includes.push(target);
  const scope=normalizeTaskScope({task_scope:{includes,excludes:[]}},host);
  if (!isTargetInScope(scope,target) || target.includes('/') && !/^https?:\/\//i.test(target))
    fail(409,'扫描目标与所选拓扑主机不一致');
  if (/^https?:\/\//i.test(target)) {
    const selected=new URL(target);
    const service=node.services?.some(service=>service.protocol==='tcp' && service.state==='open'
      && /http/i.test(service.service || '') && Number(service.port)===Number(selected.port || (selected.protocol==='https:'?443:80))
      && selected.protocol===(/https|ssl\/http/i.test(service.service)?'https:':'http:') && selected.pathname==='/' && !selected.search);
    if (!entry && !service) fail(409,'所选 Web 服务已变化或没有开放服务证据，请刷新拓扑');
  }
  if (config.authorization_confirmed !== true) fail(400,'请确认所选目标的测试授权');
  if (config.task_mode !== 'assessment') fail(400,'节点操作须创建独立扫描任务');
  const selectedScope=normalizeTaskScope(config,target);
  if (selectedScope.includes.some(value=>!isTargetInScope(scope,value))) fail(400,'节点扫描范围不能超出所选主机');
  return {...reference,node_id:node.id,host,target,created_at:new Date().toISOString()};
}
