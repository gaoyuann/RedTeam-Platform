export const SCAN_CAPABILITIES=Object.freeze({
 port_scan:{kind:'observation',tools:['nmap'],description:'授权端口和服务观察，不是漏洞检测'},
 app_discovery:{kind:'observation',tools:['http-discovery'],description:'HTTP 页面及入口观察'},
 api_fuzz:{kind:'observation',tools:['arjun','ffuf'],description:'API 参数与路径发现，不是漏洞确认'},
 web_scan:{kind:'detection',tools:['nikto'],description:'Web 配置与已知问题检测，候选需复核'},
 web_parameter_scan:{kind:'detection',tools:['sqlmap'],description:'受控 GET 及用户声明的只读 POST/JSON 参数检测；动态令牌未支持'},
});
const parse=v=>{try{return JSON.parse(v||'{}');}catch{return {};}};
export function assessCapability(db,id,type){
 const capability=SCAN_CAPABILITIES[type];
 const records=db.prepare('SELECT result_type,result_data FROM scan_results WHERE scan_task_id=? ORDER BY id').all(id).map(r=>({...r,data:parse(r.result_data)}));
 const runs=db.prepare('SELECT tool_run_id,tool_id,state,outcome FROM scan_tool_runs WHERE scan_task_id=?').all(id).map(r=>({...r,data:parse(r.outcome)}));
 const relevant=runs.filter(r=>capability?.tools.includes(r.tool_id));
 const clean=r=>r.state==='completed'&&r.data.stopped===true&&r.data.exit_code===0&&!r.data.aborted&&!r.data.timed_out&&!r.data.incomplete&&(capability?.kind!=='detection'||r.data.parser_coverage_known===true);
 const unknownStop=runs.some(r=>r.state==='running'||r.data.stopped===false);
 const observed=records.some(r=>r.result_type==='http_probe'&&r.data.status_code>=200&&r.data.status_code<400||['open_port','host_discovery','api_parameter','api_endpoint'].includes(r.result_type)||r.result_type==='web_observation'&&r.data.status_code>=200&&r.data.status_code<400);
 let operationComplete=false,executed=null;
 if(capability){
  const started=relevant.some(r=>r.data.tool_started===true);
  executed=started?true:relevant.length&&relevant.every(r=>r.data.tool_started===false)?false:null;
  operationComplete=capability.tools.every(tool=>relevant.some(r=>r.tool_id===tool&&clean(r)))&&relevant.every(clean);
  if(type==='app_discovery')operationComplete=observed&&!unknownStop&&(!relevant.length||relevant.every(clean));
  if(type==='web_parameter_scan'){
   const summary=records.filter(r=>r.result_type==='web_scan_summary').at(-1)?.data;
   const reports=records.filter(r=>r.result_type==='scan_evidence');
   executed=typeof summary?.checks_started==='number'?summary.checks_started>0:executed;
   const reportIds=reports.map(r=>r.data.tool_run_id);
   operationComplete=executed===true&&summary?.complete===true&&relevant.length>0&&
    summary.checks_started===relevant.length&&reports.length===relevant.length&&new Set(reportIds).size===reports.length&&
    relevant.every(r=>clean(r)&&r.data.tool_started===true)&&reports.every(r=>
      typeof r.data.tool_run_id==='string'&&relevant.some(run=>run.tool_run_id===r.data.tool_run_id)&&
      r.data.complete===true&&['tool_positive','not_detected'].includes(r.data.status));
  }else if(type!=='app_discovery')operationComplete=operationComplete&&executed===true;
 }
 operationComplete=operationComplete&&!unknownStop;
 const detection=capability?.kind==='detection';
 const gaps=[];
 if(!capability)gaps.push('unsupported_capability');
 if(unknownStop)gaps.push('stop_unconfirmed');
 if(!operationComplete)gaps.push(executed===false?'not_executed':'incomplete_or_unknown');
 return {version:1,capability:type,kind:capability?.kind||'unsupported',observation_success:observed,
  detection_executed:detection?executed:null,detection_complete:detection?operationComplete:null,
  operation_complete:operationComplete,coverage_incomplete:!operationComplete,gaps,
  usable_for_analysis:operationComplete};
}
