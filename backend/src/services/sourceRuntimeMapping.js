// Route literals identify review candidates, never a proven call/data-flow edge.
export function sourceRuntimeMapping(finding,observation,target) {
  const mapping={status:'unresolved',semantic_link_verified:false,entries:[],missing_conditions:[]};
  if(!target) {mapping.missing_conditions.push('缺少实际运行地址');return mapping;}
  const runtime=new URL(target);
  if(runtime.protocol==='tcp:') {
    mapping.entries.push({url:target,provenance:'runtime_entry_observation',observed:observation.connected===true});
    mapping.missing_conditions.push('需要确认菜单输入、消息格式与源码函数的对应关系');return mapping;
  }
  const fragments=[{file:finding.file,start_line:finding.start_line,code:finding.code},...(finding.trace || [])];
  for(const fragment of fragments) {
    if(!/route|request|uri|path|strcmp|strncmp|http|handler/i.test(fragment.code)) continue;
    for(const match of fragment.code.matchAll(/["'](\/[^\s"'\\]{0,180})["']/g)) {
      let url;
      try {url=new URL(match[1],runtime);if(url.origin!==runtime.origin || url.search || url.hash) continue;} catch {continue;}
      if(mapping.entries.some(entry=>entry.url===url.href)) continue;
      mapping.entries.push({url:url.href,provenance:'source_route_literal',observed:observation.connected===true && observation.url===url.href,
        citation:{file:fragment.file,line:fragment.start_line+fragment.code.slice(0,match.index).split('\n').length-1}});
      if(mapping.entries.length>=8) break;
    }
    if(mapping.entries.length>=8) break;
  }
  if(mapping.entries.length) mapping.status='candidate';
  else mapping.entries.push({url:target,provenance:'runtime_entry_observation',observed:observation.connected===true});
  mapping.missing_conditions.push(mapping.status==='candidate' ? '路由字符串与危险函数之间的实际调用和输入传播仍需确认' : '未发现有代码依据的运行路由，先确认入口到危险函数的关系');
  return mapping;
}
