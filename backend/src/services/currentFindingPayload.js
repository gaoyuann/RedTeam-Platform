// Both stores are already scoped by verification_id. This is a read projection,
// not an execution binding or a claim that any script has been validated.
export function currentFindingPayload(artifacts={},history=[]) {
  const items=[];
  const collection=artifacts.collections?.find(c=>c.state==='ready'&&c.scripts?.some(s=>s.content));
  for(const script of collection?.scripts || [])if(typeof script.content==='string'&&script.content.trim())
    items.push({id:'scan:'+collection.id+':'+script.id,name:script.name || '扫描载荷',
      language:script.language || '',code:script.content,origin:'scan',runtime_verified:false});
  const generated=history.find(r=>r.state==='ready'&&r.result?.files?.length);
  for(const file of generated?.result.files || [])if(typeof file.source==='string'&&file.source.trim())
    items.push({id:'generated:'+generated.id+':'+file.filename,name:file.filename,language:file.language,
      code:file.source,origin:'generated',artifact_id:generated.id,execution_supported:!!generated.result.execution,
      execution_mode:'local_simulation',runtime_verified:false});
  const latest=history[0];
  return {state:items.length?'available':latest?.state==='generating'?'generating':'missing',items,
    reason:items.length?'':latest?.error_message || (latest?.state==='needs_information'?latest.result?.missing_information?.join('；'):'') || '',
    runtime_verified:false};
}
