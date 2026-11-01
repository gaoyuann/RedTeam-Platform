// Code stores are scoped by verification_id; library items must already match
// the finding signature. This read projection never creates execution bindings.
export function currentFindingPayload(artifacts={},history=[],libraryItems=[],findingFingerprint='') {
  const items=[];
  const collection=artifacts.collections?.find(c=>c.state==='ready'&&Array.isArray(c.scripts)
    &&c.scripts.some(s=>typeof s?.content==='string'&&s.content.trim()));
  for(const script of collection?.scripts || [])if(typeof script?.content==='string'&&script.content.trim())
    items.push({id:'scan:'+collection.id+':'+script.id,name:script.name || '扫描载荷',
      language:script.language || '',code:script.content,origin:'scan',
      purpose:script.purpose || '',usage:script.usage || '',safety_notes:script.safety_notes || '',runtime_verified:false});
  const generated=history.find(r=>r.state==='ready'&&Array.isArray(r.result?.files)
    &&r.result.files.some(f=>typeof f?.source==='string'&&f.source.trim()));
  for(const file of generated?.result.files || [])if(typeof file?.source==='string'&&file.source.trim())
    items.push({id:'generated:'+generated.id+':'+file.filename,name:file.filename,language:file.language,
      code:file.source,origin:'generated',artifact_id:generated.id,
      stale:!!findingFingerprint && generated.result.source_fingerprint!==findingFingerprint,
      execution_supported:!!generated.result.execution && (!findingFingerprint || generated.result.source_fingerprint===findingFingerprint),
      execution_mode:'local_simulation',
      run_conditions:generated.result.run_conditions || [],dependencies:generated.result.dependencies || [],
      expected_results:generated.result.expected_results || [],failure_reasons:generated.result.failure_reasons || [],
      model_inferences:generated.result.model_inferences || [],reused:!!generated.result.reuse,runtime_verified:false});
  items.push(...libraryItems);
  const latest=history[0];
  return {state:items.length?'available':latest?.state==='generating'?'generating':'missing',items,
    reason:items.length?'':latest?.error_message || (latest?.state==='needs_information'?latest.result?.missing_information?.join('；'):'') || '',
    runtime_verified:false};
}
