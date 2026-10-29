// Preserve the user's application URL separately from the host address used by
// Nmap. A declared path is not proof that the application responded. Hostname
// aliases must come from a host observation in the same scan, never from DNS
// lookups performed while rendering a graph or from another node's services.
export function appendDeclaredTopologyEntries(graph, scans, results) {
  const dataOf = row => { try { return typeof row.result_data === 'string' ? JSON.parse(row.result_data) : row.result_data; } catch { return null; } };
  const host = value => String(value || '').replace(/^\[|\]$/g,'').toLowerCase();
  for (const scan of scans) {
    if (!['port_scan','topology_scan'].includes(scan.scan_type)) continue;
    let url;
    try { url=new URL(scan.target); } catch { continue; }
    if (!['http:','https:'].includes(url.protocol) || url.username || url.password || url.hash) continue;
    const name=host(url.hostname);
    const observations=results.filter(row=>row.scan_task_id===scan.scan_task_id && row.result_type==='host_discovery')
      .map(row=>({row,data:dataOf(row)})).filter(({data})=>data?.host && !data.traceTarget
        && host(data.hostName)===name);
    for (const node of graph.nodes) {
      if (['network_segment','virtual-switch'].includes(node.deviceType)) continue;
      const evidence=observations.find(({data})=>host(data.host)===host(node.ip || node.hostName));
      if (host(node.ip || node.hostName)!==name && !evidence) continue;
      const entries=node.entries || [];
      // Put the declared application first so the client does not silently
      // replace /app/ with the root service URL when choosing a default.
      node.entries=[{kind:'web_url',value:url.href,state:'declared',
        sourceRecordId:evidence?.row.id ?? null,sourceScanTaskId:scan.scan_task_id},
        ...entries.filter(entry=>entry.value!==url.href)];
    }
  }
  return graph;
}
