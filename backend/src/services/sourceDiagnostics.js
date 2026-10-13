export function parseSourceDiagnostics(output,files=[]) {
  let text=String(output || '').slice(0,65536);
  // Diagnostic HTTP endpoints commonly wrap process output in JSON. Decode
  // only the bounded stdout/stderr strings, never conclusions or source paths
  // supplied by the endpoint as structured "verified" evidence.
  try {
    const envelope=JSON.parse(text);
    if(envelope && !Array.isArray(envelope) && typeof envelope==='object') {
      const streams=[envelope.stdout,envelope.stderr].filter(value=>typeof value==='string');
      if(streams.length) text=streams.join('\n').slice(0,65536);
    }
  } catch {}
  text=text.replace(/\x1b\[[0-9;]*m/g,'');
  const diagnostics=[];
  let current=null;
  const add=(detector,type,message)=>{
    current=diagnostics.find(item=>item.detector===detector && item.type===type);
    if(current) return;
    if(diagnostics.length>=12) {current=null;return;}
    current={detector,type,message:message.slice(0,600),locations:[],runtime_verified:false,review_required:true};
    diagnostics.push(current);
  };
  for(const lineText of text.split('\n')) {
    const asan=lineText.match(/(?:ERROR|SUMMARY): AddressSanitizer: ([\w-]+)/);
    if(asan) add('asan',asan[1],lineText);
    const ubsan=lineText.match(/([^\s:]+\.(?:c|cc|cpp|cxx|h|hpp)):(\d+):\d+: runtime error: (.+)/);
    if(ubsan) {
      const type=/null pointer/.test(ubsan[3])?'null-pointer':/overflow/.test(ubsan[3])?'integer-overflow':/misaligned/.test(ubsan[3])?'misaligned-access':'undefined-behavior';
      add('ubsan',type,ubsan[3]);
    }
    if(!current) continue;
    for(const match of lineText.matchAll(/([^\s()]+\.(?:c|cc|cpp|cxx|h|hpp)):(\d+)(?::\d+)?/g)) {
      const path=match[1].replaceAll('\\','/'),line=Number(match[2]);
      const matches=[...new Map(files.filter(file=>path===file.path || path.endsWith('/'+file.path))
        .map(file=>[file.path+'|'+(file.sha256 || file.source_sha256 || ''),file])).values()];
      if(matches.length!==1 || line<1 || matches[0].end_line && line>matches[0].end_line) continue;
      const location={file:matches[0].path,line,source_sha256:matches[0].sha256 || matches[0].source_sha256 || null};
      if(current.locations.length<12 && !current.locations.some(loc=>loc.file===location.file && loc.line===line)) current.locations.push(location);
    }
  }
  return diagnostics;
}
