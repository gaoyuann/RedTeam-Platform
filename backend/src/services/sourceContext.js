// Bounded lexical retrieval for review context, not a compiler or a proven call graph.
const keywords=new Set(['if','for','while','switch','return','sizeof','alignof','decltype','catch','static_cast','reinterpret_cast','const_cast']);
const symbols=text=>[...new Set([...text.matchAll(/\b([A-Za-z_]\w*)\s*\(/g)].map(m=>m[1]).filter(s=>!keywords.has(s)))];
export function createSourceContextIndex(documents) {
  const occurrences=new Map();
  for(const document of documents) {
    const lines=document.content.split('\n');
    lines.forEach((line,index)=>{
      for(const symbol of symbols(line)) {
        if(!occurrences.has(symbol)) occurrences.set(symbol,[]);
        const entries=occurrences.get(symbol);
        if(entries.length<64) entries.push({document,line:index+1});
      }
    });
  }
  return {documents,occurrences};
}
export function relatedSourceContext(primary,index) {
  const candidates=new Map();
  const add=(document,line,score)=>{
    if(document.path===primary.path && line>=primary.start_line && line<=primary.end_line) return;
    const key=document.path+':'+Math.floor((line-1)/40);
    const item=candidates.get(key);
    if(item) item.score+=score;
    else candidates.set(key,{document,line,score});
  };
  for(const symbol of symbols(primary.content).slice(0,48)) {
    const entries=index.occurrences.get(symbol) || [];
    // Prefer project-specific symbols to ubiquitous calls.
    for(const entry of entries) add(entry.document,entry.line,entries.length<8?3:1);
  }
  const includes=[...primary.content.matchAll(/^\s*#\s*include\s*"([^"]+)"/gm)].map(m=>m[1]);
  for(const document of index.documents)
    if(includes.some(name=>document.path===name || document.path.endsWith('/'+name))) add(document,1,4);
  const fragments=[];
  let chars=0;
  for(const item of [...candidates.values()].sort((a,b)=>b.score-a.score || a.document.path.localeCompare(b.document.path) || a.line-b.line)) {
    const lines=item.document.content.split('\n');
    const start=Math.max(1,item.line-20),end=Math.min(lines.length,item.line+40);
    if(fragments.some(f=>f.path===item.document.path && start<=f.end_line && end>=f.start_line)) continue;
    const content=lines.slice(start-1,end).join('\n');
    if(chars+content.length>16000) continue;
    fragments.push({...item.document,start_line:start,end_line:end,content});
    chars+=content.length;
    if(fragments.length===4) break;
  }
  return fragments;
}
