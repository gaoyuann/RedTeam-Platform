// Parse explicit report fields only. Prose and source code are never evaluated
// or sent to the platform's former source-analysis model.
const labels = new Map([
  ['file','file'],['文件','file'],['文件路径','file'],['source file','file'],
  ['line','start_line'],['lines','start_line'],['行号','start_line'],
  ['severity','severity'],['严重度','severity'],['严重级别','severity'],
  ['cwe','cwe'],['reason','reason'],['evidence','reason'],['依据','reason'],['根因','reason'],['root cause','reason'],
  ['preconditions','preconditions'],['触发条件','preconditions'],['触发前提','preconditions'],
  ['suggestion','suggestion'],['remediation','suggestion'],['修复建议','suggestion'],
  ['title','title'],['漏洞名称','title'],['标题','title'],
]);

function plain(value) {
  let text = value.trim();
  // Unwrap paired Markdown, preserving literal filename underscores.
  for(let pass=0;pass<4;pass++) {
    const wrapper=['**','__','`','*','_'].find(mark=>text.startsWith(mark) && text.endsWith(mark) && text.length>mark.length*2);
    if(!wrapper) break;
    text=text.slice(wrapper.length,-wrapper.length).trim();
  }
  return text;
}
function assign(finding, key, value) {
  value = plain(value);
  if(key === 'start_line') {
    const match = value.match(/^(\d+)(?:\s*[-–—]\s*(\d+))?$/);
    if(match) {finding.start_line=Number(match[1]);finding.end_line=Number(match[2] || match[1]);}
  } else if(key === 'severity') {
    const severity = {严重:'critical',高:'high',高危:'high',中:'medium',中危:'medium',低:'low',低危:'low',信息:'info'};
    finding.severity=severity[value] || value.toLowerCase();
  } else finding[key] = value;
}

// Keep fenced source/payload text in its original section. A Markdown-looking
// comment inside a script is not a new audit finding.
export function splitCscanMarkdownSections(markdown) {
  const sections=[];
  let current='',fence=null;
  for(const chunk of markdown.split(/(?<=\n)/)) {
    const line=chunk.replace(/\r?\n$/,'');
    const marker=line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if(fence) {
      if(marker && marker[1][0]===fence[0] && marker[1].length>=fence.length && !marker[2].trim())fence=null;
    } else if(marker)fence=marker[1];
    else if(/^#{2,6}\s+/.test(line) && current) {sections.push(current);current='';}
    current+=chunk;
  }
  if(current)sections.push(current);
  return sections;
}

export function parseCscanMarkdown(markdown, snapshotId) {
  const findings = [];
  let current = null, fence = null, headers = null, lastField = null;
  const push = () => {
    if(current?.file && current.start_line && current.title && current.reason) findings.push(current);
    current=null;lastField=null;
  };
  for(const line of markdown.split(/\r?\n/)) {
    const marker=line.match(/^ {0,3}(`{3,}|~{3,})(.*)$/);
    if(fence) {
      if(marker && marker[1][0]===fence[0] && marker[1].length>=fence.length && !marker[2].trim()) fence=null;
      continue;
    }
    if(marker) {fence=marker[1];continue;}
    if(/^(?: {4}|\t)/.test(line)) continue;
    const heading = line.match(/^#{2,6}\s+(.+)$/);
    if(heading) {push();headers=null;current={title:plain(heading[1]).replace(/^\d+[.)、]\s*/, '')};continue;}
    if(/^\s*\|/.test(line)) {
      const cells = line.trim().replace(/^\||\|$/g,'').split('|').map(plain);
      if(cells.every(cell=>/^:?-+:?$/.test(cell))) continue;
      const keys = cells.map(cell=>labels.get(cell.toLowerCase()));
      if(keys.includes('file') && keys.includes('start_line') && keys.includes('title') && keys.includes('reason')) {
        push();headers=keys;continue;
      }
      if(headers && cells.length===headers.length) {
        const finding={};headers.forEach((key,index)=>{if(key) assign(finding,key,cells[index]);});
        if(finding.file && finding.start_line && finding.title && finding.reason) findings.push(finding);
      }
      continue;
    }
    headers=null;
    // Remove the label's paired bold markers, including **File:** form.
    const field = line.replace(/\*\*([^*]+?)\*\*/g,'$1').match(/^\s*(?:[-*]\s+)?([^:：]+?)\s*[:：]\s*(.*)$/);
    const key = field && labels.get(field[1].trim().toLowerCase());
    // Payload metadata belongs to the preceding finding, not its evidence or
    // remediation text. Code fences below it are already ignored above.
    if(field && /^payload[- ]/i.test(field[1].trim())) {lastField=null;continue;}
    if(key) {
      current ||= {};
      assign(current,key,field[2]);lastField=key;
    } else if(current && ['reason','preconditions','suggestion'].includes(lastField) && line.trim()) {
      current[lastField]+='\n'+line.trim();
    }
    if(findings.length > 1000) throw new Error('CScan Markdown 发现数量超过限制');
  }
  push();
  // Markdown does not attest file-level coverage or the requested version.
  // It is tied to this snapshot only by the immutable Flow/submission mapping.
  return {snapshot_id:snapshotId,findings,markdown,report_format:'markdown',coverage:null,
    report_warnings:['Markdown 报告未提供可核对的完整文件审阅清单；仅导入具有明确文件、行号、名称和依据的记录']};
}
