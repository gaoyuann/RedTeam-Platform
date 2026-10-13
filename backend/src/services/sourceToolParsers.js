function decodeXml(value) {
  return value.replace(/&(?:quot|apos|lt|gt|amp|#\d+|#x[\da-f]+);/gi, entity => {
    const known = {'&quot;': '"', '&apos;': "'", '&lt;': '<', '&gt;': '>', '&amp;': '&'};
    if (known[entity]) return known[entity];
    const number = entity.startsWith('&#x') ? parseInt(entity.slice(3, -1), 16) : Number(entity.slice(2, -1));
    return Number.isInteger(number) && number > 0 && number <= 0x10ffff ? String.fromCodePoint(number) : entity;
  });
}
function attributes(text) {
  return Object.fromEntries([...text.matchAll(/\b([\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)]
    .map(match => [match[1], decodeXml(match[2] ?? match[3])]));
}
export function parseCppcheck(output) {
  const rows = [];
  const severity = {error: 'high', warning: 'medium', performance: 'low', portability: 'low', style: 'low', information: 'info'};
  for (const match of output.matchAll(/<error\b([^>]*?)(?:\/>|>([\s\S]*?)<\/error>)/g)) {
    const error = attributes(match[1]);
    if (!error.msg) continue;
    const locations = [...(match[2] || '').matchAll(/<location\b([^>]*?)\/?\s*>/g)].map(item => attributes(item[1]));
    const location = locations.find(item => Number(item.line) > 0) || {};
    rows.push({result_type: 'source_vuln', result_data: {
      file: location.file || error.file0 || '', line: Number(location.line) || 0,
      rule: error.id, cwe: error.cwe, message: error.msg, tool: 'cppcheck',
      inconclusive: error.inconclusive === 'true', locations,
    }, severity: severity[error.severity] || 'info', source_tool: 'cppcheck'});
  }
  return rows;
}

// RFC 4180 records, including escaped quotes and multiline context fields.
export function csvRecords(text) {
  const rows = []; let cells = [], cell = '', quoted = false;
  for (let i = 0; i < text.length; i++) {
    const char = text[i];
    if (quoted) {
      if (char === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (char === '"') quoted = false;
      else cell += char;
    } else if (char === '"' && !cell) quoted = true;
    else if (char === ',') { cells.push(cell); cell = ''; }
    else if (char === '\n') { cells.push(cell.replace(/\r$/, '')); rows.push(cells); cells = []; cell = ''; }
    else cell += char;
  }
  if (cell || cells.length) { cells.push(cell); rows.push(cells); }
  return rows;
}
export function parseFlawfinder(output) {
  let header; const rows = [];
  for (const cells of csvRecords(output)) {
    if (!header) {
      if (cells[0]?.trim().toLowerCase() === 'file') header = cells.map(cell => cell.trim().toLowerCase());
      continue;
    }
    const field = name => cells[header.indexOf(name)] || '';
    const line = Number(field('line')), level = Number(field('level') || field('defaultlevel'));
    if (!field('file') || !Number.isInteger(line) || line < 1 || !field('warning')) continue;
    rows.push({result_type: 'source_vuln', result_data: {file: field('file'), line,
      rule: field('name'), cwe: field('cwes'), message: field('warning'), suggestion: field('suggestion'),
      context: field('context'), tool: 'flawfinder'},
    severity: ({5: 'critical', 4: 'high', 3: 'medium', 2: 'low'})[level] || 'info', source_tool: 'flawfinder'});
  }
  return rows;
}
