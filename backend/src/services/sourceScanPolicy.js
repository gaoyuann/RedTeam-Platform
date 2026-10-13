// Explicit analysis settings; project configuration never supplies shell arguments.
export function sourceAnalysisOptions(value = {}) {
  const standard = value.standard || null;
  const platform = value.platform || 'unix64';
  if (standard && !['c89', 'c99', 'c11', 'c++03', 'c++11', 'c++14', 'c++17', 'c++20'].includes(standard)) {
    throw new Error('C/C++ 标准配置无效');
  }
  if (!['unix32', 'unix64', 'win32A', 'win32W', 'win64'].includes(platform)) throw new Error('源码分析平台配置无效');
  const defines = value.defines || [];
  if (!Array.isArray(defines) || defines.length > 32 || defines.some(item => typeof item !== 'string'
    || !/^[A-Za-z_]\w*(?:=[A-Za-z0-9_.+-]{1,64})?$/.test(item))) throw new Error('源码宏定义配置无效');
  const compileDatabase=value.compile_database || null;
  if(compileDatabase && (typeof compileDatabase!=='string' || compileDatabase.length>256
    || !/^(?:[A-Za-z0-9_.-]+\/)*compile_commands\.json$/.test(compileDatabase)
    || compileDatabase.split('/').some(part=>part==='.' || part==='..'))) throw new Error('编译数据库须为项目内的 compile_commands.json 相对路径');
  return {standard, platform, defines: [...new Set(defines)],...(compileDatabase ? {compile_database:compileDatabase} : {})};
}

export function sourceToolArgs(tool, options = {}, compilation = {}) {
  if (tool === 'flawfinder') return ['--csv', '--minlevel=1', '/src/project'];
  const config = sourceAnalysisOptions(options);
  return ['-q', '--enable=warning,portability,performance', '--xml', '--xml-version=2',
    '--max-configs=12', `--platform=${config.platform}`,
    ...(config.standard ? [`--std=${config.standard}`] : []),
    ...config.defines.map(item => `-D${item}`),
    ...(compilation.available ? ['--project=/src/project/.rt-compile-commands.json'] : ['/src/project'])];
}

// Center the first AI chunks on static alerts and risky operations. Keep the
// remaining chunks for coverage, and never replace the tool evidence with a score.
export function sourceReviewChunks(documents, candidates = []) {
  const chunks = [], seen = new Set();
  chunks.omitted = 0;
  const risk = /\b(?:strcpy|strcat|sprintf|gets|scanf|memcpy|memmove|recv|read|malloc|free|new|delete|system|popen|exec\w*)\b/;
  for (const document of documents) {
    const lines = document.content.split('\n');
    const starts = new Set();
    for (const finding of candidates.filter(item => item.file === document.path)) {
      starts.add(Math.max(0, finding.start_line - 41));
    }
    lines.forEach((line, index) => { if (starts.size < 256 && risk.test(line)) starts.add(Math.max(0, index - 40)); });
    const focusedRanges = [...starts].map(start => ({start, end:Math.min(start + 120,lines.length)}));
    for (let start = 0; start < lines.length; start += 100) starts.add(start);
    for (const start of starts) {
      const end = Math.min(start + 120, lines.length);
      const key = `${document.path}:${start}:${end}`;
      if (seen.has(key) || focusedRanges.some(item => item.start !== start && item.start <= start && item.end >= end)) continue;
      seen.add(key);
      const content = lines.slice(start, end).join('\n');
      if (content.length > 18000) { chunks.omitted++; continue; }
      const alerts = candidates.filter(item => item.file === document.path && item.start_line > start && item.start_line <= end);
      const riskCount = lines.slice(start, end).filter(line => risk.test(line)).length;
      const priority = alerts.length * 100 + Math.min(riskCount, 20);
      chunks.push({...document, content, start_line: start + 1, end_line: end, priority});
    }
  }
  chunks.sort((a, b) => b.priority - a.priority || a.path.localeCompare(b.path) || a.start_line - b.start_line);
  return chunks;
}
