import {posix} from 'node:path';

// Decode arguments only. No compiler, shell, response file or project script is run.
function commandWords(command) {
  if(typeof command!=='string' || command.length>32768) throw new Error('编译参数无效');
  const words=[];let word='',quote='',active=false;
  for(let i=0;i<command.length;i++) {
    const char=command[i];
    if(char==='\\' && quote!=="'") {if(++i===command.length) throw new Error('编译参数转义不完整');word+=command[i];active=true;}
    else if(quote) {if(char===quote) quote='';else word+=char;}
    else if(char==='"' || char==="'") {quote=char;active=true;}
    else if(/\s/.test(char)) {if(active) words.push(word);word='';active=false;}
    else {word+=char;active=true;}
  }
  if(quote) throw new Error('编译参数引号不完整');
  if(active) words.push(word);
  return words;
}

export function prepareSourceCompilation(collected, connection) {
  const requested=!!connection.analysis?.compile_database;
  const summary={requested,available:false,configured_units:0,fallback_units:0,skipped_units:0,ignored_options:0,external_paths:0,errors:[]};
  if(!requested) return {summary,units:[]};
  if(!collected.compilation?.content) {
    summary.errors.push(collected.compilation?.error || '未读取到指定的编译数据库');
    return {summary,units:[]};
  }
  const documents=collected.files,paths=new Set(documents.map(file=>file.path));
  const root=posix.normalize(connection.source_root || '/');
  function relativePath(value,directory='.') {
    if(typeof value!=='string' || value.length>1024 || /[\x00-\x1f\\]/.test(value)
      || typeof directory!=='string' || directory.length>1024 || /[\x00-\x1f\\]/.test(directory)) return null;
    const base=posix.isAbsolute(directory) ? directory : posix.resolve(root,directory);
    const absolute=posix.resolve(base,value),relative=posix.relative(root,absolute);
    return relative==='..' || relative.startsWith('../') ? null : relative || '.';
  }
  let entries;
  try {entries=JSON.parse(collected.compilation.content);if(!Array.isArray(entries) || entries.length>500) throw new Error('编译数据库超过500条或格式无效');}
  catch(error) {summary.errors.push(error.message);return {summary,units:[]};}
  const units=[],configured=new Set();
  for(const entry of entries) {
    const file=relativePath(entry?.file,entry?.directory || '.');
    if(!file || !paths.has(file) || !/\.(?:c|cc|cpp|cxx)$/i.test(file)) {summary.skipped_units++;continue;}
    let args;
    try {
      args=entry.arguments===undefined ? commandWords(entry.command) : entry.arguments;
      if(!Array.isArray(args) || args.length<2 || args.length>512 || args.some(arg=>typeof arg!=='string' || arg.length>4096)
        || !args[0].trim()) throw new Error('编译参数无效');
    } catch {summary.skipped_units++;continue;}
    const options=[];
    for(let i=1;i<args.length;i++) {
      const arg=args[i];let kind,value;
      if(['-I','-isystem','-iquote','-D','-U'].includes(arg)) {kind=arg;value=args[++i];}
      else if(/^-(?:I|D|U).+/.test(arg)) {kind=arg.slice(0,2);value=arg.slice(2);}
      else if(arg.startsWith('-std=')) {kind='std';value=arg.slice(5);}
      else {if(['-o','-MF','-MT','-MQ'].includes(arg)) {i++;continue;}
        if(arg.startsWith('-') && arg!=='-c') summary.ignored_options++;continue;}
      if(['-I','-isystem','-iquote'].includes(kind)) {
        const path=relativePath(value,entry.directory || '.');
        if(path!==null && documents.some(doc=>path==='.' || doc.path.startsWith(path+'/'))) options.push('-I/src/project'+(path==='.'?'':'/'+path));
        else summary.external_paths++;
      } else if(kind==='std' && /^(?:c(?:89|99|11)|c\+\+(?:03|11|14|17|20))$/.test(value || '')) options.push('-std='+value);
      else if((kind==='-D' && /^[A-Za-z_]\w*(?:=[A-Za-z0-9_.+-]{1,64})?$/.test(value || ''))
        || (kind==='-U' && /^[A-Za-z_]\w*$/.test(value || ''))) options.push(kind+value);
      else summary.ignored_options++;
    }
    if(options.length>96) {summary.skipped_units++;continue;}
    units.push({directory:'/src/project',file:'/src/project/'+file,arguments:['cc',...new Set(options),'-c','/src/project/'+file]});
    configured.add(file);summary.configured_units++;
  }
  // Files absent from the build database still receive the ordinary scan.
  for(const doc of documents.filter(doc=>/\.(?:c|cc|cpp|cxx)$/i.test(doc.path) && !configured.has(doc.path))) {
    units.push({directory:'/src/project',file:'/src/project/'+doc.path,arguments:['cc','-c','/src/project/'+doc.path]});summary.fallback_units++;
  }
  summary.available=summary.configured_units>0;
  if(!summary.available) summary.errors.push('编译数据库没有匹配快照的有效编译单元，使用普通静态扫描');
  return {summary,units};
}

export function hostCompilationUnits(units,sourceDir) {
  const remap=value=>value.replace(/\/src\/project(?=\/|$)/g,()=>sourceDir);
  return units.map(unit=>({directory:sourceDir,file:remap(unit.file),arguments:unit.arguments.map(remap)}));
}
