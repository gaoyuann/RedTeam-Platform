import http from 'node:http';
import {mkdtemp,mkdir,writeFile,rm} from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';

// Protocol fixture, not a scanner: test-owned findings are served over real HTTP
// and files so callers exercise the production submit/poll/import implementation.
export async function cscanFixture(t, findings = []) {
  const root = await mkdtemp(join(tmpdir(),'rt-cscan-protocol-'));
  const sources = join(root,'sources'),work = join(root,'work');
  await mkdir(sources);await mkdir(work);
  const counts = {created:0,stopped:0,finished:0};
  const server = http.createServer(async(req,res)=>{
    try {
      if(req.headers.authorization !== 'Bearer fixture-only-cscan') {res.writeHead(401);res.end();return;}
      let raw = '';for await(const chunk of req) raw += chunk;
      const body = JSON.parse(raw);res.setHeader('content-type','application/json');
      if(body.query.includes('createFlow')) {
        counts.created++;
        const id = String(counts.created),input = body.variables.input;
        const snapshotId = JSON.parse(input.match(/"snapshot_id":("(?:[^"\\]|\\.)*")/)[1]);
        const key = input.match(/\/src\/(rt-[\w-]+)/)[1];
        const inventory = JSON.parse(input.split('\n').at(-1));
        const directory = join(work,'flow-'+id);await mkdir(directory);
        const accepted = typeof findings === 'function' ? await findings({inventory,key,snapshotId,sources}) : findings;
        await writeFile(join(directory,'findings.json'),JSON.stringify({snapshot_id:snapshotId,findings:accepted,
          coverage:{reviewed_files:inventory.map(file=>file.path),omitted_files:[],complete:true}}));
        await writeFile(join(directory,'report.md'),'Controlled CScan protocol fixture; no real model or scanner was invoked.');
        res.end(JSON.stringify({data:{createFlow:{id,status:'running'}}}));
      } else if(body.query.includes('stopFlow')) {counts.stopped++;res.end(JSON.stringify({data:{stopFlow:'success'}}));}
      else if(body.query.includes('finishFlow')) {counts.finished++;res.end(JSON.stringify({data:{finishFlow:'success'}}));}
      else if(body.query.includes('CScanHealth')) res.end(JSON.stringify({data:{flows:[]}}));
      // Mirrors upstream task.SetStatus: finished tasks leave Flow=waiting.
      else res.end(JSON.stringify({data:{flow:{id:body.variables.id,status:'waiting'},
        tasks:[{id:'1',flowId:body.variables.id,status:'finished',subtasks:[{id:'1',status:'finished'}]}]}}));
    } catch {res.writeHead(500);res.end('{}');}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  const env = {CSCAN_API_URL:'http://127.0.0.1:'+server.address().port,CSCAN_API_TOKEN:'fixture-only-cscan',
    CSCAN_SOURCES_DIR:sources,CSCAN_WORK_DIR:work,CSCAN_POLL_MS:'10',CSCAN_TIMEOUT_MS:'2000'};
  const previous = Object.fromEntries(Object.keys(env).map(key=>[key,process.env[key]]));
  Object.assign(process.env,env);
  t.after(async()=>{
    for(const [key,value] of Object.entries(previous)) {if(value===undefined) delete process.env[key];else process.env[key]=value;}
    server.closeAllConnections();await new Promise(resolve=>server.close(resolve));
    await rm(root,{recursive:true,force:true});
  });
  return {env,counts,sources,work};
}
