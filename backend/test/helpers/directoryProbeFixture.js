export function directoryProbeFixture(args) {
  const spec=JSON.parse(args[0]);
  const missing=new URL(spec.url).pathname.includes('__rt_missing_');
  return {success:true,exitCode:0,stdout:JSON.stringify({complete:true,truncated:false,
    status_code:missing?404:200,response:missing?'Not found':'<title>Application directory</title>',
    response_headers:{'content-type':'text/html'}}),stderr:''};
}
