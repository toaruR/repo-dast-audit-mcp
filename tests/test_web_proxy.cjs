'use strict';
const test=require('node:test'), assert=require('node:assert/strict');
const http=require('node:http'), fs=require('node:fs'), path=require('node:path'), Module=require('node:module');
const filename=path.resolve(__dirname,'../src/repo_dast_audit_mcp/web_audit/browser_worker.cjs');
const implementation=new Module(filename,module);
implementation.filename=filename;
implementation.paths=module.paths;
implementation.require=name=>name==='./playwright-core'?{}:require(name);
implementation._compile(fs.readFileSync(filename,'utf8'),filename);
const proxy=implementation.exports;
test('proxy enforces scope, concurrency, byte budget and completes empty GET bodies',async()=>{
  let active=0,maximum=0,targetRequests=0;
  const target=http.createServer((request,response)=>{
    targetRequests++; active++;maximum=Math.max(maximum,active);
    response.once('close',()=>active--);
    request.resume();
    setTimeout(()=>{
      if(request.url==='/large') response.end(Buffer.alloc(1048577,65));
      else response.end('synthetic');
    },20);
  });
  await new Promise(resolve=>target.listen(0,'127.0.0.1',resolve));
  const origin='http://127.0.0.1:'+target.address().port;
  await proxy.createProxy({origin,actors:{},login:{path:'/login'},effects:['network_read'],templates:{}});
  const get=(url,method='GET')=>new Promise((resolve,reject)=>{
    const request=http.request('http://127.0.0.1:8081',{path:url,method,agent:false},response=>{
      const chunks=[];response.on('data',chunk=>chunks.push(chunk));
      response.on('end',()=>resolve({status:response.statusCode,body:Buffer.concat(chunks).toString()}));
      response.on('error',reject);
    });
    request.on('error',reject);request.setTimeout(6000,()=>request.destroy(new Error('timeout')));request.end();
  });
  try{
    const originalNow=Date.now;
    let clockCalls=0;
    Date.now=()=>originalNow()-(clockCalls++%2?20000:0);
    const results=await Promise.all(Array.from({length:12},()=>get(origin+'/read')));
    Date.now=originalNow;
    assert.ok(results.every(x=>x.status===200&&x.body==='synthetic'));
    assert.ok(maximum<=2);
    const count=targetRequests;
    assert.equal((await get('http://203.0.113.1/read')).status,403);
    assert.equal((await get(origin+'/write','POST')).status,429);
    assert.equal(targetRequests,count);
    await assert.rejects(get(origin+'/large'));
    assert.ok(proxy.getStats().bytes_read>1048576);
    const denied=await get(origin+'/after-limit');
    assert.equal(denied.status,429);
    assert.equal(targetRequests,count+1);
  } finally {
    await proxy.closeProxy();
    await new Promise(resolve=>target.close(resolve));
  }
});
