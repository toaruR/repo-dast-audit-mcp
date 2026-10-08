/* Trusted worker: no arbitrary client evaluation, shell or destination. */
'use strict';
const { chromium } = require('./playwright-core');
const http = require('http');
const readline = require('readline');
const { Transform } = require('stream');
const { randomUUID, createHash } = require('crypto');
let config, browser, proxy, stats, limited = null;
let recent=[];
function note(value){recent.push({at:Date.now(),...value}); if(recent.length>16)recent.shift();}
let contexts = new Map(), handles = new Map(), captured = new Map();
const fail = (code, message) => { const e = new Error(message); e.code = code; throw e; };
const digest = value => createHash('sha256').update(value).digest('hex');
const monotonic = ()=>Number(process.hrtime.bigint()/1000000n);
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function scoped(url) {
  const parsed = new URL(url);
  if (parsed.origin !== config.origin || parsed.username || parsed.password)
    fail('E_SCOPE', 'Destination is outside the registered target');
  return parsed;
}
function check() {
  if (limited) fail('E_LIMIT', limited);
}
function scrub(value) {
  let text = String(value);
  for (const actor of Object.values(config.actors))
    if (actor.password) text = text.split(actor.password).join('[REDACTED]');
  return text.replace(/(bearer\s+)\S+/gi, '$1[REDACTED]')
    .replace(/((?:password|token|secret|api[_-]?key)\s*[:=]\s*)[^\r\n]+/gi, '$1[REDACTED]');
}

let activeHttp=0, httpWaiters=[];
async function enterHttp() {
  if(activeHttp<2) {activeHttp++; return;}
  if(httpWaiters.length>=16) {limited='HTTP concurrency queue limit'; fail('E_LIMIT',limited);}
  await new Promise(resolve=>httpWaiters.push(resolve));
}
function leaveHttp() {
  const next=httpWaiters.shift();
  if(next) next(); else activeHttp--;
}

async function startProxy() {
  stats = config.stats || {http_requests:0, bytes_read:0, last_http_at:0};
  // A new worker has a new clock origin. Waiting one interval also preserves the job-wide rate across resets.
  stats.last_http_at=monotonic();
  proxy = http.createServer(async (incoming, outgoing) => {
    let release=null;
    try {
      const destination = scoped(incoming.url);
      note({event:'request',method:incoming.method,path:destination.pathname});
    if (!['GET','HEAD','OPTIONS'].includes(incoming.method) && destination.pathname!==config.login?.path && !config.effects.includes('fixture_write'))
      fail('E_CAPABILITY','Profile does not permit fixture writes');
      check();
      if (++stats.http_requests > 1000) { limited='request budget exceeded'; fail('E_LIMIT',limited); }
      await enterHttp();
      let released=false;
      release=()=>{if(!released){released=true;leaveHttp();}};
      outgoing.once('finish',release); outgoing.once('close',release);
      const now = monotonic();
      const wait = Math.max(0, stats.last_http_at + 200 - now);
      stats.last_http_at = now + wait;
      await pause(wait);
      if(outgoing.destroyed){release();return;}
      check();
      const headers = {...incoming.headers};
      delete headers['proxy-connection'];
      delete headers['x-web-audit-actor'];
      headers.host = destination.host;
      headers['accept-encoding'] = 'identity';
      let upload=0, responseSize=0, excerpt=[];
      const upstream = http.request(destination, {method:incoming.method, headers}, response => {
        note({event:'response',path:destination.pathname,status:response.statusCode});
        outgoing.writeHead(response.statusCode, response.headers);
        response.on('data', chunk => {
          responseSize += chunk.length;
          stats.bytes_read += chunk.length;
          if (responseSize > 1048576 || stats.bytes_read > 52428800) {
            limited='response byte budget exceeded';
            upstream.destroy(); outgoing.destroy(); return;
          }
          if (excerpt.reduce((n,b)=>n+b.length,0)<16384) excerpt.push(chunk.subarray(0,16384));
          outgoing.write(chunk);
        });
        response.on('end', () => {
          note({event:'end',path:destination.pathname,bytes:responseSize});
          outgoing.end();
          const path=destination.pathname + destination.search;
          if (!['/login','/identity'].includes(destination.pathname)) {
            const requestRef='request_'+randomUUID().replaceAll('-','');
            const templates=Object.entries(config.templates).filter(([,t])=>destination.pathname.startsWith(t.match_prefix));
            captured.set(requestRef,{path,method:incoming.method,templates:templates.map(([key])=>key)});
            if (captured.size>100) captured.delete(captured.keys().next().value);
          }
        });
        response.on('error',()=>outgoing.destroy());
      });
      outgoing.on('close',()=>upstream.destroy());
      upstream.setTimeout(15000,()=>{limited='HTTP response deadline';upstream.destroy();outgoing.destroy();});
      upstream.on('error',()=>{ if (!outgoing.headersSent) outgoing.writeHead(502); outgoing.end('lab upstream error'); });
      if (['GET','HEAD','OPTIONS'].includes(incoming.method)) {
        incoming.resume(); upstream.end();
      } else {
        const limiter=new Transform({transform(chunk,encoding,callback){
          upload+=chunk.length;
          if(upload>65536){limited='upload budget exceeded';callback(new Error(limited));}
          else callback(null,chunk);
        }});
        limiter.on('error',()=>{upstream.destroy();incoming.destroy();outgoing.destroy();});
        incoming.pipe(limiter).pipe(upstream);
      }
    } catch(e) { outgoing.writeHead(e.code==='E_SCOPE'?403:429); outgoing.end('lab policy rejected request'); }
  });
  proxy.maxConnections=32; proxy.headersTimeout=5000; proxy.requestTimeout=15000;
  proxy.on('connect',(req,socket)=>socket.destroy());
  proxy.on('upgrade',(req,socket)=>socket.destroy());
  await new Promise((resolve,reject)=>{ proxy.once('error',reject); proxy.listen(8081,'127.0.0.1',resolve); });
}
function actorConfig(actor) {
  if (!(actor in config.actors)) fail('E_AUTH','Unknown actor');
  return config.actors[actor];
}
async function actor(actor) {
  actorConfig(actor);
  if (contexts.has(actor)) {
  const existing=contexts.get(actor);
  if(!existing.verified && actor!=='anonymous') fail('E_AUTH','Actor identity is unavailable');
  return existing;
 }
  const context = await browser.newContext({serviceWorkers:'block'});
  const page=await context.newPage();
  page.setDefaultTimeout(10000);
  page.on('requestfailed',r=>note({event:'browser_request_failed',path:new URL(r.url()).pathname,reason:r.failure()?.errorText}));
  page.on('dialog',dialog=>dialog.dismiss());
  context.on('page', popup=>{ if (popup!==page) popup.close().catch(()=>{}); });
  const entry={context,page,verified:false};
  contexts.set(actor,entry);
  if (actor!=='anonymous') {
    if (!config.login) fail('E_AUTH','No registered login procedure');
    await page.goto(config.origin+config.login.path, {waitUntil:'domcontentloaded'});
    await page.locator(config.login.username_selector).fill(actorConfig(actor).username);
    await page.locator(config.login.password_selector).fill(actorConfig(actor).password);
  await Promise.all([page.waitForURL(url=>url.pathname!==config.login.path,{waitUntil:'domcontentloaded'}),
                     page.locator(config.login.submit_selector).click({noWaitAfter:true})]);
  }
  const identity=await requestProxy(entry,{url:config.origin+config.login.identity_path,path:config.login.identity_path,template:{method:'GET'},body:{}});
  const data=identity.data;
  check();
  if (data[config.login.identity_field]!==actorConfig(actor).identity)
    fail('E_AUTH','Actor identity could not be verified');
  entry.verified=true;
  if (actor==='anonymous') {
  await page.goto(config.origin+'/orders', {waitUntil:'domcontentloaded'});
  if(config.login) {
   const response=await requestProxy(entry,{url:config.origin+config.login.identity_path,path:config.login.identity_path,template:{method:'GET'},body:{}});
   entry.verified=response.data?.[config.login.identity_field]===(actorConfig(actor).identity||'anonymous');
   if(!entry.verified) fail('E_AUTH','Anonymous identity could not be verified');
  }
 }
 return entry;
}
function fixtureValue(ref) {
  const value=config.resources[ref];
  if (!value) fail('E_CAPABILITY','Unknown fixture resource');
  if (value.kind==='xss_probe') return '<script>window.__webAuditNonce='+JSON.stringify(config.nonce)+'</script>';
  return value.id;
}
function templateRequest(templateRef, mutations) {
  const t=config.templates[templateRef];
  if (!t) fail('E_CAPABILITY','Unknown request template');
  let path=t.path, body=structuredClone(t.body || {});
  for (const mutation of mutations) {
    const field=t.fields[mutation.field_ref];
    if (!field) fail('E_CAPABILITY','Request field is not permitted');
    let value=typeof mutation.value==='object'?fixtureValue(mutation.value.fixture_ref):mutation.value;
    if (field.type==='integer') {
      if (!/^-?\d+$/.test(String(value))) fail('E_SCHEMA','Expected an integer fixture field');
      value=Number(value);
    }
    if (field.location==='path') path=path.replace('{'+field.name+'}',encodeURIComponent(value));
    else if (field.location==='query') {
      const url=new URL(path,config.origin); url.searchParams.set(field.name,value); path=url.pathname+url.search;
    } else if (field.location==='json') body[field.name]=value;
    else fail('E_CAPABILITY','Unsupported request field');
  }
  if (path.includes('{')) fail('E_SCHEMA','Missing fixture field');
  const url=scoped(config.origin+path);
  return {template:t,url:url.href,path,body};
}
async function requestProxy(entry, request) {
  const method=request.template.method;
  const cookies=await entry.context.cookies(config.origin);
  const headers={cookie:cookies.map(c=>c.name+'='+c.value).join(';')};
  const payload=method==='GET'?null:Buffer.from(JSON.stringify(request.body));
  if (payload) { headers['content-type']='application/json'; headers['content-length']=String(payload.length); }
  const response=await new Promise((resolve,reject)=>{
    const outgoing=http.request('http://127.0.0.1:8081',{method,path:request.url,headers},incoming=>{
      const parts=[]; let bytes=0;
      incoming.on('data',chunk=>{ bytes+=chunk.length; if(bytes>1048576){incoming.destroy();reject(new Error('Response budget exceeded'));} else parts.push(chunk); });
      incoming.on('end',()=>resolve({status:incoming.statusCode,raw:Buffer.concat(parts).toString('utf8')}));
      incoming.on('error',reject);
    });
    outgoing.on('error',reject);
    outgoing.setTimeout(10000,()=>{outgoing.destroy();reject(new Error('Request timed out'));});
    if(payload) outgoing.write(payload);
    outgoing.end();
  });
  check();
  let data;try {data=JSON.parse(response.raw);} catch {data=null;}
  return {status:response.status,data,body:scrub(response.raw).slice(0,16384),path:request.path};
}
async function api(actorId, request) {
  const entry=await actor(actorId);
  if(!entry.verified) fail('E_AUTH','Actor identity is unavailable');
  return {...await requestProxy(entry, request),actor_id:actorId,identity_verified:true};
}
async function observe(actorId) {
  const entry=await actor(actorId), prefix='element_'+randomUUID().replaceAll('-','');
  for (const [key,value] of handles) if (value.actor===actorId) handles.delete(key);
  const controls = await entry.page.evaluate(prefix=>{
    return [...document.querySelectorAll('input,button,a,select,textarea')].slice(0,200)
      .filter(el=>el.type!=='password'&&el.name!=='password').map((el,index)=>{
        const ref=prefix+'_'+index; el.setAttribute('data-web-audit-ref',ref);
        return {ref,tag:el.tagName, id:el.id, name:el.name, text:(el.innerText||'').slice(0,120)};
      });
  },prefix);
  controls.forEach(c=>handles.set(c.ref,{actor:actorId,selector:'[data-web-audit-ref="'+c.ref+'"]'}));
  const body=await entry.page.locator('body').innerText().catch(()=> '');
  const dom=body+'\n[controls]\n'+controls.map(c=>c.ref+' '+c.tag+' '+c.id+' '+c.name+' '+c.text).join('\n');
  const url=scoped(entry.page.url());
  return {actor_id:actorId,identity_verified:entry.verified,path:url.pathname+url.search,
          dom_excerpt:scrub(dom).slice(0,32768),element_refs:controls.map(c=>c.ref),
          control_refs:Object.keys(config.controls),request_refs:[...captured.keys()],
          template_refs:Object.keys(config.templates),source_refs:[],artifact_ids:[],truncated:dom.length>32768};
}
async function action(a) {
  const entry=await actor(a.actor_id);
  if (a.kind==='navigate') {scoped(config.origin+a.path);await entry.page.goto(config.origin+a.path, {waitUntil:'domcontentloaded'});}
  else if (a.kind==='replay_request') {
    if (!captured.has(a.request_ref)) fail('E_CAPABILITY','Request was not observed');
    const request=captured.get(a.request_ref);
    const possible=request.templates.filter(id=>a.mutations.every(m=>config.templates[id].fields[m.field_ref]));
    if (possible.length!==1) fail('E_CAPABILITY','Request template is ambiguous');
    const prepared=templateRequest(possible[0],a.mutations);
    if (prepared.template.method!=='GET'&&!config.effects.includes('fixture_write')) fail('E_CAPABILITY','Fixture writes disabled');
    return {observation:await observe(a.actor_id),network:await api(a.actor_id,prepared)};
  } else if (['click','fill','select'].includes(a.kind)) {
    const handle=handles.get(a.element_ref);
    if (!handle||handle.actor!==a.actor_id) fail('E_REVISION','Element handle is stale');
    const locator=entry.page.locator(handle.selector);
    if (await locator.count()!==1) fail('E_REVISION','Element no longer matches');
    if (a.kind==='click') await locator.click();
    if (a.kind==='fill') await locator.fill(a.value);
    if (a.kind==='select') await locator.selectOption(a.value);
  } else if (a.kind!=='observe') fail('E_SCHEMA','Unknown browser action');
  check();
  return {observation:await observe(a.actor_id)};
}
async function verify(c) {
  const oracle=config.oracles[c.oracle_id];
  if (!oracle||oracle.category!==c.category||c.steps.length!==1||c.steps[0].kind!=='replay_request')
    fail('E_CAPABILITY','This case has no supported deterministic oracle');
  const step=c.steps[0];
  if (step.actor_id!==c.actor_id||step.template_ref!==oracle.template_ref)
    fail('E_CAPABILITY','Case does not match the registered oracle');
  const prepared=templateRequest(step.template_ref,step.mutations);
  const evidence=[];
  const record=(role,value)=>evidence.push({role,value});
  if (c.category==='authz_read') {
    const resource=config.resources[c.resource_ref];
    if (!resource||resource.allowed.includes(c.actor_id)) fail('E_CAPABILITY','Actor/resource policy does not deny access');
    const idMutation=step.mutations.find(m=>typeof m.value==='object'&&m.value.fixture_ref===c.resource_ref);
    if (!idMutation) fail('E_CAPABILITY','Missing symbolic resource binding');
    const owner=await api(resource.owner,prepared);
    const marker=resource.marker || config.nonce+resource.marker_suffix;
    record('control',owner);
    if (owner.status!==200||owner.data?.[oracle.marker_field]!==marker)
      return {status:'inconclusive',reason:'owner_control_failed',evidence};
    const attack=await api(c.actor_id,prepared);record('attack',attack);
    const status = attack.status===200&&attack.data?.[oracle.marker_field]===marker?'confirmed':
      [403,404].includes(attack.status)?'rejected':'inconclusive';
    return {status,
            reason:'owner_only_read_policy',evidence};
  }
  if (c.category==='xss_reflected_dom') {
    if (!step.mutations.some(m=>typeof m.value==='object'&&config.resources[m.value.fixture_ref]?.kind==='xss_probe'))
      fail('E_CAPABILITY','Only registered nonce probes can be confirmed');
    const entry=await actor(c.actor_id);
    if(!entry.verified) fail('E_AUTH','Actor identity is unavailable');
    const control=templateRequest(step.template_ref,step.mutations.map(m=>({...m,value:'plain-'+config.nonce})));
    await entry.page.goto(control.url, {waitUntil:'domcontentloaded'});
    const normal=await entry.page.evaluate(()=>window.__webAuditNonce||null);
    record('control',{path:control.path,executed:normal!==null});
    if (normal!==null) return {status:'inconclusive',reason:'control_already_executed',evidence};
    await entry.page.goto(prepared.url, {waitUntil:'domcontentloaded'});
    const observed=await entry.page.evaluate(()=>window.__webAuditNonce||null);
    record('attack',{path:prepared.path,executed:observed===config.nonce,dom:scrub(await entry.page.locator('body').innerText()).slice(0,1024)});
    check();
    return {status:observed===config.nonce?'confirmed':'rejected',reason:'input_must_be_inert',evidence};
  }
  if (c.category==='business_invariant') {
    if (!config.effects.includes('fixture_write')||!c.effects.includes('fixture_write'))
      fail('E_CAPABILITY','Fixture write capability required');
    const control=await api(c.actor_id,templateRequest(step.template_ref,oracle.control_mutations));
    record('control',control);
    if (control.status!==200||typeof control.data?.[oracle.field]!=='number'||control.data[oracle.field]<oracle.minimum)
      return {status:'inconclusive',reason:'business_control_failed',evidence};
    const attack=await api(c.actor_id,prepared);record('attack',attack);
    const status=attack.status===200&&typeof attack.data?.[oracle.field]==='number'?
      (attack.data[oracle.field]<oracle.minimum?'confirmed':'rejected'):
      [400,422].includes(attack.status)?'rejected':'inconclusive';
    return {status,
            reason:'registered_minimum_invariant',evidence};
  }
  return {status:'inconclusive',reason:'unsupported_oracle',evidence};
}
module.exports={createProxy: async value=>{config=value;await startProxy();},
                getStats:()=>stats, closeProxy:()=>new Promise(resolve=>proxy.close(resolve))};
if (require.main===module) {
const input=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
let chain=Promise.resolve();
input.on('line',line=>{
 chain=chain.then(async()=>{
  let m;
  try {
   m=JSON.parse(line);
   let result;
   if (m.method==='initialize') {
    config=m.arguments;
    await startProxy();
    browser=await chromium.launch({channel:'chromium',headless:true,chromiumSandbox:true,
      proxy:{server:'http://127.0.0.1:8081',bypass:'<-loopback>'},args:['--proxy-bypass-list=<-loopback>']});
    let health=false;
    const healthDeadline=monotonic()+5000;
    while (!health && monotonic()<healthDeadline) {
     health=await new Promise(resolve=>{
      const req=http.get('http://127.0.0.1:8081', {path:config.origin+(config.health_path||'/health')},r=>{r.resume();resolve(r.statusCode===200);});
      req.on('error',()=>resolve(false));req.setTimeout(5000,()=>{req.destroy();resolve(false);});
    });
     if (!health) await pause(200);
    }
    if (!health) fail('E_ENVIRONMENT','Target health check failed');
    result={ready:true,sandbox:true};
   } else if(m.method==='action') result=await action(m.arguments);
   else if(m.method==='verify') result=await verify(m.arguments);
   else fail('E_SCHEMA','Unknown worker method');
   check();
   process.stdout.write(JSON.stringify({id:m.id,ok:true,result,stats})+'\n');
  } catch(e) {
   process.stdout.write(JSON.stringify({id:m?.id,ok:false,code:e.code||'E_ENVIRONMENT',message:(scrub(e.message)+'\nDiagnostics: '+JSON.stringify(recent)).slice(0,8192),stats})+'\n');
  }
 });
});
input.on('close',()=>chain.finally(async()=>{if(browser)await browser.close();if(proxy)proxy.close();process.exit(0);}));

}
