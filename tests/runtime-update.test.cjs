'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync,readdirSync}=require('node:fs');
const {join}=require('node:path');
const lib=import('../scripts/lib/runtime-update.mjs');
const read=path=>JSON.parse(readFileSync(join(__dirname,'..',path),'utf8'));
const record=read('releases/records/v26.8.1-r4.json'),policy=read('config/trivy.json');
const sha='a'.repeat(40),configDigest='sha256:'+'c'.repeat(64),candidateDigest='sha256:'+'d'.repeat(64);
const vuln=id=>({VulnerabilityID:id,PkgName:'libexample',InstalledVersion:'1',FixedVersion:'',Severity:'MEDIUM'});
function report(arch,ids) {return {SchemaVersion:2,ArtifactType:'container_image',CreatedAt:'2026-11-01T00:00:00Z',Metadata:{ImageID:configDigest,OS:{Family:'debian'},ImageConfig:{os:'linux',architecture:arch}},
  Results:[{Class:'os-pkgs',Type:'debian',Target:'Debian',Packages:[{Name:'libexample',Version:'1'}],Vulnerabilities:ids.map(vuln)},
    {Class:'lang-pkgs',Type:'jar',Target:'Java',Packages:[{Name:'app',Version:'1'}]}]};}
async function fixture(){const {runtimeIntent,validateRequest}=await lib;const lock={...record.plan.imageLock,runtime:record.plan.imageLock.runtime.split('@')[0]+'@sha256:'+'f'.repeat(64)};
  const request=validateRequest({schemaVersion:1,...runtimeIntent([record],lock),issue:104,fragment:'changes/104-distroless.json'});
  const pairs=request.baselines.map(target=>({schemaVersion:1,requestId:request.id,profile:target.profile,architecture:target.architecture,target,sourceCommit:sha,runId:1,runAttempt:1,
    candidateDigest,candidateConfig:configDigest,baselineConfig:configDigest,scannerVersion:policy.version,scannerSha256:target.architecture==='arm64'?policy.linuxArm64Sha256:policy.linuxAmd64Sha256,
    database:{vulnerability:'1'.repeat(64),java:'2'.repeat(64)},databaseAfter:{vulnerability:'1'.repeat(64),java:'2'.repeat(64)},
    before:report(target.architecture,['CVE-2099-10000','CVE-2099-10001']),after:report(target.architecture,['CVE-2099-10001','CVE-2099-10002'])}));
  return {lock,request,pairs,context:{monitorCommit:sha,runId:1,runAttempt:1}};
}
test('runtime digest eligibility is explicit, same-family and independent of builder-only changes',async()=>{
  const {validateChanges,assessRelease}=await import('../scripts/lib/image-changes.mjs');
  const {eligibleRevisionChange}=await import('../scripts/lib/release-policy.mjs');
  const f=await fixture();const change={type:'runtime-update',summary:'Refresh distroless runtime with measured before/after CVE evidence.',issues:[104],profiles:['core','aws'],runtime:{from:f.request.from,to:f.request.to}};
  assert.doesNotThrow(()=>validateChanges([change]));assert.equal(Boolean(eligibleRevisionChange(change)),true);
  assert.equal(Boolean(eligibleRevisionChange({...change,type:'maintenance'})),false);
  assert.equal(Boolean(eligibleRevisionChange({...change,release:false})),false);
  for(const mutate of [c=>c.runtime.to=c.runtime.from.core,c=>c.runtime.to=c.runtime.to.replace('java25','java21'),c=>delete c.runtime.from.aws,c=>c.runtime.to=c.runtime.to.replace('gcr.io/distroless','docker.io/library')]) {const c=structuredClone(change);mutate(c);assert.throws(()=>validateChanges([c]));}
  assert.equal(typeof assessRelease,'function');
});
test('runtime requests preserve profile/architecture bindings and reject tampering',async()=>{
  const {runtimeIntent,validateRequest}=await lib;const f=await fixture();
  assert.equal(runtimeIntent([record],record.plan.imageLock),null);
  assert.equal(runtimeIntent([record],{...record.plan.imageLock,builder:'new'}),null);
  for(const mutate of [r=>r.baselines.pop(),r=>r.baselines[0].digest='bad',r=>r.baselines[0].reference='https://evil.example/image',r=>r.id='0'.repeat(64)]) {const r=structuredClone(f.request);mutate(r);assert.throws(()=>validateRequest(r));}
});
test('paired CVE deltas distinguish real disappearance, newly detected findings and zero-fix updates',async()=>{
  const {aggregatePairs}=await lib;const f=await fixture();const images=aggregatePairs(f.request,f.pairs,f.context,policy);
  assert.deepEqual(images[0].resolved,['CVE-2099-10000']);assert.deepEqual(images[0].introduced,['CVE-2099-10002']);
  f.pairs[1].after=f.pairs[1].before;
  assert.deepEqual(aggregatePairs(f.request,f.pairs,f.context,policy)[0].resolved,[],'One vulnerable architecture prevents a profile-wide repair claim');
  for(const p of f.pairs) p.after=p.before;
  assert.ok(aggregatePairs(f.request,f.pairs,f.context,policy).every(i=>!i.resolved.length));
});
test('mismatched database bytes, scanner, run, attempt, native coverage or scanned digest fail closed',async()=>{
  const {aggregatePairs}=await lib;const f=await fixture();
  for(const mutate of [p=>p.databaseAfter.java='3'.repeat(64),p=>p.runAttempt++,p=>p.sourceCommit='b'.repeat(40),p=>p.scannerVersion='0.1.0',p=>p.scannerSha256='0'.repeat(64),
    p=>p.after.Metadata.ImageConfig.architecture='other',p=>p.after.Results[1].Packages=[],p=>p.candidateConfig='sha256:'+'e'.repeat(64),p=>p.target.digest='sha256:'+'e'.repeat(64)]) {
    const pairs=structuredClone(f.pairs);mutate(pairs[0]);assert.throws(()=>aggregatePairs(f.request,pairs,f.context,policy));
  }
  assert.throws(()=>aggregatePairs(f.request,f.pairs.slice(1),f.context,policy));
  const bad=structuredClone(f.pairs);bad[0].after.Results[0].Vulnerabilities=[{...vuln('CVE-2099-10000'),Severity:'HIGH',FixedVersion:'2'}];assert.throws(()=>aggregatePairs(f.request,bad,f.context,policy),/blocked/);
});
test('compact durable evidence preserves findings and package inventory without claiming full original JSON',async()=>{
  const {compactReport,compareReports}=await lib;const f=await fixture(),p=f.pairs[0];
  assert.deepEqual(compareReports(compactReport(p.before),compactReport(p.after),p.target,f.context,policy),compareReports(p.before,p.after,p.target,f.context,policy));
});
test('Release event validation excludes fork/PR runs, failed CI and other workflows',async()=>{
  const {trustedRun}=await import('../scripts/runtime-release.mjs');
  const run={repository:{full_name:'rambow-cloud/keycloak'},head_repository:{full_name:'rambow-cloud/keycloak'},path:'.github/workflows/ci.yml',status:'completed',conclusion:'success',head_sha:sha,event:'push',head_branch:'main'};
  assert.equal(trustedRun(run,'rambow-cloud/keycloak','ci.yml','main'),run);
  for(const patch of [{event:'pull_request'},{head_branch:'branch'},{head_repository:{full_name:'fork/keycloak'}},{conclusion:'failure'},{path:'.github/workflows/untrusted.yml'}]) assert.throws(()=>trustedRun({...run,...patch},'rambow-cloud/keycloak','ci.yml','main'));
});
test('Release notes explicitly retain no-repair outcomes and never turn introduced CVEs into repairs',async()=>{
  const {buildRuntimeReport,runtimeReleaseBody}=await import('../scripts/runtime-release.mjs');const f=await fixture();
  const prepared={request:f.request,sourceCommit:sha,sourceRun:{id:1,attempt:1},lock:f.lock};
  for(const p of f.pairs) p.after=p.before;
  const body=runtimeReleaseBody(buildRuntimeReport(prepared,f.pairs,policy));assert.match(body,/No CVE repairs were detected/);assert.match(body,/runtime-comparison.json/);
});
test('runtime configuration validates selected profiles without changing final-image fingerprints',async()=>{
  const {sourceProfiles,validationProfiles}=await import('../scripts/lib/image-changes.mjs');
  assert.deepEqual(sourceProfiles('config/runtime-update.json'),[]);assert.deepEqual(sourceProfiles('scripts/compare-runtime.mjs'),[]);
  assert.deepEqual(validationProfiles('scripts/compare-runtime.mjs'),['core','aws']);
});
test('runtime updater writes only approved inputs, starts a compliant Issue first and preserves an existing candidate',async()=>{
  const {runRuntimeUpdate,checkRuntimePullRequest}=await import('../scripts/runtime-update.mjs');const {updaterApp}=await import('../scripts/lib/upstream.mjs');const f=await fixture();
  const calls=[];let createdFiles,pr,commit;
  const endpoint=(name,result)=>async args=>{calls.push([name,args]);return {data:typeof result==='function'?result(args):result};};
  const file=path=>readFileSync(join(__dirname,'..',path),'utf8');
  const github={paginate:async(method,args)=>(await method(args)).data,graphql:async(q,args)=>q.startsWith('query')?{repository:{pullRequest:{id:'PR',headRefOid:'b'.repeat(40),isDraft:false}}}:{},rest:{
    repos:{get:endpoint('metadata',{full_name:'rambow-cloud/keycloak',default_branch:'main'}),getContent:endpoint('content',a=>({encoding:'base64',content:Buffer.from(a.ref==='b'.repeat(40)?createdFiles[a.path]:file(a.path)).toString('base64')})),getCommit:async()=>({data:{sha:'b'.repeat(40),author:updaterApp.bot}})},
    git:{getRef:endpoint('ref',{object:{sha}}),getTree:endpoint('tree',{tree:readdirSync(join(__dirname,'../releases/records')).map(n=>({path:'releases/records/'+n,type:'blob'}))}),getCommit:endpoint('base',{tree:{sha}}),createTree:endpoint('createTree',a=>{createdFiles=Object.fromEntries(a.tree.map(t=>[t.path,t.content]));return {sha};}),createCommit:endpoint('commit',{sha:'b'.repeat(40)}),createRef:endpoint('branch',{})},
    issues:{listForRepo:endpoint('issues',[]),create:endpoint('createIssue',a=>({...a,number:104,state:'open',user:updaterApp.bot}))},
    pulls:{list:endpoint('pulls',[]),create:endpoint('createPR',a=>{pr={...a,number:105,user:updaterApp.bot,head:{sha:'b'.repeat(40),ref:a.head,repo:{full_name:'rambow-cloud/keycloak'}}};return pr;}),listFiles:async()=>({data:Object.keys(createdFiles).map(filename=>({filename}))})},
  }};
  const options={github,context:{repo:{owner:'rambow-cloud',repo:'keycloak'},ref:'refs/heads/main'},core:{info(){}},identity:updaterApp.bot,resolve:async()=>f.lock.runtime,inspect:async()=>({warnings:[]})};
  const result=await runRuntimeUpdate(options);assert.equal(result.issue,104);assert.ok(calls.findIndex(([n])=>n==='createIssue')<calls.findIndex(([n])=>n==='createTree'));
  require('../scripts/issue-policy.cjs').validateIssue(calls.find(([n])=>n==='createIssue')[1]&&{...calls.find(([n])=>n==='createIssue')[1],number:104,state:'open'});
  assert.ok(Object.keys(createdFiles).every(p=>['images.lock.json','config/runtime-update.json','changes/104-distroless.json'].includes(p)));
  await checkRuntimePullRequest({github,context:options.context,pr});
  await assert.rejects(checkRuntimePullRequest({github,context:options.context,pr:{...pr,body:pr.body+'human edit'}}),/edited/);
  const count=calls.length;github.rest.pulls.list=async()=>({data:[pr]});assert.equal((await runRuntimeUpdate(options)).status,'existing-candidate-preserved');assert.equal(calls.slice(count).some(([n])=>n==='createTree'),false);
});
test('automatic Release creation freezes evidence before publishing and fails on tag, source or evidence conflicts',async()=>{
  const {buildRuntimeReport,createRuntimeRelease}=await import('../scripts/runtime-release.mjs');const {updaterApp}=await import('../scripts/lib/upstream.mjs');
  const f=await fixture();const prepared={mode:'release',request:f.request,sourceCommit:sha,sourceRun:{id:1,attempt:1},lock:f.lock,selected:[]};
  const report=buildRuntimeReport(prepared,f.pairs,policy),calls=[];let releases=[],assets=[],collision=false;
  const notFound=()=>{const e=Error('not found');e.status=404;throw e;};
  const endpoint=(name,value)=>async args=>{calls.push([name,args]);return {data:typeof value==='function'?value(args):value};};
  const github={paginate:async(method,args)=>(await method(args)).data,rest:{
    repos:{getContent:async a=>({data:{encoding:'base64',content:readFileSync(join(__dirname,'..',a.path)).toString('base64')}}),listReleases:async()=>({data:releases}),
      createRelease:endpoint('draft',a=>({...a,id:5,html_url:'https://github.com/rambow-cloud/keycloak/releases/tag/'+a.tag_name})),
      listReleaseAssets:async()=>({data:assets}),getReleaseAsset:async()=>({data:Buffer.from(JSON.stringify({...report,sourceCommit:'b'.repeat(40)}))}),
      uploadReleaseAsset:endpoint('asset',{}),updateRelease:endpoint('publish',{})},
    git:{getRef:async()=>collision?{data:{object:{sha}}}:notFound(),getTree:async()=>({data:{tree:readdirSync(join(__dirname,'../releases/records')).map(n=>({path:'releases/records/'+n,type:'blob'}))}})},
  }};
  const options={github,context:{repo:{owner:'rambow-cloud',repo:'keycloak'},sha},prepared,report,identity:updaterApp.bot,refresh:async()=>prepared};
  assert.equal((await createRuntimeRelease(options)).status,'formal-release-created');
  assert.deepEqual(calls.map(([n])=>n),['draft','asset','publish']);
  assert.equal(calls[0][1].target_commitish,sha);assert.equal(calls[0][1].draft,true);assert.equal(calls[2][1].draft,false);
  calls.length=0;collision=true;await assert.rejects(createRuntimeRelease(options),/already exists/);assert.equal(calls.length,0);
  collision=false;await assert.rejects(createRuntimeRelease({...options,refresh:async()=>({...prepared,sourceCommit:'b'.repeat(40)})}),/baseline changed/);
  releases=[{id:5,draft:false,tag_name:'v26.8.1-r100',body:'<!-- rambow-runtime-release:'+f.request.id+' -->'}];assets=[{id:1,name:'runtime-comparison.json',size:100}];
  await assert.rejects(createRuntimeRelease(options),/evidence conflicts/);assert.equal(calls.length,0);
});
