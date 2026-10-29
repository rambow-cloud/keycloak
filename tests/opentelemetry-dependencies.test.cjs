const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFile,mkdtemp,rm,writeFile}=require('node:fs/promises');
const {tmpdir}=require('node:os');
const {join}=require('node:path');
const {createHash}=require('node:crypto');
const lib=import('../scripts/opentelemetry-dependencies.mjs');
const actual=JSON.parse(require('node:fs').readFileSync('dependencies/keycloak/opentelemetry.lock.json','utf8'));
const bytes=Buffer.from('reviewed test artifact'),sha=createHash('sha256').update(bytes).digest('hex');
const fixture=()=>({...actual,modules:actual.modules.map(m=>({...m,upstreamSha256:'a'.repeat(64),sha256:sha}))});
test('OpenTelemetry exception locks a complete coherent artifact inventory and rejects source/version drift',async()=>{
 const {validateTelemetryOverride}=await lib;
 const targets=validateTelemetryOverride(actual,'26.8.1');assert.equal(targets.length,14);
 assert(targets.every(t=>new URL(t.url).origin==='https://repo.maven.apache.org'&&t.path.startsWith('lib/lib/main/io.opentelemetry.')));
 assert(targets.find(t=>t.artifactId==='opentelemetry-api-incubator').url.includes('/1.67.0-alpha/'));
 for(const patch of [{version:'1.66.0'},{version:actual.upstreamVersion},{upstreamVersion:'1.68.0'},{version:'../../x'},{url:'https://evil.invalid'},{modules:actual.modules.slice(1)},{modules:[actual.modules[0],...actual.modules.slice(0,-1)]}]) assert.throws(()=>validateTelemetryOverride({...actual,...patch},'26.8.1'));
 assert.throws(()=>validateTelemetryOverride(actual,'26.8.2'),/review\/retire/);
 assert.throws(()=>validateTelemetryOverride({...actual,modules:actual.modules.map((m,i)=>i?m:{...m,sha256:'bad'})},'26.8.1'));
});
test('pinned cohort downloads reuse good cache and regenerate integrity manifests only after complete verification',async()=>{
 const {prepareTelemetryOverride}=await lib,lock=fixture(),output=await mkdtemp(join(tmpdir(),'rambow-otel-'));let count=0;
 const fetcher=async(url,options)=>{count++;assert.equal(options.redirect,'error');return new Response(bytes);};
 try {
  await prepareTelemetryOverride(lock,'26.8.1',output,fetcher);await prepareTelemetryOverride(lock,'26.8.1',output,fetcher);assert.equal(count,14);
  const original=await readFile(join(output,'upstream.sha256'),'utf8'),patched=await readFile(join(output,'patched.sha256'),'utf8');
  assert.equal(original.trim().split('\n').length,14);assert(original.includes('1.62.0-alpha.jar'));assert(patched.startsWith(sha+'  '));
  await writeFile(join(output,'opentelemetry-api.jar'),'corrupt');await prepareTelemetryOverride(lock,'26.8.1',output,fetcher);assert.equal(count,15);
 }finally{await rm(output,{recursive:true,force:true});}
});
test('wrong/failed payloads and changed Keycloak cannot produce a usable override',async()=>{
 const {prepareTelemetryOverride}=await lib,output=await mkdtemp(join(tmpdir(),'rambow-otel-failure-'));
 try {
  await assert.rejects(prepareTelemetryOverride(fixture(),'26.8.2',output,()=>{throw Error('unexpected fetch');}),/review\/retire/);
  await assert.rejects(prepareTelemetryOverride(fixture(),'26.8.1',output,async()=>new Response('wrong')),/checksum/);
  await assert.rejects(prepareTelemetryOverride(fixture(),'26.8.1',output,async()=>new Response('',{status:503})),/download failed/);
  await assert.rejects(readFile(join(output,'patched.sha256')),{code:'ENOENT'});
 }finally{await rm(output,{recursive:true,force:true});}
});
test('specific CVE regression requires complete aligned fixed scanner metadata without ignoring findings',async()=>{
 const {verifyTelemetryScan}=await lib;
 const packages=actual.modules.map(m=>({Name:'io.opentelemetry:'+m.artifactId,Version:m.artifactId.endsWith('-incubator')?'1.67.0-alpha':'1.67.0'}));
 verifyTelemetryScan({Results:[{Packages:packages}]});
 for(const report of [{},{Results:[]},{Results:[{Packages:packages.slice(1)}]},{Results:[{Packages:packages,Vulnerabilities:[{VulnerabilityID:'CVE-2026-118259'}]}]},{Results:[{Packages:packages.map((p,i)=>i?p:{...p,Version:'1.62.0'})}]},{Results:[{Packages:packages.map((p,i)=>i?p:{...p,Version:'1.68.0'})}]}])assert.throws(()=>verifyTelemetryScan(report));
});
test('publication regression follows per-profile declarations in real pre-freeze preparation shape',async()=>{
 const {requiresTelemetryRepair}=await lib;
 const prepared={images:[{profile:'core',changes:[{type:'fix',cves:['CVE-2026-118259']}]},{profile:'aws',changes:[{type:'feature'}]}]};
 assert.equal(requiresTelemetryRepair(prepared,'core'),true);assert.equal(requiresTelemetryRepair(prepared,'aws'),false);
 assert.equal(requiresTelemetryRepair({images:[{profile:'core'}]},'core'),false);
 assert.throws(()=>requiresTelemetryRepair({plan:prepared},'core'));
 assert.throws(()=>requiresTelemetryRepair(prepared,'missing'));
 assert.throws(()=>requiresTelemetryRepair({images:[...prepared.images,prepared.images[0]]},'core'));
});
