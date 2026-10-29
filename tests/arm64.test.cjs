const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const {join} = require('node:path');
const {tmpdir} = require('node:os');
const {createHash} = require('node:crypto');
const platforms = import('../scripts/lib/platforms.mjs');
const multiarch = import('../scripts/lib/multiarch.mjs');
const releases = import('../scripts/lib/releases.mjs');
const scans = import('../scripts/lib/trivy.mjs');
const sourceCommit = 'a'.repeat(40);
const identity = {profile:'core',keycloakVersion:'26.8.1',sourceCommit};
const digest = c => 'sha256:'+c.repeat(64);
const lock = {keycloakVersion:'26.8.1',javaVersion:25,platforms:['linux/amd64','linux/arm64']};
test('platform locks and base indexes require unique native amd64/arm64 coverage',async()=>{
  const {lockArchitectures,nativeArchitecture,assertBasePlatforms}=await platforms;
  assert.deepEqual(lockArchitectures(lock),['amd64','arm64']);
  assert.deepEqual(lockArchitectures({platform:'linux/amd64'}),['amd64']);
  assert.equal(nativeArchitecture('arm64'),'arm64'); assert.equal(nativeArchitecture('x64'),'amd64');
  for(const invalid of ['ia32','riscv64']) assert.throws(()=>nativeArchitecture(invalid));
  for(const invalid of [{platforms:['linux/amd64']},{...lock,platform:'linux/amd64'},{platform:'linux/arm64'}]) assert.throws(()=>lockArchitectures(invalid));
  const manifest={schemaVersion:2,manifests:['amd64','arm64'].map((architecture,i)=>({platform:{os:'linux',architecture},digest:digest(i?'b':'a')}))};
  assertBasePlatforms(manifest);
  for(const list of [manifest.manifests.slice(0,1),[manifest.manifests[0],manifest.manifests[0]],manifest.manifests.map(m=>({...m,platform:{...m.platform,os:'windows'}}))]) assert.throws(()=>assertBasePlatforms({...manifest,manifests:list}));
});
async function blob(path,value,mediaType){
  const bytes=Buffer.isBuffer(value)?value:Buffer.from(JSON.stringify(value));
  const digest='sha256:'+createHash('sha256').update(bytes).digest('hex');
  await fs.mkdir(join(path,'blobs','sha256'),{recursive:true}); await fs.writeFile(join(path,'blobs','sha256',digest.slice(7)),bytes);
  return {mediaType,digest,size:bytes.length};
}
async function native(path,architecture,labels={}){
  const config=await blob(path,{os:'linux',architecture,config:{Labels:{'org.opencontainers.image.revision':sourceCommit,'org.opencontainers.image.version':'26.8.1','cloud.rambow.keycloak.profile':'core',...labels}}},'application/vnd.oci.image.config.v1+json');
  const layer=await blob(path,Buffer.from('native layer '+architecture),'application/vnd.oci.image.layer.v1.tar');
  const manifest=await blob(path,{schemaVersion:2,mediaType:'application/vnd.oci.image.manifest.v1+json',config,layers:[layer]},'application/vnd.oci.image.manifest.v1+json');
  await fs.writeFile(join(path,'index.json'),JSON.stringify({schemaVersion:2,manifests:[manifest]}));
  return {architecture,path,digest:manifest.digest,layer};
}
test('OCI composition preserves exact child digests and is deterministic across input order',async t=>{
  const work=await fs.mkdtemp(join(tmpdir(),'arm64-'));t.after(()=>fs.rm(work,{recursive:true,force:true}));
  const inputs=await Promise.all(['amd64','arm64'].map(a=>native(join(work,a),a)));
  const {combineLayouts,inspectLayout}=await multiarch;
  const first=await combineLayouts(inputs,join(work,'one'),identity);
  const second=await combineLayouts([...inputs].reverse(),join(work,'two'),identity);
  assert.deepEqual(first,second);
  assert.deepEqual(first.children,inputs.map(i=>({architecture:i.architecture,digest:i.digest})));
  const inspection=await inspectLayout(join(work,'one'),identity);
  assert.equal(inspection.digest,first.digest);assert.deepEqual(inspection.children,first.children);
  await assert.rejects(inspectLayout(join(work,'one'),{...identity,profile:'aws'}),/profile/);
  await assert.rejects(combineLayouts([inputs[0],inputs[0]],join(work,'bad'),identity),/native/);
  await fs.writeFile(join(work,'one','blobs','sha256',inputs[1].layer.digest.slice(7)),'tampered');
  await assert.rejects(inspectLayout(join(work,'one'),identity),/checksum/);
});
test('OCI inspection rejects a mislabelled native architecture and corrupt metadata before packaging',async t=>{
  const work=await fs.mkdtemp(join(tmpdir(),'arm64-'));t.after(()=>fs.rm(work,{recursive:true,force:true}));
  const input=await native(join(work,'native'),'amd64');
  const {inspectLayout}=await multiarch;
  await assert.rejects(inspectLayout(input.path,identity,['arm64']),/architecture/);
  await fs.writeFile(join(input.path,'blobs','sha256',input.digest.slice(7)),'{}');
  await assert.rejects(inspectLayout(input.path,identity,['amd64']),/digest/);
});
async function planFixture(){
  const {hash}=await releases;
  return {schemaVersion:3,registry:'quay.io/rambow-cloud/keycloak',tag:'v26.8.1-r3',releaseId:10,keycloakVersion:'26.8.1',revision:3,sourceCommit,toolsCommit:'b'.repeat(40),sourceRun:{id:1,attempt:1},lockSha256:hash(JSON.stringify(lock)),imageLock:lock,aliases:[],previousAliases:{},images:[{profile:'core',artifactId:1,artifactName:'keycloak-oci-core-multiarch-'+sourceCommit,tag:'26.8.1-r3-core',digest:digest('c'),archiveSha256:'d'.repeat(64),inputSha256:'e'.repeat(64),changes:[{type:'feature',summary:'Add native ARM64 alongside the existing AMD64 image.',issues:[64]}],children:[{architecture:'amd64',digest:digest('f')},{architecture:'arm64',digest:digest('a')}]}]};
}
test('frozen multiarch plans bind both children and select only the exact multiarch artifact',async()=>{
  const {validatePlan,chooseArtifacts}=await releases;
  const plan=await planFixture();validatePlan(plan);
  for(const children of [[],plan.images[0].children.slice(0,1),[plan.images[0].children[0],plan.images[0].children[0]],[{architecture:'arm64',digest:plan.images[0].digest},plan.images[0].children[0]]]) assert.throws(()=>validatePlan({...plan,images:[{...plan.images[0],children}]}));
  const artifact={id:1,name:plan.images[0].artifactName,expired:false,size_in_bytes:100};
  assert.equal(chooseArtifacts([artifact],sourceCommit,['core'],lock)[0].artifactId,1);
  assert.throws(()=>chooseArtifacts([{...artifact,name:'keycloak-oci-core-amd64-'+sourceCommit}],sourceCommit,['core'],lock),/Missing/);
  const {makeFrozenPlan}=await import('../scripts/quay-release.mjs');
  const prepared={...plan,frozen:plan};
  const scan={profile:'core',sourceCommit,sourceRunId:1,artifactId:1,lockSha256:plan.lockSha256,digest:plan.images[0].digest,archiveSha256:plan.images[0].archiveSha256,children:plan.images[0].children};
  assert.deepEqual(makeFrozenPlan(prepared,[scan]),plan);
  assert.throws(()=>makeFrozenPlan(prepared,[{...scan,children:[...scan.children.slice(0,1),{architecture:'arm64',digest:digest('b')}]}]),/Frozen|differ/);
});
test('publication retries reuse the complete index and conflicts stop before any copy',async()=>{
  const {publishImages}=await import('../scripts/lib/quay-publish.mjs');
  const plan=await planFixture();let copied=0;
  const adapter={inspect:async()=>plan.images[0].digest,copy:async()=>{copied++;return plan.images[0].digest;}};
  const record=await publishImages(plan,adapter,{runId:2});assert.equal(copied,0);assert.deepEqual(record.plan.images[0].children,plan.images[0].children);
  await assert.rejects(publishImages(plan,{...adapter,inspect:async()=>digest('d')},{runId:2}),/Immutable/);assert.equal(copied,0);
});
const scanContext={profile:'core',headSha:sourceCommit,runId:1,runAttempt:1,policy:{version:'0.76.1',linuxAmd64Sha256:'a'.repeat(64),blockingSeverities:['HIGH','CRITICAL'],blockUnfixed:false}};
const report=architecture=>({SchemaVersion:2,ArtifactType:'container_image',Metadata:{OS:{Family:'debian'},ImageConfig:{os:'linux',architecture}},Results:[{Class:'os-pkgs'},{Class:'lang-pkgs',Type:'jar'}]});
test('scanner summaries and release gates cannot substitute one architecture for another',async()=>{
  const {summarize,validateSummary,gateTargetSummaries}=await scans;
  const summaries=['amd64','arm64'].map(architecture=>summarize(report(architecture),{...scanContext,architecture}));
  const aggregate={schemaVersion:3,profile:'core',summaries};gateTargetSummaries(aggregate,scanContext);
  assert.throws(()=>summarize(report('amd64'),{...scanContext,architecture:'arm64'}),/architecture/);
  assert.throws(()=>validateSummary(summaries[0],{...scanContext,architecture:'arm64'}),/match/);
  for(const list of [[summaries[0]],[summaries[0],summaries[0]],[summaries[0],{...summaries[1],status:'error'}]]) assert.throws(()=>gateTargetSummaries({...aggregate,summaries:list},scanContext));
});
test('trusted report planning exposes missing architecture jobs/reports instead of a clean profile',async()=>{
  const {plannedScanTargets}=await import('../scripts/trivy-comment.mjs');
  assert.deepEqual(plannedScanTargets([{name:'Build aws (amd64)',conclusion:'success'}]),['aws/amd64','aws/arm64']);
  const {summarize,renderReport}=await scans;
  const summary=summarize(report('amd64'),{...scanContext,architecture:'amd64'});
  const md=renderReport({'core/amd64':summary},{runUrl:'https://github.com/rambow-cloud/keycloak/actions/runs/1',headSha:sourceCommit,runId:1,runAttempt:1,conclusion:'failure',expectedTargets:['core/amd64','core/arm64']});
  assert.match(md,/core\/arm64.*FAILED \/ missing/);
});
