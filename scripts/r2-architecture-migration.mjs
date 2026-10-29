import {readFile,writeFile,mkdir,mkdtemp,copyFile,unlink,rm} from 'node:fs/promises';
import {writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {pathToFileURL,fileURLToPath} from 'node:url';
import {hash,json,equal,registry} from './lib/releases.mjs';
import {combineLayouts,inspectLayout,fileHash} from './lib/multiarch.mjs';
import {validateSummary,gateSummary} from './lib/trivy.mjs';
import {federatedQuayCredentials,quayRegistryWriteToken} from './lib/quay-auth.mjs';
import {readAsset,putImmutableAsset} from './quay-release.mjs';
import {validateReleaseEvents} from './lib/release-events.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const config=JSON.parse(await readFile(join(root,'config/r2-architecture-migration.json'),'utf8'));
const original=JSON.parse(await readFile(join(root,'releases/records/v26.8.1-r2.json'),'utf8'));
const withdrawn=JSON.parse(await readFile(join(root,'releases/records/v26.8.1-r3.json'),'utf8'));
const identity=profile=>({profile,sourceCommit:config.sourceCommit,keycloakVersion:'26.8.1'});
function run(command,args,options={}) {
  const result=spawnSync(command,args,{encoding:'utf8',timeout:600000,maxBuffer:10000000,...options});
  if(result.error||result.status!==0) throw Error(command+' failed: '+(result.error?.message??result.stderr?.slice(0,1500)));
  return result.stdout;
}
export function migrationAction(current,before,expected) {
  if(!/^sha256:[a-f0-9]{64}$/.test(before??'')||!/^sha256:[a-f0-9]{64}$/.test(expected??'')||before===expected) throw Error('Invalid migration transition');
  if(current===expected) return 'reuse';
  if(current===before) return 'expand';
  throw Error('Destination differs from both the authorized original AMD64 digest and frozen index');
}
export function withdrawalTargets(bindings) {
  const targets=[];
  for(const image of withdrawn.plan.images) {
    if(!Object.hasOwn(bindings,image.tag)) continue;
    if(bindings[image.tag]!==image.digest||Object.entries(bindings).some(([tag,digest])=>tag!==image.tag&&digest===image.digest)) throw Error('r3 withdrawal conflicts with unexpected digest or additional manifest tags');
    targets.push(image);
  }
  return targets;
}
export function assertMigrationOutcome({active,eventName,ref,results}) {
  if(results.prepare!=='success'||!['true','false'].includes(active)) throw Error('No trustworthy migration decision');
  const writes=['freeze','publish','audit'];
  if(active==='false') {
    if(['verify',...writes].some(job=>results[job]!=='skipped')) throw Error('Completed migration must be an explicit no-op');
    return;
  }
  if(results.verify!=='success') throw Error('Frozen package verification did not pass');
  const expected=eventName==='workflow_dispatch'&&ref==='refs/heads/main'?'success':'skipped';
  if(writes.some(job=>results[job]!==expected)) throw Error('Migration publication/audit outcomes are incomplete or unexpected');
}
export function validateMigrationPlan(plan) {
  if(config.id!=='r2-arm64-v1'||config.tag!=='v26.8.1-r2'||config.sourceCommit!==original.plan.sourceCommit||config.sourceLockSha256!==original.plan.lockSha256||
    plan.schemaVersion!==1||plan.id!==config.id||plan.tag!==config.tag||plan.releaseId!==original.plan.releaseId||plan.sourceCommit!==config.sourceCommit||
    !/^[a-f0-9]{40}$/.test(plan.toolsCommit??'')||!Number.isSafeInteger(plan.sourceRun)||plan.sourceRun<1||!Number.isSafeInteger(plan.sourceAttempt)||plan.sourceAttempt<1||plan.configSha256!==hash(json(config))||plan.images?.length!==2) throw Error('Invalid bounded r2 migration identity');
  for(const expected of config.images) {
    const matches=plan.images.filter(i=>i.profile===expected.profile), image=matches[0], old=original.plan.images.find(i=>i.profile===expected.profile);
    if(matches.length!==1||expected.tag!==old.tag||expected.beforeDigest!==old.digest||image.tag!==old.tag||image.beforeDigest!==old.digest||
      !/^sha256:[a-f0-9]{64}$/.test(image.digest??'')||image.digest===old.digest||!/^[a-f0-9]{64}$/.test(image.archiveSha256??'')||image.children?.length!==2||
      image.children.filter(c=>c.architecture==='amd64'&&c.digest===old.digest).length!==1||
      image.children.filter(c=>c.architecture==='arm64'&&c.digest!==old.digest&&/^sha256:[a-f0-9]{64}$/.test(c.digest??'')).length!==1) throw Error('Migration must retain each original r2 AMD64 child');
  }
  return plan;
}
export async function prepareMigration({github,context,core}) {
  const {data:release}=await github.rest.repos.getReleaseByTag({...context.repo,tag:config.tag});
  if(release.id!==config.releaseId||release.target_commitish!==config.sourceCommit) throw Error('Original r2 Release identity changed');
  const completed=await readAsset(github,context.repo,release,'architecture-extension-record.json');
  const frozen=await readAsset(github,context.repo,release,'architecture-extension-plan.json');
  if(frozen) validateMigrationPlan(frozen);
  if(completed) {
    validateReleaseEvents([completed],[original]);
    if(!frozen||completed.operation!=='architecture-expansion'||completed.consumedSourceCommit!==frozen.toolsCommit||!equal(completed.images,frozen.images.map(({profile,tag,beforeDigest,digest,children})=>({profile,tag,beforeDigest,digest,children})))) throw Error('Completed migration evidence does not match its frozen plan');
  }
  core.setOutput('active',!completed);
  core.setOutput('reuse',!!frozen);
  core.setOutput('source_run',frozen?.sourceRun??context.runId);
  core.setOutput('artifact','r2-architecture-package-'+(frozen?.sourceRun??context.runId)+'-'+(frozen?.sourceAttempt??process.env.GITHUB_RUN_ATTEMPT));
  core.setOutput('plan',JSON.stringify(frozen));
}
async function prepareSource(path) {
  if(run('git',['-C',path,'rev-parse','HEAD']).trim()!==config.sourceCommit) throw Error('Checkout is not the original r2 source');
  const lockText=await readFile(join(path,'images.lock.json'),'utf8');
  if(hash(lockText)!==config.sourceLockSha256) throw Error('r2 input lock changed');
  await writeFile(join(path,'.source-lock.json'),lockText);
  const lock=JSON.parse(lockText);delete lock.platform;lock.platforms=['linux/amd64','linux/arm64'];
  await writeFile(join(path,'images.lock.json'),json(lock));
  // Overlay only native build/verification tooling, never distribution, providers or Containerfile.
  for(const file of ['scripts/build.sh','scripts/verify-image.sh','scripts/platform.mjs','scripts/lib/platforms.mjs']) {
    await mkdir(join(path,file,'..'),{recursive:true});await copyFile(join(root,file),join(path,file));
  }
  const buildPath=join(path,'scripts/build.sh'), build=await readFile(buildPath,'utf8'), revision='${GITHUB_SHA:-$(git rev-parse HEAD)}';
  if(build.split(revision).length!==2) throw Error('Reviewed build revision label changed');
  await writeFile(buildPath,build.replace(revision,config.sourceCommit));
}
async function exportNative(path,layout,out) {
  const profile=process.env.BUILD_PROFILE;
  if(process.env.BUILD_ARCH!=='arm64'||!config.images.some(i=>i.profile===profile)) throw Error('Only the missing ARM64 profile may be built');
  if(hash(await readFile(join(path,'.source-lock.json'),'utf8'))!==config.sourceLockSha256) throw Error('r2 source-lock evidence missing');
  const checked=await inspectLayout(layout,identity(profile),['arm64']);
  const summary=JSON.parse(await readFile(join(path,'.cache/migration-scan/summary.json'),'utf8'));
  validateSummary(summary,{profile,architecture:'arm64',headSha:process.env.TOOLS_COMMIT,runId:Number(process.env.GITHUB_RUN_ID),runAttempt:Number(process.env.GITHUB_RUN_ATTEMPT)});gateSummary(summary);
  await mkdir(out,{recursive:true});
  run('skopeo',['copy','--preserve-digests','oci:'+resolve(layout),'oci-archive:'+resolve(out,'keycloak.oci.tar')]);
  await writeFile(join(out,'native-evidence.json'),json({profile,architecture:'arm64',sourceCommit:config.sourceCommit,toolsCommit:process.env.TOOLS_COMMIT,runId:Number(process.env.GITHUB_RUN_ID),sourceLockSha256:config.sourceLockSha256,digest:checked.digest,archiveSha256:await fileHash(join(out,'keycloak.oci.tar'))}));
  await writeFile(join(out,'scan-summary.json'),json(summary));
}
async function assemble(input,out) {
  const work=await mkdtemp(join(tmpdir(),'r2-index-')),images=[];
  for(const target of config.images) {
    const native=join(input,'r2-arm64-'+target.profile+'-'+process.env.GITHUB_RUN_ID+'-'+process.env.GITHUB_RUN_ATTEMPT);
    const evidence=JSON.parse(await readFile(join(native,'native-evidence.json'),'utf8'));
    const summary=JSON.parse(await readFile(join(native,'scan-summary.json'),'utf8'));
    validateSummary(summary,{profile:target.profile,architecture:'arm64',headSha:process.env.TOOLS_COMMIT,runId:Number(process.env.GITHUB_RUN_ID),runAttempt:Number(process.env.GITHUB_RUN_ATTEMPT)});gateSummary(summary);
    if(evidence.sourceCommit!==config.sourceCommit||evidence.toolsCommit!==process.env.TOOLS_COMMIT||evidence.profile!==target.profile||evidence.architecture!=='arm64'||evidence.runId!==Number(process.env.GITHUB_RUN_ID)||evidence.sourceLockSha256!==config.sourceLockSha256||evidence.archiveSha256!==await fileHash(join(native,'keycloak.oci.tar'))) throw Error('Native artifact provenance mismatch');
    const amd=join(work,target.profile,'amd64'),arm=join(work,target.profile,'arm64'),combined=join(work,target.profile,'combined');
    await mkdir(join(work,target.profile),{recursive:true});
    run('skopeo',['copy','--preserve-digests','docker://'+registry+'@'+target.beforeDigest,'oci:'+amd+':original']);
    run('skopeo',['copy','--preserve-digests','oci-archive:'+join(native,'keycloak.oci.tar'),'oci:'+arm+':native']);
    const reused=await inspectLayout(amd,identity(target.profile),['amd64']), added=await inspectLayout(arm,identity(target.profile),['arm64']);
    if(reused.digest!==target.beforeDigest||added.digest!==evidence.digest) throw Error('Original/native manifest mismatch');
    const index=await combineLayouts([{architecture:'amd64',path:amd},{architecture:'arm64',path:arm}],combined,identity(target.profile));
    const folder=join(out,target.profile);await mkdir(folder,{recursive:true});
    const archive=join(folder,'keycloak.oci.tar');run('tar',['-cf',resolve(archive),'-C',combined,'oci-layout','index.json','blobs']);
    if('sha256:'+hash(run('skopeo',['inspect','--raw','oci-archive:'+resolve(archive)]))!==index.digest) throw Error('Index digest changed during archiving');
    images.push({...target,digest:index.digest,children:index.children,archiveSha256:await fileHash(archive)});
  }
  const plan=validateMigrationPlan({schemaVersion:1,id:config.id,tag:config.tag,releaseId:config.releaseId,sourceCommit:config.sourceCommit,toolsCommit:process.env.TOOLS_COMMIT,sourceRun:Number(process.env.GITHUB_RUN_ID),sourceAttempt:Number(process.env.GITHUB_RUN_ATTEMPT),configSha256:hash(json(config)),images});
  await writeFile(join(out,'plan.json'),json(plan));await rm(work,{recursive:true,force:true});
}
async function inspectPackage(path,scan=false) {
  const plan=validateMigrationPlan(JSON.parse(await readFile(join(path,'plan.json'),'utf8')));
  const work=await mkdtemp(join(tmpdir(),'r2-verify-'));
  for(const image of plan.images) {
    const archive=join(path,image.profile,'keycloak.oci.tar');
    if(await fileHash(archive)!==image.archiveSha256) throw Error('Frozen migration archive checksum mismatch');
    const layout=join(work,image.profile);run('skopeo',['copy','--all','--preserve-digests','oci-archive:'+resolve(archive),'oci:'+layout+':index']);
    const checked=await inspectLayout(layout,identity(image.profile));
    if(checked.digest!==image.digest||!equal(checked.children,image.children)) throw Error('Frozen index/children mismatch');
    if(scan) for(const child of image.children) {
      const selected=join(work,image.profile+'-'+child.architecture),report=join(path,'scans',image.profile,child.architecture);
      await mkdir(report,{recursive:true});run('skopeo',['--override-arch',child.architecture,'copy','--preserve-digests','oci:'+layout,'oci:'+selected+':scan']);
      const env={...process.env,BUILD_PROFILE:image.profile,BUILD_ARCH:child.architecture,SCAN_HEAD_SHA:process.env.TOOLS_COMMIT};
      run(process.execPath,[join(root,'scripts/scan-image.mjs'),selected,report],{env});
      const summary=JSON.parse(await readFile(join(report,'summary.json'),'utf8'));
      validateSummary(summary,{profile:image.profile,architecture:child.architecture,headSha:process.env.TOOLS_COMMIT,runId:Number(process.env.GITHUB_RUN_ID),runAttempt:Number(process.env.GITHUB_RUN_ATTEMPT)});gateSummary(summary);
    }
  }
  await rm(work,{recursive:true,force:true});return plan;
}
export async function publishMigration({github,context,core,path,out}) {
  if(context.eventName!=='workflow_dispatch'||context.ref!=='refs/heads/main') throw Error('Migration writes require reviewed main dispatch');
  const plan=await inspectPackage(path);
  if(!equal(JSON.parse(await readFile(join(root,'releases/archives/v26.8.1-r3/publication-record.json'),'utf8')),withdrawn)) throw Error('Original r3 publication must be archived before withdrawal');
  const {data:release}=await github.rest.repos.getReleaseByTag({...context.repo,tag:config.tag});
  if(!equal(await readAsset(github,context.repo,release,'architecture-extension-plan.json'),plan)) throw Error('Release extension plan is not frozen');
  const credentials=await federatedQuayCredentials({username:process.env.QUAY_USERNAME,context,getIDToken:audience=>core.getIDToken(audience),mask:value=>core.setSecret(value)});
  const work=await mkdtemp(join(tmpdir(),'r2-auth-')),auth=join(work,'auth.json');await mkdir(out,{recursive:true});
  const state={schemaVersion:1,tag:config.tag,runId:context.runId,completedTags:[],withdrawnTags:[]};
  try {
    run('skopeo',['login','--authfile',auth,'--username',credentials.username,'--password-stdin','quay.io'],{input:credentials.token});
    const actions={};
    for(const image of plan.images) {
      const current='sha256:'+hash(run('skopeo',['inspect','--authfile',auth,'--raw','docker://'+registry+':'+image.tag]));
      actions[image.profile]=migrationAction(current,image.beforeDigest,image.digest);
    }
    for(const image of plan.images) {
      if(actions[image.profile]==='expand') {
        const result=join(work,'digest');run('skopeo',['copy','--all','--preserve-digests','--authfile',auth,'--digestfile',result,'oci-archive:'+resolve(path,image.profile,'keycloak.oci.tar'),'docker://'+registry+':'+image.tag]);
        if((await readFile(result,'utf8')).trim()!==image.digest) throw Error('Registry did not preserve the frozen index digest');
      }
      state.completedTags.push(image.tag);writeFileSync(join(out,'attempt.json'),json(state));
    }
    // Registry deletion expires every tag on a manifest. Refuse any extra binding,
    // then address only the two archived r3 index digests; never delete children.
    const tags=JSON.parse(run('skopeo',['list-tags','--authfile',auth,'docker://'+registry])).Tags;
    if(!Array.isArray(tags)||tags.length>100||new Set(tags).size!==tags.length) throw Error('Unexpected registry tag inventory');
    const bindings=Object.create(null);
    for(const tag of tags) {
      if(!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$/.test(tag)) throw Error('Invalid registry tag');
      bindings[tag]='sha256:'+hash(run('skopeo',['inspect','--authfile',auth,'--raw','docker://'+registry+':'+tag]));
    }
    const targets=withdrawalTargets(bindings);
    const bearer=targets.length?await quayRegistryWriteToken({credentials,mask:value=>core.setSecret(value)}):null;
    for(const image of targets) {
      run('skopeo',['delete','--registry-token',bearer,'docker://'+registry+'@'+image.digest]);
      state.withdrawnTags.push(image.tag);writeFileSync(join(out,'attempt.json'),json(state));
    }
    const remaining=JSON.parse(run('skopeo',['list-tags','--authfile',auth,'docker://'+registry])).Tags;
    if(!Array.isArray(remaining)||withdrawn.plan.images.some(i=>remaining.includes(i.tag))) throw Error('r3 tags remain after withdrawal');
    state.withdrawnTags=withdrawn.plan.images.map(i=>i.tag);writeFileSync(join(out,'attempt.json'),json(state));
    const event={schemaVersion:1,id:'v26.8.1-r2-arm64',operation:'architecture-expansion',tag:config.tag,recordedAt:new Date().toISOString(),issue:70,runId:context.runId,consumedSourceCommit:plan.toolsCommit,images:plan.images.map(({profile,tag,beforeDigest,digest,children})=>({profile,tag,beforeDigest,digest,children}))};
    await writeFile(join(out,'event.json'),json(event));
  } finally { await unlink(auth).catch(error=>{if(error.code!=='ENOENT') throw error;}); }
}
async function main() {
  const [command,...args]=process.argv.slice(2);
  if(command==='source') await prepareSource(resolve(args[0]));
  else if(command==='export-arm') await exportNative(...args.map(p=>resolve(p)));
  else if(command==='assemble') await assemble(...args.map(p=>resolve(p)));
  else if(command==='verify') await inspectPackage(resolve(args[0]),true);
  else throw Error('Use source, export-arm, assemble or verify');
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url) await main();
