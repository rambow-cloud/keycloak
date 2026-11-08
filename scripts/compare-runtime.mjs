import { readFile,writeFile,mkdir,mkdtemp,readdir,appendFile } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve,join } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { validateRequest,runtimeIntent,compareReports,compactReport } from './lib/runtime-update.mjs';
import { parseReleaseEvents,validateReleaseEvents } from './lib/release-events.mjs';
import { downloadScannerArchive,summarize,renderReport } from './lib/trivy.mjs';
import { nativeArchitecture } from './lib/platforms.mjs';
import { json,hash } from './lib/releases.mjs';

const [imageArg,outputArg]=process.argv.slice(2),image=resolve(imageArg??'.cache/trivy-image'),output=resolve(outputArg??'.cache/trivy-report');
const profile=process.env.BUILD_PROFILE,architecture=process.env.BUILD_ARCH;
const headSha=process.env.SCAN_HEAD_SHA??process.env.GITHUB_SHA,runId=Number(process.env.GITHUB_RUN_ID),runAttempt=Number(process.env.GITHUB_RUN_ATTEMPT??1);
const run=(cmd,args,env=process.env)=>{const r=spawnSync(cmd,args,{stdio:'inherit',timeout:900000,env});if(r.status!==0) throw Error(cmd+' failed');};
await mkdir(output,{recursive:true});
const config=JSON.parse(await readFile('config/runtime-update.json','utf8'));
const lock=JSON.parse(await readFile('images.lock.json','utf8'));
const records=await Promise.all((await readdir('releases/records')).filter(n=>n.endsWith('.json')).map(async n=>JSON.parse(await readFile('releases/records/'+n,'utf8'))));
Object.defineProperty(records,'lifecycle',{value:validateReleaseEvents(parseReleaseEvents(await readFile('releases/events.jsonl','utf8')),records)});
const active=config.request?.to===lock.runtime ? runtimeIntent(records,lock) : null;
if(!config.request||!active||config.request.to!==lock.runtime||!Object.hasOwn(config.request.from,profile)) {
  run(process.execPath,[fileURLToPath(new URL('./scan-image.mjs',import.meta.url)),image,output],{...process.env,SCAN_RUNTIME:lock.runtime});
} else {
  try {
    const request=validateRequest(config.request);
    if(request.id!==active.id||process.platform!=='linux'||nativeArchitecture()!==architecture) throw Error('Stale runtime request or nonnative comparison');
    const target=request.baselines.find(t=>t.profile===profile&&t.architecture===architecture);
    const policy=JSON.parse(await readFile('config/trivy.json','utf8'));
    const work=await mkdtemp(join(tmpdir(),'rambow-runtime-pair-')),cache=join(work,'cache'),before=join(work,'before');
    run('skopeo',['copy','--preserve-digests','docker://'+target.reference,'oci:'+before+':scan']);
    const manifest=async(layout,expected)=>{
      const index=JSON.parse(await readFile(join(layout,'index.json'),'utf8'));
      if(index.manifests?.length!==1||expected&&index.manifests[0].digest!==expected) throw Error('OCI comparison digest mismatch');
      const d=index.manifests[0].digest;
      if(!/^sha256:[a-f0-9]{64}$/.test(d)) throw Error('Invalid OCI digest');
      const bytes=await readFile(join(layout,'blobs','sha256',d.slice(7)));
      if('sha256:'+hash(bytes)!==d) throw Error('OCI manifest checksum mismatch');
      return {digest:d,config:JSON.parse(bytes).config.digest};
    };
    const previous=await manifest(before,target.digest),candidate=await manifest(image);
    const archive=await downloadScannerArchive(policy,architecture);
    await writeFile(join(work,'scanner.tar.gz'),archive);
    run('tar',['-xzf',join(work,'scanner.tar.gz'),'-C',work,'--no-same-owner','trivy']);
    const scan=async(layout,path,frozen)=>{
      run(join(work,'trivy'),['image','--config','','--ignorefile','','--scanners','vuln','--pkg-types','os,library','--severity','UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
        '--ignore-unfixed=false','--list-all-pkgs','--format','json','--output',path,'--exit-code','0','--cache-dir',cache,'--timeout','10m','--no-progress','--skip-version-check',
        ...(frozen?['--skip-db-update','--skip-java-db-update']:[]),'--input',layout]);
      return JSON.parse(await readFile(path,'utf8'));
    };
    const database=async()=>{
      const result={};
      for(const [kind,dir,file] of [['vulnerability','db','trivy.db'],['java','java-db','trivy-java.db']]) {
        const h=createHash('sha256');for await(const bytes of createReadStream(join(cache,dir,file))) h.update(bytes);
        result[kind]=h.digest('hex');
        await writeFile(join(output,dir+'-metadata.json'),await readFile(join(cache,dir,'metadata.json')));
      }
      return result;
    };
    const old=await scan(before,join(output,'before.json'),false),db=await database();
    const next=await scan(image,join(output,'trivy.json'),true),dbAfter=await database();
    if(json(db)!==json(dbAfter)||old.Metadata?.ImageID!==previous.config||next.Metadata?.ImageID!==candidate.config) throw Error('Comparison database or scanned config changed');
    const context={monitorCommit:headSha,runId,runAttempt};
    const delta=compareReports(old,next,target,context,policy);
    const pair={schemaVersion:1,requestId:request.id,profile,architecture,sourceCommit:headSha,runId,runAttempt,target,
      candidateDigest:candidate.digest,candidateConfig:candidate.config,baselineConfig:previous.config,scannerVersion:policy.version,
      scannerSha256:architecture==='arm64'?policy.linuxArm64Sha256:policy.linuxAmd64Sha256,database:db,databaseAfter:dbAfter,
      before:compactReport(old),after:compactReport(next),fullReportSha256:{before:hash(await readFile(join(output,'before.json'))),after:hash(await readFile(join(output,'trivy.json')))},delta};
    await writeFile(join(output,'runtime-pair.json'),json(pair));
    const summary=summarize(next,{profile,architecture,headSha,runId,runAttempt,policy});
    await writeFile(join(output,'summary.json'),json(summary));
    if(process.env.GITHUB_STEP_SUMMARY) await appendFile(process.env.GITHUB_STEP_SUMMARY,
      renderReport({[profile+'/'+architecture]:summary},{runUrl:'https://github.com/'+process.env.GITHUB_REPOSITORY+'/actions/runs/'+runId,headSha,runId,runAttempt,
        expectedTargets:[profile+'/'+architecture],conclusion:'Same-database runtime comparison complete; normal gate follows'})+
      '\n## Distroless update comparison\n\nDetected CVEs no longer present: '+(delta.resolved.join(', ')||'None')+'. Newly detected: '+(delta.introduced.join(', ')||'None')+'. Full before/after reports and database hashes are retained.\n');
  } catch(error) {
    await writeFile(join(output,'summary.json'),json({schemaVersion:2,profile,architecture,headSha,runId,runAttempt,status:'error'}));
    throw error;
  }
}
