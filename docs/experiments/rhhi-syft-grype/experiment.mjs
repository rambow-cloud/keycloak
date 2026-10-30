import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {resolve, dirname} from 'node:path';
import {fileURLToPath} from 'node:url';

const directory=dirname(fileURLToPath(import.meta.url));
const lock=JSON.parse(fs.readFileSync(resolve(directory,'inputs.lock.json')));
const candidateByDigest=lock.candidate.reference.replace(/:[^/@]+@/,'@');
const output=resolve('.cache/rhhi-results');
const prepared=resolve('.cache/rhhi-prepared');
const arch=process.arch==='arm64'?'arm64':'amd64';
const read=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const write=(p,v)=>{fs.mkdirSync(dirname(p),{recursive:true});fs.writeFileSync(p,JSON.stringify(v,null,2)+'\n');};
const hash=p=>{
  const digest=createHash('sha256'),fd=fs.openSync(p,'r'),buffer=Buffer.alloc(4*1024*1024);
  try {let bytes;while((bytes=fs.readSync(fd,buffer,0,buffer.length,null))>0)digest.update(buffer.subarray(0,bytes));return digest.digest('hex');}
  finally {fs.closeSync(fd);}
};
function run(command,args,file,env={}) {
  const fd=file?fs.openSync(file,'w'):undefined;
  try {
    const r=spawnSync(command,args,{encoding:'utf8',timeout:1200000,maxBuffer:10000000,
      env:{...process.env,...env},stdio:file?['ignore',fd,'inherit']:['ignore','pipe','inherit']});
    if(r.error||r.status!==0)throw Error(command+' failed: '+(r.error?.message??r.status));
    return r.stdout?.trim();
  } finally {if(fd!==undefined)fs.closeSync(fd);}
}
process.env.GRYPE_DB_CACHE_DIR=resolve('.cache/rhhi-db');
process.env.GRYPE_DB_AUTO_UPDATE='false';
process.env.GRYPE_CHECK_FOR_APP_UPDATE='false';
process.env.SYFT_CHECK_FOR_APP_UPDATE='false';
process.env.SYFT_JAVA_USE_NETWORK='false';
process.env.GRYPE_EXTERNAL_SOURCES_ENABLE='false';
async function tools() {
  const dir=resolve('.cache/rhhi-tools');fs.mkdirSync(dir,{recursive:true});
  const bins={};
  for(const name of ['syft','grype']) {
    const tool=lock[name],pin=tool.architectures[arch];
    const r=await fetch('https://github.com/anchore/'+name+'/releases/download/v'+tool.version+'/'+pin.filename,{signal:AbortSignal.timeout(120000)});
    if(!r.ok)throw Error('Tool download '+r.status);
    const p=resolve(dir,pin.filename);fs.writeFileSync(p,Buffer.from(await r.arrayBuffer()));
    if(hash(p)!==pin.sha256)throw Error('Tool checksum mismatch');
    run('tar',['-xzf',p,'-C',dir,name]);bins[name]=resolve(dir,name);
    const version=run(bins[name],['version','-o','json']);
    if(JSON.parse(version).version!==tool.version)throw Error('Unexpected '+name+' version');
  }
  return bins;
}
function databaseHash() {
  const status=read(resolve(output,'database-status.json'));
  if(!status.valid||!fs.existsSync(status.path))throw Error('Grype database unavailable');
  return hash(status.path);
}
async function prepare() {
  fs.mkdirSync(output,{recursive:true});fs.mkdirSync(prepared,{recursive:true});
  run('skopeo',['inspect','--raw','docker://'+candidateByDigest],resolve(prepared,'base-index.json'));
  if('sha256:'+hash(resolve(prepared,'base-index.json'))!==lock.candidate.digest)throw Error('Base index mismatch');
  const bins=await tools();run(bins.grype,['db','update']);
  run(bins.grype,['db','status','-o','json'],resolve(output,'database-status.json'));
  const status=read(resolve(output,'database-status.json'));
  const dbHash=databaseHash();
  if(!status.valid||!/^v?6\./.test(status.schemaVersion))throw Error('Invalid Grype database');
  // Distribute exactly one database, including its metadata, to all native jobs.
  run('tar',['-czf',resolve(prepared,'database.tar.gz'),'-C',process.env.GRYPE_DB_CACHE_DIR,'.']);
  const controls=[];
  const guava=read('dependencies/keycloak/overrides.lock.json');
  for(const [label,version,sha] of [['vulnerable',guava.upstreamVersion,guava.upstreamSha256],['fixed',guava.version,guava.sha256]]) {
    const dir=resolve(output,'control-'+label);fs.mkdirSync(dir,{recursive:true});
    const r=await fetch('https://repo.maven.apache.org/maven2/com/google/guava/guava/'+version+'/guava-'+version+'.jar');
    if(!r.ok)throw Error('Control download failed');
    const jar=resolve(dir,'guava.jar');fs.writeFileSync(jar,Buffer.from(await r.arrayBuffer()));
    if(hash(jar)!==sha)throw Error('Control checksum mismatch');
    const sbom=resolve(dir,'inventory.json'),report=resolve(dir,'grype.json');
    run(bins.syft,['dir:'+dir,'-o','syft-json='+sbom]);run(bins.grype,['sbom:'+sbom,'-o','json'],report);
    const found=read(report).matches.some(m=>[m.vulnerability,...(m.relatedVulnerabilities??[])].some(v=>['CVE-2026-102554','GHSA-xxph-c9ww-hj94'].includes(v.id)));
    controls.push({label,version,found});
  }
  if(!controls[0].found||controls[1].found)throw Error('Vulnerable/fixed advisory controls failed');
  write(resolve(prepared,'database.json'),{status,sha256:dbHash,archiveSha256:hash(resolve(prepared,'database.tar.gz')),controls});
  console.log('One validated database snapshot and positive/negative controls are frozen.');
}
async function setup() {
  fs.mkdirSync(output,{recursive:true});const bins=await tools();
  const db=read(resolve(prepared,'database.json'));
  if(hash(resolve(prepared,'database.tar.gz'))!==db.archiveSha256)throw Error('Database archive drift');
  fs.mkdirSync(process.env.GRYPE_DB_CACHE_DIR,{recursive:true});
  run('tar',['-xzf',resolve(prepared,'database.tar.gz'),'-C',process.env.GRYPE_DB_CACHE_DIR]);
  run(bins.grype,['db','status','-o','json'],resolve(output,'database-status.json'));
  if(databaseHash()!==db.sha256)throw Error('Database snapshot differs');
  const original=read('images.lock.json');write(resolve(output,'production-images.lock.json'),original);
  write('images.lock.json',{...original,runtime:lock.candidate.reference});
  run('skopeo',['inspect','--config','--override-os','linux','--override-arch',arch,'docker://'+candidateByDigest],resolve(output,'base-config.json'));
  const fixtures=read('docs/security/evidence/emudhra-core.json').fixtures;
  const dir=resolve(output,'certificates');fs.mkdirSync(resolve(dir,'chains'),{recursive:true});
  for(const chain of fixtures.chains) {
    const p=resolve(dir,'chains',chain.name);fs.writeFileSync(p,chain.pem);
    if(hash(p)!==chain.sha256)throw Error('Certificate fixture drift');
  }
  fs.writeFileSync(resolve(dir,'restored-roots.crt'),fixtures.restoredRoots.map(r=>r.pem).join('\n'));
  fs.writeFileSync(resolve(dir,'positive.crt'),fixtures.positive.pem);
  if(hash(resolve(dir,'positive.crt'))!==fixtures.positive.sha256)throw Error('Positive certificate fixture drift');
  write(resolve(dir,'fixtures.json'),fixtures);
  const classes=resolve(output,'classes');fs.mkdirSync(classes,{recursive:true});
  run('podman',['run','--rm','--network=none','--user','0','-v',directory+':/source:ro','-v',classes+':/classes:rw','--entrypoint','/opt/java/openjdk/bin/javac',original.builder,'--release','25','-d','/classes','/source/CertificateChains.java','/source/JavaRuntimeInfo.java']);
  write(resolve(output,'setup.json'),{branch:process.env.GITHUB_REF_NAME,commit:process.env.GITHUB_SHA,runId:Number(process.env.GITHUB_RUN_ID),architecture:arch,databaseSha256:db.sha256,tools:lock});
}
export function summarize(report,inventory,kind) {
  const errors=[],rpm=kind==='rhhi',osType=rpm?'rpm':'deb';
  const expected=rpm?/hummingbird/i:/debian/i;
  if(!expected.test(inventory.distro?.id??'')||!expected.test(report.distro?.name??''))errors.push('OS coverage not recognized');
  if(report.descriptor?.name!=='grype'||report.descriptor.version!==lock.grype.version||report.descriptor.db?.status?.valid!==true)errors.push('Scanner/database identity invalid');
  if(!Array.isArray(report.matches)||!Array.isArray(inventory.artifacts))throw Error('Missing scan/inventory');
  const os=inventory.artifacts.filter(p=>p.type===osType),jars=inventory.artifacts.filter(p=>p.type==='java-archive');
  const app=jars.filter(p=>p.locations?.some(l=>(l.path??l.accessPath??'').includes('/opt/keycloak/')));
  if(!os.length||!app.length)errors.push('Missing OS/application inventory');
  if(!app.some(p=>/guava/i.test(p.name)&&p.version==='33.7.2-jre'))errors.push('Fixed Guava absent');
  if(!app.some(p=>p.name==='opentelemetry-api'&&p.version==='1.67.0'))errors.push('Fixed OpenTelemetry absent');
  const levels=['CRITICAL','HIGH','MEDIUM','LOW','NEGLIGIBLE','UNKNOWN'];
  const counts=Object.fromEntries(levels.map(s=>[s,{total:0,fixable:0}]));
  const matches=report.matches.map(m=>{const v=m.vulnerability;let severity=String(v.severity??'UNKNOWN').toUpperCase();if(!levels.includes(severity))severity='UNKNOWN';
    const fixes=v.fix?.versions??[];counts[severity].total++;if(fixes.length)counts[severity].fixable++;
    return{id:v.id,related:(m.relatedVulnerabilities??[]).map(v=>v.id),severity,package:m.artifact.name,version:m.artifact.version,type:m.artifact.type,fixes,fixState:v.fix?.state,namespace:v.namespace,url:v.dataSource,matchTypes:m.matchDetails?.map(d=>d.type)??[]};});
  const cves=[...new Set(matches.flatMap(m=>[m.id,...m.related]).filter(id=>/^CVE-/.test(id)))].sort();
  return{status:errors.length?'coverage-failed':'complete',errors,distro:report.distro,counts,total:matches.length,uniqueAdvisories:new Set(matches.map(m=>m.id)).size,uniqueCVEs:cves.length,cves,
    blocking:counts.HIGH.fixable+counts.CRITICAL.fixable,namespaces:[...new Set(matches.map(m=>m.namespace))].sort(),
    inventory:{os:os.length,jars:jars.length,applicationJars:app.length,jvm:inventory.artifacts.filter(p=>p.type==='java-jvm'||(p.type===osType&&/openjdk|jre|temurin/i.test(p.name))).map(p=>({name:p.name,version:p.version,type:p.type,purl:p.purl,cpes:p.cpes})),
      utilLinux:os.filter(p=>/uuid|mount|util-linux|nsenter/i.test(p.name)).map(p=>({name:p.name,version:p.version,type:p.type}))},
    applicationPackages:app.map(p=>({name:p.name,version:p.version,purl:p.purl})).sort((a,b)=>JSON.stringify(a).localeCompare(JSON.stringify(b))),matches};
}
async function scan() {
  const bins={syft:resolve('.cache/rhhi-tools/syft'),grype:resolve('.cache/rhhi-tools/grype')};
  const profile=process.env.BUILD_PROFILE,baseline=lock.baseline.images.find(i=>i.profile===profile),child=baseline.children.find(c=>c.architecture===arch);
  const rows=[],db=read(resolve(prepared,'database.json'));
  for(const kind of ['distroless','rhhi']) {
    const dir=resolve(output,kind);fs.mkdirSync(dir,{recursive:true});
    try {
      const archive=resolve(output,kind+'.oci.tar');
      if(kind==='distroless')run('skopeo',['copy','--preserve-digests','docker://quay.io/rambow-cloud/keycloak@'+child.digest,'oci-archive:'+archive]);
      const info=JSON.parse(run('skopeo',['inspect','oci-archive:'+archive]));
      if(info.Architecture!==arch||info.Os!=='linux'||info.Labels?.['cloud.rambow.keycloak.profile']!==profile)throw Error('Image profile/architecture mismatch');
      if(kind==='distroless'&&info.Digest!==child.digest)throw Error('Baseline digest drift');
      if(kind==='rhhi'&&info.Labels?.['org.opencontainers.image.revision']!==process.env.GITHUB_SHA)throw Error('Candidate source drift');
      const image='localhost/rhhi-evaluation:'+kind;
      const id=run('podman',['pull','--quiet','oci-archive:'+archive]).split('\n').at(-1);run('podman',['tag',id,image]);
      const probe=['run','--rm','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=512m','-v',resolve(output,'classes')+':/classes:ro','-v',resolve(output,'certificates')+':/fixtures:ro','--entrypoint','/usr/bin/java',image];
      run('podman',[...probe,'-Xmx128m','-cp','/classes','JavaRuntimeInfo'],resolve(dir,'java.json'));
      const fixture=read(resolve(output,'certificates/fixtures.json'));
      let certificateStatus='passed';
      try {run('podman',[...probe,'-Dcom.sun.security.enableAIAcaIssuers=false','-cp','/classes','CertificateChains','/fixtures',fixture.validationTime,fixture.positiveTime],resolve(dir,'certificate-regression.json'));}
      catch(error){certificateStatus='failed';write(resolve(dir,'certificate-failure.json'),{error:error.message});}
      const sbom=resolve(dir,'inventory.json'),report=resolve(dir,'grype.json');
      run(bins.syft,['oci-archive:'+archive,'-o','syft-json='+sbom]);run(bins.grype,['sbom:'+sbom,'-o','json'],report);
      const inventory=read(sbom),grype=read(report),summary=summarize(grype,inventory,kind);
      const row={kind,profile,architecture:arch,...summary,digest:info.Digest,archiveSha256:hash(archive),inventorySha256:hash(sbom),reportSha256:hash(report),databaseSha256:db.sha256,database:grype.descriptor.db,
        java:read(resolve(dir,'java.json')),certificateStatus,runtimeStatus:kind==='rhhi'?process.env.RUNTIME_RESULT:'previously-validated-r4',runtimeResultScope:kind==='rhhi'?'Current native runtime suite':'Exact published r4 bytes; prior native runtime evidence retained in main',
        targetedUtilLinux:summary.matches.filter(m=>[m.id,...m.related].some(v=>['CVE-2026-76642','CVE-2026-78408','CVE-2026-78409','CVE-2026-78410'].includes(v)))};
      write(resolve(dir,'summary.json'),row);rows.push(row);
    }catch(error){const row={kind,profile,architecture:arch,status:'failed',errors:[error.message]};rows.push(row);write(resolve(dir,'failure.json'),row);}
  }
  const issues=[];
  if(databaseHash()!==db.sha256)issues.push('Database drift during scans');
  if(rows.some(r=>r.status!=='complete'))issues.push('Incomplete scan or coverage');
  if(rows.every(r=>r.applicationPackages)&&JSON.stringify(rows[0].applicationPackages)!==JSON.stringify(rows[1].applicationPackages))issues.push('Application inventories differ');
  write(resolve(output,'comparison.json'),{schemaVersion:1,branch:process.env.GITHUB_REF_NAME,sourceCommit:process.env.GITHUB_SHA,runId:Number(process.env.GITHUB_RUN_ID),runAttempt:Number(process.env.GITHUB_RUN_ATTEMPT),profile,architecture:arch,database:db,issues,rows});
  if(issues.length||rows.some(r=>r.certificateStatus==='failed')||process.env.RUNTIME_RESULT!=='success')throw Error('Evaluation has coverage, compatibility or certificate failures; evidence retained.');
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  const command=process.argv[2];
  if(command==='prepare')await prepare();else if(command==='setup')await setup();else if(command==='scan')await scan();else throw Error('Expected prepare | setup | scan');
}
