import {createHash} from 'node:crypto';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=fileURLToPath(new URL('../',import.meta.url));
const modules=['api','api-incubator','common','context','exporter-common','exporter-otlp','exporter-otlp-common','sdk','sdk-common','sdk-extension-autoconfigure','sdk-extension-autoconfigure-spi','sdk-logs','sdk-metrics','sdk-trace'].map(id=>'opentelemetry-'+id);
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const version=v=>/^1\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})$/.test(v??'');
export function validateTelemetryOverride(lock,keycloakVersion) {
  const keys=['schemaVersion','keycloakVersion','upstreamVersion','version','modules'];
  if(!lock||Object.keys(lock).length!==keys.length||Object.keys(lock).some(k=>!keys.includes(k))||lock.schemaVersion!==1||
    lock.keycloakVersion!==keycloakVersion||!/^\d+\.\d+\.\d+$/.test(lock.keycloakVersion??'')||!version(lock.upstreamVersion)||!version(lock.version)||
    Number(lock.version.split('.')[1])*1000+Number(lock.version.split('.')[2])<=Number(lock.upstreamVersion.split('.')[1])*1000+Number(lock.upstreamVersion.split('.')[2])||Number(lock.version.split('.')[1])<67||!Array.isArray(lock.modules)||lock.modules.length!==modules.length) throw Error('Invalid OpenTelemetry override or Keycloak changed; review/retire the exception');
  return modules.map(id=>{
    const matches=lock.modules.filter(m=>m.artifactId===id),m=matches[0];
    if(matches.length!==1||Object.keys(m).length!==3||Object.keys(m).some(k=>!['artifactId','upstreamSha256','sha256'].includes(k))||
      !/^[a-f0-9]{64}$/.test(m.upstreamSha256??'')||!/^[a-f0-9]{64}$/.test(m.sha256??'')||m.upstreamSha256===m.sha256) throw Error('Invalid OpenTelemetry artifact identity/checksum');
    const suffix=id==='opentelemetry-api-incubator'?'-alpha':'';
    return {...m,path:'lib/lib/main/io.opentelemetry.'+id+'-'+lock.upstreamVersion+suffix+'.jar',file:id+'.jar',
      url:'https://repo.maven.apache.org/maven2/io/opentelemetry/'+id+'/'+lock.version+suffix+'/'+id+'-'+lock.version+suffix+'.jar'};
  });
}
export async function prepareTelemetryOverride(lock,keycloakVersion,output,fetcher=fetch) {
  const artifacts=validateTelemetryOverride(lock,keycloakVersion),payloads=[];
  for(const artifact of artifacts) {
    let bytes;try{bytes=await readFile(resolve(output,artifact.file));}catch(e){if(e.code!=='ENOENT')throw e;}
    if(!bytes||hash(bytes)!==artifact.sha256) {
      const response=await fetcher(artifact.url,{redirect:'error',signal:AbortSignal.timeout(60000)});
      if(!response.ok) throw Error('OpenTelemetry download failed: '+response.status);
      bytes=Buffer.from(await response.arrayBuffer());
      if(bytes.length>4194304||hash(bytes)!==artifact.sha256)throw Error('OpenTelemetry checksum/size mismatch');
    }
    payloads.push([artifact,bytes]);
  }
  await mkdir(output,{recursive:true});
  for(const [artifact,bytes]of payloads)await writeFile(resolve(output,artifact.file),bytes);
  await writeFile(resolve(output,'upstream.sha256'),artifacts.map(a=>a.upstreamSha256+'  '+a.path+'\n').join(''));
  await writeFile(resolve(output,'patched.sha256'),artifacts.map(a=>a.sha256+'  '+a.path+'\n').join(''));
  await writeFile(resolve(output,'targets.txt'),artifacts.map(a=>a.file+' '+a.path+'\n').join(''));
  await writeFile(resolve(output,'version.txt'),lock.version+'\n');
  await writeFile(resolve(output,'sdk-version.txt'),lock.version+'\n');
  console.log('Verified all '+artifacts.length+' official OpenTelemetry core artifacts at '+lock.version+'.');
}
export function verifyTelemetryScan(report) {
  const results=report.Results;
  if(!Array.isArray(results)||results.some(r=>(r.Vulnerabilities??[]).some(v=>v.VulnerabilityID==='CVE-2026-118259'))) throw Error('CVE-2026-118259 regression: finding present or scan incomplete');
  const versions=[];
  for(const id of modules) {
    const packages=results.flatMap(r=>r.Packages??[]).filter(p=>p.Name==='io.opentelemetry:'+id);
    const normalize=v=>id==='opentelemetry-api-incubator'?v?.replace(/-alpha$/,''):v;
    if(!packages.length||packages.some(p=>!version(normalize(p.Version))||Number(p.Version.split('.')[1])<67))throw Error('CVE-2026-118259 regression: fixed '+id+' metadata absent');
    versions.push(...packages.map(p=>normalize(p.Version)));
  }
  if(new Set(versions).size!==1)throw Error('OpenTelemetry core scan versions are not aligned');
}
export function requiresTelemetryRepair(prepared,profile) {
  if(!Array.isArray(prepared?.images))throw Error('Release preparation lacks image repair declarations');
  const images=prepared.images.filter(i=>i.profile===profile);
  if(images.length!==1)throw Error('Release repair profile is missing or ambiguous');
  return images[0].changes?.some(c=>c.cves?.includes('CVE-2026-118259'))??false;
}
async function main(){
  if(process.argv[2]==='verify-scan') {
    verifyTelemetryScan(JSON.parse(await readFile(process.argv[3],'utf8')));
    console.log('Verified fixed OpenTelemetry metadata and no CVE-2026-118259 finding.');return;
  }
  const lock=JSON.parse(await readFile(resolve(root,'dependencies/keycloak/opentelemetry.lock.json'),'utf8'));
  const images=JSON.parse(await readFile(resolve(root,'images.lock.json'),'utf8'));
  if(process.argv[2]==='integrity') {
    console.log(validateTelemetryOverride(lock,images.keycloakVersion).map(a=>a.sha256+' '+a.path+' '+a.artifactId).join('\n'));return;
  }
  await prepareTelemetryOverride(lock,images.keycloakVersion,resolve(root,'.cache/keycloak/otel'));
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url)await main();
