import { hash, json, profiles, isDigest, isSha } from './releases.mjs';
import { selectTargets, fullFindings, verifyReport } from './cve-monitor.mjs';
import {gateSummary} from './trivy.mjs';
import { isRambowRuntime } from './runtime-sbom.mjs';
import { sameRuntimeFamily } from './runtime-family.mjs';

export const isAutomaticRuntime = reference => isRambowRuntime(reference) || /^gcr\.io\/distroless\/java\d+-debian13:nonroot@sha256:[a-f0-9]{64}$/.test(reference ?? '');

export function compactReport(r) {
  return {SchemaVersion:r.SchemaVersion,ArtifactType:r.ArtifactType,CreatedAt:r.CreatedAt,
    Metadata:{OS:r.Metadata?.OS,ImageID:r.Metadata?.ImageID,ImageConfig:{architecture:r.Metadata?.ImageConfig?.architecture,os:r.Metadata?.ImageConfig?.os,rootfs:r.Metadata?.ImageConfig?.rootfs}},
    ...(r.RuntimeSbom ? {RuntimeSbom:r.RuntimeSbom} : {}),
    Results:r.Results.map(t=>({Class:t.Class,Type:t.Type,Target:t.Target,Packages:t.Packages?.map(p=>({Name:p.Name,Version:p.Version,...(p.Identifier?{Identifier:p.Identifier}:{})})),
      Vulnerabilities:t.Vulnerabilities?.map(v=>({VulnerabilityID:v.VulnerabilityID,PkgName:v.PkgName,InstalledVersion:v.InstalledVersion,FixedVersion:v.FixedVersion,Severity:v.Severity}))}))};
}

export function runtimeIntent(records,lock) {
  const targets=selectTargets(records);
  const from={};
  for(const profile of profiles) {
    const target=targets.find(t=>t.profile===profile);
    const record=records.find(r=>r.plan.tag===target.release);
    const previous=record.plan.imageLock.runtime;
    if(previous===lock.runtime) continue;
    if(!sameRuntimeFamily(previous,lock.runtime)) throw Error('Runtime family change requires explicit review');
    from[profile]=previous;
  }
  const baselines=targets.filter(t=>Object.hasOwn(from,t.profile));
  if(!baselines.length) return null;
  const value={from,to:lock.runtime,baselines};
  return {id:hash(json(value)),...value};
}
export function validateRuntimeChange(runtime,selected) {
  if(!runtime || !isAutomaticRuntime(runtime.to) || !runtime.from || Object.keys(runtime.from).length!==selected.length || selected.some(p=>
    !profiles.includes(p)||!isAutomaticRuntime(runtime.from[p])||runtime.from[p]===runtime.to||!sameRuntimeFamily(runtime.from[p],runtime.to))) throw Error('Runtime updates require changed pinned distroless digests in the same reviewed family');
  return runtime;
}
export function validateRequest(request) {
  if(request.schemaVersion!==1 || !/^[a-f0-9]{64}$/.test(request.id??'') || !Number.isSafeInteger(request.issue)||request.issue<1 ||
    request.fragment!=='changes/'+request.issue+'-distroless.json' || !Array.isArray(request.baselines)||!request.baselines.length||request.baselines.length>4) throw Error('Invalid runtime request');
  validateRuntimeChange(request,Object.keys(request.from??{}));
  if(request.id!==hash(json({from:request.from,to:request.to,baselines:request.baselines}))) throw Error('Runtime request hash mismatch');
  const keys=new Set();
  for(const t of request.baselines) {
    const key=t.profile+'/'+t.architecture;
    if(!Object.hasOwn(request.from,t.profile)||!['amd64','arm64'].includes(t.architecture)||!isDigest(t.digest)||!isDigest(t.indexDigest)||!isSha(t.sourceCommit)||
       !/^v\d+\.\d+\.\d+-r[1-9]\d*$/.test(t.release)||t.tag!==t.release.slice(1)+'-'+t.profile||t.reference!=='quay.io/rambow-cloud/keycloak@'+t.digest||keys.has(key)) throw Error('Invalid runtime baseline');
    keys.add(key);
  }
  for(const profile of Object.keys(request.from)) for(const arch of ['amd64','arm64']) if(!keys.has(profile+'/'+arch)) throw Error('Native amd64/arm64 baselines required');
  return request;
}
export function compareReports(before,after,target,context,policy,candidateRuntime=target.runtime) {
  const a=verifyReport(before,target,context,policy),b=verifyReport(after,{...target,runtime:candidateRuntime},context,policy);
  const ids=rows=>[...new Set(rows.map(r=>r.id).filter(id=>/^CVE-\d{4}-\d{4,}$/.test(id)))].sort();
  const old=ids(a.findings),next=ids(b.findings);
  return {resolved:old.filter(id=>!next.includes(id)),introduced:next.filter(id=>!old.includes(id)),remaining:next.filter(id=>old.includes(id)),
    beforeTotal:a.summary.total,afterTotal:b.summary.total,beforeCounts:a.summary.counts,afterCounts:b.summary.counts};
}
export function aggregatePairs(request,pairs,context,policy) {
  validateRequest(request);
  if(pairs.length!==request.baselines.length) throw Error('Incomplete runtime comparison matrix');
  return Object.keys(request.from).map(profile=>{
    const selected=[];
    for(const target of request.baselines.filter(t=>t.profile===profile)) {
      const matches=pairs.filter(p=>p.profile===profile&&p.architecture===target.architecture);
      if(matches.length!==1) throw Error('Missing or duplicate comparison architecture');
      const p=matches[0];
      if(p.schemaVersion!==1||p.requestId!==request.id||p.sourceCommit!==context.monitorCommit||p.runId!==context.runId||p.runAttempt!==context.runAttempt||
         json(p.target)!==json(target)||!isDigest(p.candidateDigest)||!isDigest(p.candidateConfig)||p.after.Metadata?.ImageID!==p.candidateConfig||
         !isDigest(p.baselineConfig)||p.before.Metadata?.ImageID!==p.baselineConfig||p.scannerVersion!==policy.version||
         p.scannerSha256!==(target.architecture==='arm64'?policy.linuxArm64Sha256:policy.linuxAmd64Sha256)||
         !/^[a-f0-9]{64}$/.test(p.database?.vulnerability??'')||!/^[a-f0-9]{64}$/.test(p.database?.java??'')||json(p.database)!==json(p.databaseAfter)) throw Error('Runtime comparison provenance/database mismatch');
      gateSummary(verifyReport(p.after,{...target,runtime:request.to},context,policy).summary);
      selected.push({...p,delta:compareReports(p.before,p.after,target,context,policy,request.to)});
    }
    const afterIds=new Set(selected.flatMap(p=>fullFindings(p.after).map(f=>f.id)));
    const resolved=[...new Set(selected.flatMap(p=>p.delta.resolved))].filter(id=>!afterIds.has(id)).sort();
    return {profile,resolved,introduced:[...new Set(selected.flatMap(p=>p.delta.introduced))].sort(),
      children:selected.map(p=>({architecture:p.architecture,digest:p.candidateDigest})),pairs:selected};
  });
}
