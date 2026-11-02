import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {readText,readCatalog,readAsset,putImmutableAsset,completionAsset} from './quay-release.mjs';
import {json,hash,parseRelease,isSha,validateRecord} from './lib/releases.mjs';
import {validateRequest,runtimeIntent,aggregatePairs} from './lib/runtime-update.mjs';
import {updaterApp,sameUpdater,inspectCompatibility} from './lib/upstream.mjs';
import {parseLedger,validateRecords,ledgerImageCatalog,render,renderHistory} from '../docs/security/ledger.mjs';

const repoName='rambow-cloud/keycloak';
export function trustedRun(run,repo,workflow,main) {
  if(run.repository?.full_name!==repo||run.head_repository?.full_name!==repo||run.path!=='.github/workflows/'+workflow||
     run.status!=='completed'||run.conclusion!=='success'||!isSha(run.head_sha)||
     workflow==='ci.yml'&&(!['push','workflow_dispatch'].includes(run.event)||run.head_branch!==main)) throw Error('Expected successful trusted exact-source main CI');
  return run;
}
export function runtimeArtifacts(artifacts,request,run) {
  // Successful metadata-only CI is an intentional skip, never clean scan evidence.
  if(!artifacts.some(a=>/^(?:trivy-|keycloak-oci-)/.test(a.name))) return null;
  const selected=request.baselines.map(t=>{
    const name='trivy-'+t.profile+'-'+t.architecture+'-'+run.run_attempt;
    const matches=artifacts.filter(a=>a.name===name&&!a.expired);
    if(matches.length!==1||matches[0].size_in_bytes>30000000) throw Error('Missing or oversized paired scan artifact: '+name);
    return {name,id:matches[0].id};
  });
  for(const profile of Object.keys(request.from)) if(artifacts.filter(a=>a.name==='keycloak-oci-'+profile+'-multiarch-'+run.head_sha&&!a.expired).length!==1) throw Error('Missing exact-source multiarchitecture artifact');
  return selected;
}
export async function prepareRuntimeRelease({github,context,runId,inspect=inspectCompatibility}) {
  const repo=context.repo;
  const {data:metadata}=await github.rest.repos.get(repo);
  if(metadata.full_name!==repoName||context.ref!=='refs/heads/'+metadata.default_branch) throw Error('Runtime release tooling runs only on main');
  const {data:run}=await github.rest.actions.getWorkflowRun({...repo,run_id:runId});
  if(context.eventName==='workflow_run') {
    try {trustedRun(run,repoName,run.path==='.github/workflows/release.yml'?'release.yml':'ci.yml',metadata.default_branch);}
    catch {return {skip:true,reason:'Automated source workflow/event is not eligible for runtime publication'};}
  }
  if(run.path==='.github/workflows/release.yml') {
    trustedRun(run,repoName,'release.yml',metadata.default_branch);
    if(!/^v\d+\.\d+\.\d+-r[1-9]\d*$/.test(run.head_branch)) return {skip:true,reason:'Manual Quay recovery needs explicit formal-tag documentation review'};
    const {data:release}=await github.rest.repos.getReleaseByTag({...repo,tag:run.head_branch});
    const report=await readAsset(github,repo,release,'runtime-comparison.json');
    if(!report) return {skip:true,reason:'Not a distroless automatic Release'};
    const record=await readAsset(github,repo,release,'publication-record.json'),complete=await readAsset(github,repo,release,'publication-complete.json');
    if(!record||!complete||json(complete)!==json(completionAsset(record))) throw Error('Runtime publication is not catalog-complete');
    return {mode:'documentation',releaseId:release.id,tag:release.tag_name,runId:run.id};
  }
  trustedRun(run,repoName,'ci.yml',metadata.default_branch);
  const publishers=await github.paginate(github.rest.actions.listWorkflowRuns,{...repo,workflow_id:'release.yml',per_page:30});
  if(publishers.some(r=>r.status!=='completed')) return {skip:true,reason:'A prior formal publication is still active; recover after its catalog completes'};
  const {data:comparison}=await github.rest.repos.compareCommits({...repo,base:run.head_sha,head:metadata.default_branch});
  if(comparison.merge_base_commit.sha!==run.head_sha) throw Error('CI source is outside main history');
  let config;
  try {config=JSON.parse(await readText(github,repo,'config/runtime-update.json',run.head_sha));} catch(error) {if(error.status===404) return {skip:true,reason:'Source predates runtime requests'};throw error;}
  if(!config.request) return {skip:true,reason:'No runtime request'};
  const request=validateRequest(config.request);
  const lock=JSON.parse(await readText(github,repo,'images.lock.json',run.head_sha));
  const current=JSON.parse(await readText(github,repo,'images.lock.json',metadata.default_branch));
  const records=await readCatalog(github,repo,metadata.default_branch);
  const active=runtimeIntent(records,lock);
  if(!active||active.id!==request.id||current.runtime!==request.to) return {skip:true,reason:'Runtime is already published or candidate was superseded'};
  const {warnings}=await inspect(lock.keycloakVersion,lock.javaVersion,JSON.parse(await readText(github,repo,'config/upstream-compatibility.json',metadata.default_branch)));
  if(warnings.length) throw Error('Runtime automatic release requires reviewed compatibility: '+warnings.join(' '));
  const artifacts=await github.paginate(github.rest.actions.listWorkflowRunArtifacts,{...repo,run_id:run.id,per_page:100});
  const selected=runtimeArtifacts(artifacts,request,run);
  if(!selected) return {skip:true,reason:'Successful metadata-only CI produced no image artifacts; no comparison or publication attempted'};
  return {mode:'release',sourceCommit:run.head_sha,sourceRun:{id:run.id,attempt:run.run_attempt},request,lock,selected};
}
export async function readPairs(prepared,directory) {
  return Promise.all(prepared.selected.map(async a=>{
    const bytes=await readFile(join(directory,a.name,'runtime-pair.json'));
    if(bytes.length>2000000) throw Error('Runtime pair report exceeds limit');
    return JSON.parse(bytes);
  }));
}
export function buildRuntimeReport(prepared,pairs,policy) {
  const images=aggregatePairs(prepared.request,pairs,{monitorCommit:prepared.sourceCommit,runId:prepared.sourceRun.id,runAttempt:prepared.sourceRun.attempt},policy);
  return {schemaVersion:1,sourceCommit:prepared.sourceCommit,sourceRun:prepared.sourceRun,request:prepared.request,imageLock:prepared.lock,images,
    limits:'Point-in-time Trivy comparison with identical database bytes per native pair; disappearing CVEs are scan observations. No exploitability, complete JVM, cloud or extension certification. Full original reports remain in the source CI artifacts with retained hashes.'};
}
export function runtimeReleaseBody(report) {
  return '<!-- rambow-runtime-release:'+report.request.id+' -->\n## Distroless runtime update\n\n'+
    'Runtime: `'+report.request.to+'`. Source: `'+report.sourceCommit+'`. [Native CI and complete comparison artifacts](https://github.com/'+repoName+'/actions/runs/'+report.sourceRun.id+').\n\n'+
    report.images.map(i=>'### '+i.profile+'\n\nPrevious runtime: `'+report.request.from[i.profile]+'`. Native architectures: amd64, arm64.\n\n'+
      (i.resolved.length?'CVEs no longer detected across both candidate architectures:\n\n'+i.resolved.map(id=>'- '+id).join('\n'):'No CVE repairs were detected by the paired scans.')+
      '\n\nNewly detected CVEs: '+(i.introduced.join(', ')||'None')+'.\n').join('\n')+
    '\nThe immutable `runtime-comparison.json` attachment retains exact baseline index/child bindings, candidate child digests, package inventories, findings and scanner/database hashes. Normal fresh publication scans remain mandatory. '+report.limits+'\n';
}
export async function createRuntimeRelease({github,validationGithub=github,context,prepared,report,identity,refresh=prepareRuntimeRelease}) {
  if(!sameUpdater(identity,updaterApp.bot)) throw Error('Pinned updater App required');
  const repo=context.repo;
  const refreshed=await refresh({github:validationGithub,context,runId:prepared.sourceRun.id});
  if(refreshed.skip||refreshed.mode!=='release'||json(refreshed)!==json(prepared)) throw Error('Runtime publication baseline changed before Release creation');
  const policy=JSON.parse(await readText(github,repo,'config/trivy.json',context.sha));
  if(json(report)!==json(buildRuntimeReport(prepared,report.images.flatMap(i=>i.pairs),policy))) throw Error('Runtime report changed');
  const releases=await github.paginate(github.rest.repos.listReleases,{...repo,per_page:100});
  const marker='<!-- rambow-runtime-release:'+report.request.id+' -->';
  const existing=releases.filter(r=>r.body?.includes(marker));
  if(existing.length>1) throw Error('Duplicate runtime Releases');
  let release=existing[0];
  if(release) {
    const asset=await readAsset(github,repo,release,'runtime-comparison.json');
    if(asset&&json(asset)!==json(report)) throw Error('Existing runtime Release evidence conflicts');
    if(!release.draft) return {tag:release.tag_name,status:'existing-release-preserved'};
    if(release.target_commitish!==prepared.sourceCommit) throw Error('Existing draft source differs');
  } else {
    const records=await readCatalog(github,repo,'main');
    const numbers=[...records.map(r=>r.plan.tag),...releases.map(r=>r.tag_name)].flatMap(tag=>{
      try {const p=parseRelease(tag);return p.keycloakVersion===prepared.lock.keycloakVersion?[p.revision]:[];} catch{return [];}
    });
    const tag='v'+prepared.lock.keycloakVersion+'-r'+(Math.max(0,...numbers)+1);
    // A stray tag without a Release is a conflict, never an overwrite target.
    try {await github.rest.git.getRef({...repo,ref:'tags/'+tag});throw Error('Next runtime revision tag already exists');} catch(error) {if(error.status!==404) throw error;}
    ({data:release}=await github.rest.repos.createRelease({...repo,tag_name:tag,target_commitish:prepared.sourceCommit,name:tag,draft:true,prerelease:false,body:runtimeReleaseBody(report)}));
  }
  if(Buffer.byteLength(json(report))>2000000) throw Error('Runtime evidence attachment exceeds limit');
  await putImmutableAsset(github,repo,release,'runtime-comparison.json',report);
  await github.rest.repos.updateRelease({...repo,release_id:release.id,draft:false,prerelease:false});
  return {tag:release.tag_name,status:'formal-release-created',url:release.html_url};
}

export async function createRuntimeDocumentation({github,context,prepared,identity}) {
  if(!sameUpdater(identity,updaterApp.bot)) throw Error('Pinned updater App required');
  const repo=context.repo;
  const {data:release}=await github.rest.repos.getRelease({...repo,release_id:prepared.releaseId});
  const report=await readAsset(github,repo,release,'runtime-comparison.json'),record=validateRecord(await readAsset(github,repo,release,'publication-record.json'));
  const completed=await readAsset(github,repo,release,'publication-complete.json');
  if(!completed||json(completed)!==json(completionAsset(record))||record.plan.sourceCommit!==report.sourceCommit||record.plan.sourceRun.id!==report.sourceRun.id||record.plan.sourceRun.attempt!==report.sourceRun.attempt||record.plan.runtimeComparisonSha256!==hash(json(report))||
     report.images.some(i=>json(i.children)!==json(record.plan.images.find(p=>p.profile===i.profile)?.children))) throw Error('Publication does not match runtime comparison');
  const marker='<!-- rambow-runtime-documentation:'+release.id+' -->';
  const issues=await github.paginate(github.rest.issues.listForRepo,{...repo,state:'all',creator:identity.login,labels:'maintenance',per_page:100});
  const prior=issues.find(i=>!i.pull_request&&sameUpdater(i.user,identity)&&i.body?.includes(marker));
  if(prior) return {status:'documentation-already-tracked',issue:prior.number};
  const {data:issue}=await github.rest.issues.create({...repo,title:'[Maintenance]: Record distroless update '+release.tag_name,labels:['maintenance'],body:marker+
    '\n### Maintenance goal\nRetain completed runtime publication evidence and update the current image table.\n\n### Scope\nAdd the immutable runtime comparison report to Git. Append security repairs and concise notes only for observed resolved CVEs; preserve all historical lines.\n\n'+
    '### Security and compatibility\nPublication is complete. Match exact recorded index/children and Release evidence; no image or code changes, no false zero-CVE claim, no direct main push. This documentation PR requires normal review and is not automatically merged.\n\n'+
    '### Acceptance criteria\n- [ ] Match the immutable Release attachment and catalog.\n- [ ] Generate both security documents and update current image references.\n- [ ] Preserve prior records and distinguish no-observed-fix updates.\n\n### Validation plan\nRun required static and Issue checks, generated-document validation and append-only ledger validation. Review exact Release '+release.tag_name+' and source CI '+report.sourceRun.id+'.\n'});
  const {data:ref}=await github.rest.git.getRef({...repo,ref:'heads/main'}),sha=ref.object.sha;
  const records=await readCatalog(github,repo,sha),ledgerText=await readText(github,repo,'docs/security/records.jsonl',sha),ledger=parseLedger(ledgerText);
  const notes=JSON.parse(await readText(github,repo,'docs/security/release-notes.json',sha));
  const year=new Date().getUTCFullYear();let n=Math.max(0,...ledger.filter(r=>r.id.startsWith('SEC-'+year+'-')).map(r=>Number(r.id.split('-')[2])));
  for(const image of report.images.filter(i=>i.resolved.length)) {
    const published=record.plan.images.find(i=>i.profile===image.profile),id='SEC-'+year+'-'+String(++n).padStart(3,'0');
    ledger.push({schemaVersion:1,id,recordedAt:new Date().toISOString(),kind:'fix',status:'fixed-before-publication',advisories:image.resolved,
      summary:'Publish the distroless runtime update with verified disappearance of detected CVEs in the '+image.profile+' profile.',
      details:['Native before/after scans use identical Trivy database bytes per pair. Every listed CVE is absent on both published candidate architectures.',report.limits,
        'The comparison does not attribute application-library changes solely to distroless; exact source inputs and package inventories are retained.'],issues:[report.request.issue,issue.number],pullRequests:[],
      images:[{profile:image.profile,tag:published.tag,digest:published.digest}],references:[{label:'Formal Release and immutable paired evidence',url:release.html_url},
        {label:'Native source CI',url:'https://github.com/'+repoName+'/actions/runs/'+report.sourceRun.id}],evidence:[]});
    notes.notes.push({release:release.tag_name,record:id,fixes:image.resolved.map(advisory=>({advisory,summary:'Remove the detected vulnerability from the published '+image.profile+' image through the verified runtime-input refresh; see paired package evidence.'}))});
  }
  validateRecords(ledger,ledgerImageCatalog(records,records.lifecycle));
  const files={['releases/evidence/'+release.tag_name+'-runtime.json']:json(report)};
  if(ledger.length!==parseLedger(ledgerText).length) {
    files['docs/security/records.jsonl']=ledgerText+ledger.slice(parseLedger(ledgerText).length).map(r=>JSON.stringify(r)+'\n').join('');
    files['docs/security/release-notes.json']=json(notes);files['docs/security/README.md']=render(ledger,notes,records);files['docs/security/history.md']=renderHistory(ledger);
  }
  const targets=Object.values(Object.fromEntries(records.filter(r=>!records.lifecycle.some(e=>e.operation==='withdrawal'&&e.tag===r.plan.tag)).sort((a,b)=>Date.parse(b.publishedAt)-Date.parse(a.publishedAt)).flatMap(r=>r.plan.images.map(i=>[i.profile,{...i,release:r.plan.tag}])).reverse()));
  const section='## Current images\n\nPublished profiles are OCI indexes selecting native Linux amd64 or arm64. See [recorded digests and validation](releases/README.md).\n\n| Profile | Latest published tag | Image reference |\n| --- | --- | --- |\n'+targets.map(i=>'| '+i.profile+' | `'+i.tag+'` | `quay.io/rambow-cloud/keycloak:'+i.tag+'` |').join('\n')+
    '\n\nPull a profile with Podman:\n\n```sh\n'+targets.map(i=>'podman pull quay.io/rambow-cloud/keycloak:'+i.tag).join('\n')+'\n```\n\nRuntime digest updates publish with a [paired CVE comparison](https://github.com/'+repoName+'/releases/tag/'+release.tag_name+'). No `latest` tag is published.\n\n';
  const readme=await readText(github,repo,'README.md',sha);
  if(!/^## Current images\r?\n[\s\S]*?^## Features/m.test(readme)) throw Error('README current-image section changed; preserve human edits for review');
  files['README.md']=readme.replace(/^## Current images\r?\n[\s\S]*?(?=^## Features)/m,section);
  const {data:base}=await github.rest.git.getCommit({...repo,commit_sha:sha});
  const {data:tree}=await github.rest.git.createTree({...repo,base_tree:base.tree.sha,tree:Object.entries(files).map(([path,content])=>({path,content,type:'blob',mode:'100644'}))});
  const {data:commit}=await github.rest.git.createCommit({...repo,message:'docs: record runtime publication (#'+issue.number+')',tree:tree.sha,parents:[sha]});
  const branch='chore/'+issue.number+'-runtime-report';await github.rest.git.createRef({...repo,ref:'refs/heads/'+branch,sha:commit.sha});
  const {data:pr}=await github.rest.pulls.create({...repo,head:branch,base:'main',title:'docs: record distroless update '+release.tag_name,body:
    '## Linked issues\n\nCloses #'+issue.number+'\n\n## Problem and resulting behavior\n\nRetain completed [runtime publication]('+release.html_url+') evidence and current pull references. Observed resolved CVEs: '+report.images.map(i=>i.profile+' '+(i.resolved.join(', ')||'none')).join('; ')+'.\n\n'+
    '## Validation\n\nImmutable Release comparison, successful source CI and catalog-completion attachment match the exact published indexes/children. Required generated-document, append-only and Issue checks follow.\n\n## Security and compatibility\n\nNo image/code changes or unpublished-fix claims. Existing history remains intact. Normal review is required; no automatic merge.\n\n## Checklist\n\n- [x] Compliant Issue and immutable publication evidence.\n- [ ] Required checks and review complete.\n- [x] No credentials or Docker tooling.\n'});
  return {status:'documentation-pr-created',pullRequest:pr.html_url,issue:issue.number};
}
