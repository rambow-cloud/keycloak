import { resolveImageDigest } from './lib/oci.mjs';
import { readCatalog,readText } from './quay-release.mjs';
import { runtimeIntent,validateRequest } from './lib/runtime-update.mjs';
import { json,hash } from './lib/releases.mjs';
import { updaterApp,sameUpdater,inspectCompatibility,autoMergeEligible } from './lib/upstream.mjs';
import { configureAutoMerge } from './upstream-update.mjs';
import policy from './issue-policy.cjs';

export async function runRuntimeUpdate({github,context,core,identity,dryRun=false,resolve=resolveImageDigest,inspect=inspectCompatibility}) {
  const repo=context.repo;
  const {data:metadata}=await github.rest.repos.get(repo);
  if(metadata.full_name!=='rambow-cloud/keycloak'||context.ref!=='refs/heads/'+metadata.default_branch||!dryRun&&!sameUpdater(identity,updaterApp.bot)) throw Error('Runtime updater requires trusted main and the pinned App');
  const {data:ref}=await github.rest.git.getRef({...repo,ref:'heads/'+metadata.default_branch});
  const sha=ref.object.sha;
  const text=await readText(github,repo,'images.lock.json',sha),lock=JSON.parse(text);
  const next={...lock,runtime:await resolve(lock.runtime.split('@')[0],fetch,['amd64','arm64'])};
  const records=await readCatalog(github,repo,sha),intent=runtimeIntent(records,next);
  if(!intent) return {changed:false};
  const config=JSON.parse(await readText(github,repo,'config/runtime-update.json',sha));
  if(config.request?.id===intent.id&&lock.runtime===next.runtime) return {changed:false,status:'awaiting-publication',request:intent.id};
  if(dryRun) return {changed:true,dryRun:true,intent};
  const pulls=await github.paginate(github.rest.pulls.list,{...repo,state:'open',base:metadata.default_branch,per_page:100});
  const pending=pulls.filter(p=>p.head.repo?.full_name===metadata.full_name&&/^fix\/\d+-distroless-[a-f0-9]{16}$/.test(p.head.ref));
  if(pending.length) return {changed:true,status:'existing-candidate-preserved',pullRequest:pending[0].html_url};
  const issues=await github.paginate(github.rest.issues.listForRepo,{...repo,state:'all',creator:identity.login,labels:'maintenance',per_page:100});
  const marker='<!-- rambow-runtime-update:'+intent.id+' -->';
  const matches=issues.filter(i=>!i.pull_request&&sameUpdater(i.user,identity)&&i.body?.includes(marker));
  if(matches.length>1) throw Error('Duplicate runtime update Issues');
  let issue=matches[0];
  if(issue) return {changed:false,status:'existing-attempt-preserved',issue:issue.number};
  ({data:issue}=await github.rest.issues.create({...repo,labels:['maintenance'],title:'[Maintenance]: Refresh published distroless runtime and compare CVEs',body:marker+
    '\n### Maintenance goal\nPublish the updated reviewed distroless runtime digest and measure the actual final-image CVE delta.\n\n'+
    '### Scope\nUpdate only the runtime lock, immutable runtime change fragment and comparison request. Before runtimes: '+Object.values(intent.from).join(', ')+'. Candidate: '+intent.to+'. Profiles: '+Object.keys(intent.from).join(', ')+'.\n\n'+
    '### Security and compatibility\nThis approved same-family runtime digest update authorizes a revision even with no observed CVE repair. Builder-only changes remain maintenance. Native tests and current vulnerability gates are mandatory. Exact before/after images use the same scanner/database bytes; no unsupported override or suppression.\n\n'+
    '### Acceptance criteria\n- [ ] Validate native amd64/arm64 startup and vulnerability coverage.\n- [ ] Retain paired full reports and report resolved/introduced/remaining CVEs honestly.\n- [ ] Publish through a formal Release and preserve immutable index/child digests and change history.\n\n'+
    '### Validation plan\nRun required Issue policy and native CI. Trusted main CI completion may create the next formal Release after complete paired evidence validation. Fresh publisher scans and catalog completion remain required; Git security-history documentation uses a separate reviewed PR after publication.\n'}));
  policy.validateIssue(issue);
  const request=validateRequest({schemaVersion:1,...intent,issue:issue.number,fragment:'changes/'+issue.number+'-distroless.json'});
  const {warnings}=await inspect(lock.keycloakVersion,lock.javaVersion,JSON.parse(await readText(github,repo,'config/upstream-compatibility.json',sha)));
  const files={'images.lock.json':json(next),'config/runtime-update.json':json({schemaVersion:1,request}),
    [request.fragment]:json({schemaVersion:1,changes:[{type:'runtime-update',summary:'Refresh the reviewed distroless runtime digest and compare published versus candidate CVEs with identical scanner databases; no repair is assumed before comparison.',
      issues:[issue.number],profiles:Object.keys(intent.from),runtime:{from:intent.from,to:intent.to}}]})};
  const {data:base}=await github.rest.git.getCommit({...repo,commit_sha:sha});
  const {data:tree}=await github.rest.git.createTree({...repo,base_tree:base.tree.sha,tree:Object.entries(files).filter(([path,value])=>path!=='images.lock.json'||value!==text).map(([path,content])=>({path,content,type:'blob',mode:'100644'}))});
  const {data:commit}=await github.rest.git.createCommit({...repo,message:'chore: update distroless runtime (#'+issue.number+')',tree:tree.sha,parents:[sha]});
  const branch='fix/'+issue.number+'-distroless-'+intent.id.slice(0,16);
  await github.rest.git.createRef({...repo,ref:'refs/heads/'+branch,sha:commit.sha});
  const body=marker+'\n<!-- runtime-head:'+commit.sha+' -->\n<!-- runtime-files:'+hash(json(files))+' -->\n'+
    '## Linked issues\n\nCloses #'+issue.number+'\n\n## Problem and resulting behavior\n\nUpdate published distroless runtime inputs and compare actual CVEs. Same-family runtime digest updates authorize a new image revision even when no CVE disappears; builder-only updates do not.\n\n'+
    '## Validation\n\nRequired native CI builds each selected profile on amd64/arm64, performs runtime regressions, scans published and candidate images using the same scanner/database bytes and retains full reports.\n\n'+
    '## Security and compatibility\n\n'+(warnings.length?warnings.join(' '):'The reviewed launcher, Java LTS and runtime family remain unchanged.')+' No protection bypass, registry credential in CI, unsupported override or suppression. Formal publication still uses fresh scans.\n\n'+
    '## Checklist\n\n- [x] Compliant linked Issue and explicit runtime change history.\n- [ ] Required native CI and paired comparison checks pass.\n- [x] Human edits are never overwritten; edited candidates require review.\n';
  const {data:pr}=await github.rest.pulls.create({...repo,head:branch,base:metadata.default_branch,title:'chore: publish updated distroless runtime (#'+issue.number+')',body:body+'<!-- runtime-body:'+hash(body)+' -->\n',draft:!autoMergeEligible(lock,next,warnings)});
  await configureAutoMerge(github,repo,pr,autoMergeEligible(lock,next,warnings),message=>core.info(message));
  return {changed:true,pullRequest:pr.html_url,issue:issue.number};
}

export async function checkRuntimePullRequest({github,context,pr}) {
  try {
    if(!sameUpdater(pr.user,updaterApp.bot)) throw Error('Runtime candidate is not App-owned');
    if(pr.body.match(/<!-- runtime-body:([a-f0-9]{64}) -->\n?$/)?.[1]!==hash(pr.body.replace(/<!-- runtime-body:[a-f0-9]{64} -->\n?$/,''))) throw Error('Runtime PR body was edited');
    const head=pr.body?.match(/<!-- runtime-head:([a-f0-9]{40}) -->/)?.[1];
    if(head!==pr.head.sha) throw Error('Runtime candidate has untracked commits');
    const {data:commit}=await github.rest.repos.getCommit({...context.repo,ref:head});
    if(!sameUpdater(commit.author,updaterApp.bot)) throw Error('Runtime candidate was edited');
    const config=JSON.parse(await readText(github,context.repo,'config/runtime-update.json',head));
    const request=validateRequest(config.request);
    const paths=['images.lock.json','config/runtime-update.json',request.fragment];
    const files=Object.fromEntries(await Promise.all(paths.map(async path=>[path,await readText(github,context.repo,path,head)])));
    if(pr.body.match(/<!-- runtime-files:([a-f0-9]{64}) -->/)?.[1]!==hash(json(files))) throw Error('Runtime files changed after generation');
    const changed=await github.paginate(github.rest.pulls.listFiles,{...context.repo,pull_number:pr.number,per_page:100});
    if(changed.some(f=>!paths.includes(f.filename))) throw Error('Runtime candidate modifies unexpected paths');
    if(policy.issueNumbers(pr.body).length!==1||policy.issueNumbers(pr.body)[0]!==request.issue) throw Error('Runtime Issue mismatch');
  } catch(error) {
    await configureAutoMerge(github,context.repo,pr,false,()=>{});
    throw error;
  }
}
