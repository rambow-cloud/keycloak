import {validateRecord,repository,parseRelease,equal} from './lib/releases.mjs';
import {readAsset,assertTagSource,readText,completionAsset} from './quay-release.mjs';

export async function prepareCatalog({github,context,tag}) {
  parseRelease(tag);
  const repo=context.repo;
  const {data:metadata}=await github.rest.repos.get(repo);
  if(metadata.full_name!==repository||context.eventName!=='workflow_dispatch'||context.ref!=='refs/heads/'+metadata.default_branch) {
    throw Error('Catalog broker requires a trusted main dispatch');
  }
  const {data:release}=await github.rest.repos.getReleaseByTag({...repo,tag});
  if(release.draft||release.prerelease||release.tag_name!==tag) throw Error('Catalog requires a formal stable Release');
  const record=validateRecord(await readAsset(github,repo,release,'publication-record.json'));
  if(record.plan.tag!==tag||record.plan.releaseId!==release.id||!equal(record.plan,await readAsset(github,repo,release,'publication-plan.json'))) {
    throw Error('Catalog publication identity or frozen plan mismatch');
  }
  if(record.supplyChain&&!equal(record.supplyChain,await readAsset(github,repo,release,'supply-chain-verification.json'))) {
    throw Error('Catalog signing evidence mismatch');
  }
  await assertTagSource(github,repo,tag,record.plan.sourceCommit);
  for(const source of new Set([record.plan.sourceCommit,record.plan.toolsCommit,record.validationToolsCommit])) {
    const {data:comparison}=await github.rest.repos.compareCommits({...repo,base:source,head:metadata.default_branch});
    if(comparison.merge_base_commit.sha!==source) throw Error('Catalog source/tools must belong to main history');
  }
  const {data:run}=await github.rest.actions.getWorkflowRun({...repo,run_id:record.publishRunId});
  if(run.path!=='.github/workflows/release.yml'||run.repository?.full_name!==repository||run.head_repository?.full_name!==repository||
      !(run.event==='release'&&run.head_branch===tag&&run.head_sha===record.plan.sourceCommit||
        run.event==='workflow_dispatch'&&run.head_branch===metadata.default_branch)) throw Error('Untrusted publication workflow');
  const jobs=await github.paginate(github.rest.actions.listJobsForWorkflowRun,{...repo,run_id:run.id,filter:'all',per_page:100});
  const attempts=[...new Set(jobs.map(job=>job.run_attempt??1))];
  if(!attempts.some(attempt=>['publish','audit'].every(name=>{
    const matches=jobs.filter(job=>job.name===name&&(job.run_attempt??1)===attempt);
    return matches.length===1&&matches[0].conclusion==='success';
  }))) throw Error('Successful protected publication and audit jobs from the same attempt are required');
  const complete=await readAsset(github,repo,release,'publication-complete.json');
  if(complete) {
    if(!equal(complete,completionAsset(record))||!equal(record,JSON.parse(await readText(github,repo,'releases/records/'+tag+'.json',metadata.default_branch)))) {
      throw Error('Catalog completion conflicts with immutable record or main');
    }
    return {complete:true,tag};
  }
  return {complete:false,record};
}

export async function requestCatalog({github,context,core,record,pause=ms=>new Promise(resolve=>setTimeout(resolve,ms)),maxPolls=100}) {
  validateRecord(record);
  const {data:metadata}=await github.rest.repos.get(context.repo);
  if(metadata.full_name!==repository) throw Error('Unexpected catalog repository');
  await github.rest.actions.createWorkflowDispatch({...context.repo,workflow_id:'release-catalog.yml',ref:metadata.default_branch,inputs:{release_tag:record.plan.tag}});
  for(let n=0;n<maxPolls;n++) {
    const {data:release}=await github.rest.repos.getReleaseByTag({...context.repo,tag:record.plan.tag});
    if(release.id!==record.plan.releaseId||release.draft||release.prerelease) throw Error('Release changed while awaiting catalog');
    const complete=await readAsset(github,context.repo,release,'publication-complete.json');
    if(complete) {
      if(!equal(complete,completionAsset(record))||!equal(record,JSON.parse(await readText(github,context.repo,'releases/records/'+record.plan.tag+'.json',metadata.default_branch)))) {
        throw Error('Catalog completion differs from frozen publication');
      }
      core.info('App catalog publication complete for '+record.plan.tag);
      return {complete:true,tag:record.plan.tag};
    }
    if(n<maxPolls-1) await pause(20000);
  }
  throw Error('Catalog broker did not complete; recover the frozen record without republishing images');
}
