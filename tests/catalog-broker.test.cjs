'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const broker=import('../scripts/catalog-broker.mjs');
const clone=value=>JSON.parse(JSON.stringify(value));
async function fixture() {
 const record=JSON.parse(readFileSync('releases/records/v26.8.2-r3.json','utf8'));
 const {completionAsset}=await import('../scripts/quay-release.mjs');
 const assets={'publication-record.json':record,'publication-plan.json':record.plan,'supply-chain-verification.json':record.supplyChain};
 const state={record,assets,release:{id:record.plan.releaseId,tag_name:record.plan.tag,draft:false,prerelease:false},
  metadata:{full_name:'rambow-cloud/keycloak',default_branch:'main'},
  run:{id:record.publishRunId,path:'.github/workflows/release.yml',event:'release',head_branch:record.plan.tag,
   head_sha:record.plan.sourceCommit,repository:{full_name:'rambow-cloud/keycloak'},head_repository:{full_name:'rambow-cloud/keycloak'}},
  jobs:[{name:'publish',conclusion:'success'},{name:'audit',conclusion:'success'}],dispatches:[],ancestor:true,tagCommit:record.plan.sourceCommit};
 const github={rest:{repos:{get:async()=>({data:state.metadata}),getReleaseByTag:async()=>({data:state.release}),
  getCommit:async()=>({data:{sha:state.tagCommit}}),compareCommits:async({base})=>({data:{merge_base_commit:{sha:state.ancestor?base:'0'.repeat(40)}}}),
  getContent:async()=>({data:{encoding:'base64',size:1000,content:Buffer.from(JSON.stringify(state.record)).toString('base64')}}),
  listReleaseAssets(){},getReleaseAsset:async({asset_id})=>({data:Buffer.from(JSON.stringify(state.assets[asset_id]))})},
  actions:{getWorkflowRun:async()=>({data:state.run}),listJobsForWorkflowRun(){},createWorkflowDispatch:async args=>state.dispatches.push(args)}},
  paginate:async method=>method===github.rest.repos.listReleaseAssets?Object.keys(state.assets).map(name=>({name,id:name,size:1000})):state.jobs};
 const context={repo:{owner:'rambow-cloud',repo:'keycloak'},ref:'refs/heads/main',eventName:'workflow_dispatch'};
 return {github,context,tag:record.plan.tag,state,record,core:{info(){}},pause:async()=>{},maxPolls:2,
  finish:()=>state.assets['publication-complete.json']=completionAsset(state.record)};
}

test('catalog broker validates protected publication before exposing App work and skips completed records',async()=>{
 const {prepareCatalog}=await broker,f=await fixture();
 assert.deepEqual(await prepareCatalog(f),{complete:false,record:f.record});
 f.finish(); assert.deepEqual(await prepareCatalog(f),{complete:true,tag:f.tag}); assert.equal(f.state.dispatches.length,0);
 f.state.jobs.push({name:'publish',conclusion:'skipped',run_attempt:2},{name:'audit',conclusion:'skipped',run_attempt:2});
 assert.deepEqual(await prepareCatalog(f),{complete:true,tag:f.tag});
 f.state.jobs=[{name:'publish',conclusion:'success',run_attempt:1},{name:'audit',conclusion:'success',run_attempt:2}];
 await assert.rejects(prepareCatalog(f),/same attempt/);
});

test('catalog broker rejects changed context, Release, source, frozen evidence and protected job failures',async()=>{
 const {prepareCatalog}=await broker;
 const mutations=[f=>f.context.ref='refs/tags/'+f.tag,f=>f.context.eventName='pull_request',f=>f.state.metadata.full_name='fork/keycloak',
  f=>f.state.release.draft=true,f=>f.state.release.prerelease=true,f=>f.state.release.id++,
  f=>f.state.ancestor=false,f=>f.state.tagCommit='0'.repeat(40),
  f=>f.state.assets['publication-plan.json']={...f.record.plan,sourceCommit:'0'.repeat(40)},
  f=>f.state.assets['supply-chain-verification.json']={...f.record.supplyChain,status:'partial'},
  f=>f.state.run.path='.github/workflows/other.yml',f=>f.state.run.head_repository.full_name='fork/keycloak',
  f=>f.state.run.head_sha='0'.repeat(40),f=>f.state.jobs[0].conclusion='failure',f=>f.state.jobs.pop(),
  f=>f.state.jobs.push({...f.state.jobs[0]})];
 for(const mutate of mutations) {const f=await fixture(); mutate(f); await assert.rejects(prepareCatalog(f)); assert.equal(f.state.dispatches.length,0);}
 const f=await fixture(); f.finish(); f.state.record=clone(f.record); f.state.record.publishedAt='2026-11-11T00:00:00.000Z';
 await assert.rejects(prepareCatalog(f),/completion/);
});

test('catalog publisher dispatches main once and waits for exact Git and immutable completion',async()=>{
 const {requestCatalog}=await broker,f=await fixture(); f.pause=async()=>f.finish();
 assert.deepEqual(await requestCatalog(f),{complete:true,tag:f.tag});
 assert.equal(f.state.dispatches.length,1);
 assert.deepEqual(f.state.dispatches[0].inputs,{release_tag:f.tag}); assert.equal(f.state.dispatches[0].ref,'main');
 const absent=await fixture(); await assert.rejects(requestCatalog(absent),/did not complete/); assert.equal(absent.state.dispatches.length,1);
 const mismatch=await fixture(); mismatch.finish(); mismatch.state.record=clone(mismatch.record); mismatch.state.record.publishedAt='2026-11-11T00:00:00.000Z';
 await assert.rejects(requestCatalog(mismatch),/differs/);
});

test('only pinned App catalog CI uses native pull_request evidence, with exact source and repository',async()=>{
 const {selectCatalogCI}=await import('../scripts/release-catalog.mjs');
 const {updaterApp}=await import('../scripts/lib/upstream.mjs');
 const pr={number:1,user:updaterApp.bot,head:{sha:'a'.repeat(40),ref:'chore/1-record-release-v26.8.2-r3'}};
 const run={id:1,event:'pull_request',path:'.github/workflows/ci.yml',head_sha:pr.head.sha,head_branch:pr.head.ref,
  repository:{full_name:'rambow-cloud/keycloak'},head_repository:{full_name:'rambow-cloud/keycloak'}};
 assert.equal(selectCatalogCI([run],pr),run);
 assert.equal(selectCatalogCI([run],{...pr,user:{...updaterApp.bot,id:0}}),undefined);
 assert.equal(selectCatalogCI([{...run,head_sha:'b'.repeat(40)}],pr),undefined);
 assert.equal(selectCatalogCI([{...run,head_repository:{full_name:'fork/keycloak'}}],pr),undefined);
 const {sourceProfiles,validationProfiles}=await import('../scripts/lib/image-changes.mjs');
 for(const path of ['scripts/catalog-broker.mjs','.github/workflows/release-catalog.yml','scripts/release-catalog.mjs']) {
  assert.deepEqual(sourceProfiles(path),[]); assert.deepEqual(validationProfiles(path),[]);
 }
});
