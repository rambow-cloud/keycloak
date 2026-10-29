const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFile}=require('node:fs/promises');
const lib=import('../scripts/r2-architecture-migration.mjs');
const records=Promise.all(['r2','r3'].map(async r=>JSON.parse(await readFile('releases/records/v26.8.1-'+r+'.json','utf8'))));
const digest=c=>'sha256:'+c.repeat(64);
async function fixture(){
 const config=JSON.parse(await readFile('config/r2-architecture-migration.json','utf8'));
 const {hash,json}=await import('../scripts/lib/releases.mjs');
 return {schemaVersion:1,id:config.id,tag:config.tag,releaseId:config.releaseId,sourceCommit:config.sourceCommit,toolsCommit:'a'.repeat(40),sourceRun:123,sourceAttempt:1,configSha256:hash(json(config)),images:config.images.map((i,n)=>({...i,digest:digest(n?'b':'c'),archiveSha256:'d'.repeat(64),children:[{architecture:'amd64',digest:i.beforeDigest},{architecture:'arm64',digest:digest(n?'e':'f')}]}))};
}
test('only new features and explicitly identified CVE repairs qualify for a revision',async()=>{
 const {eligibleRevisionChange}=await import('../scripts/lib/release-policy.mjs');
 assert.equal(eligibleRevisionChange({type:'feature'}),true);
 assert.equal(eligibleRevisionChange({type:'fix',cves:['CVE-2099-12345']}),true);
 for(const c of [{type:'maintenance'},{type:'fix'},{type:'fix',cves:[]},{type:'fix',cves:['CVE-bad']},{type:'feature',release:false}]) assert.equal(eligibleRevisionChange(c),false);
});
test('migration plan and registry transition reject unrelated releases or changed original children',async()=>{
 const {validateMigrationPlan,migrationAction}=await lib,plan=await fixture();validateMigrationPlan(plan);
 for(const patch of [{tag:'v26.8.1-r3'},{sourceCommit:'b'.repeat(40)},{sourceAttempt:0},{images:plan.images.slice(1)},{images:plan.images.map(i=>({...i,children:[{architecture:'amd64',digest:digest('a')},i.children[1]]}))}]) assert.throws(()=>validateMigrationPlan({...plan,...patch}));
 const i=plan.images[0];assert.equal(migrationAction(i.beforeDigest,i.beforeDigest,i.digest),'expand');assert.equal(migrationAction(i.digest,i.beforeDigest,i.digest),'reuse');
 for(const value of [null,digest('d'),'unknown']) assert.throws(()=>migrationAction(value,i.beforeDigest,i.digest));
 assert.throws(()=>migrationAction(i.beforeDigest,i.beforeDigest,i.beforeDigest));
});
test('r3 withdrawal is idempotent and refuses other tags sharing a manifest or changed digests',async()=>{
 const {withdrawalTargets}=await lib,[,r3]=await records;
 const bindings=Object.fromEntries(r3.plan.images.map(i=>[i.tag,i.digest]));
 assert.deepEqual(withdrawalTargets(bindings),r3.plan.images);
 assert.deepEqual(withdrawalTargets({}),[]);
 assert.equal(withdrawalTargets({[r3.plan.images[0].tag]:r3.plan.images[0].digest}).length,1);
 assert.throws(()=>withdrawalTargets({...bindings,extra:r3.plan.images[0].digest}));
 assert.throws(()=>withdrawalTargets({...bindings,[r3.plan.images[0].tag]:digest('a')}));
});
test('lifecycle projections preserve raw records, exact old AMD64 bindings and withdrawal history',async()=>{
 const {validateReleaseEvents,parseReleaseEvents}=await import('../scripts/lib/release-events.mjs');
 const {renderCatalog,resolveTag,tagHistory}=await import('../scripts/lib/releases.mjs');
 const rows=await records, plan=await fixture(),before=JSON.stringify(rows);
 const extension={schemaVersion:1,id:'v26.8.1-r2-arm64',operation:'architecture-expansion',tag:'v26.8.1-r2',recordedAt:'2026-10-30T00:00:00.000Z',issue:70,runId:123,consumedSourceCommit:plan.toolsCommit,images:plan.images};
 const withdrawal={schemaVersion:1,id:'v26.8.1-r3-withdrawn',operation:'withdrawal',tag:'v26.8.1-r3',recordedAt:'2026-10-30T00:00:01.000Z',issue:70,runId:123,tags:rows[1].plan.images.map(i=>i.tag)};
 const events=validateReleaseEvents([extension,withdrawal],rows);Object.defineProperty(rows,'lifecycle',{value:events});
 assert.deepEqual(parseReleaseEvents(events.map(e=>JSON.stringify(e)).join('\n')+'\n'),events);
 assert.equal(resolveTag(rows,'26.8.1-r2-core').digest,plan.images[0].digest);
 assert.equal(resolveTag(rows,'26.8.1-r2-core').children[0].digest,rows[0].plan.images[0].digest);
 assert.throws(()=>resolveTag(rows,'26.8.1-r3-core'),/No recorded/);
 const md=renderCatalog(rows);assert.match(md,/Withdrawn releases/);assert.match(md,/Original amd64 manifest retained/);assert.doesNotMatch(md,/\| \[v26\.8\.1-r3\]/);
 assert.equal(tagHistory(rows,'26.8.1-r2-core')[0].operation,'architecture-expansion');assert.equal(JSON.stringify(rows),before);
 assert.throws(()=>validateReleaseEvents([{...extension,images:extension.images.map(i=>({...i,beforeDigest:digest('a')}))}],rows));
 assert.throws(()=>validateReleaseEvents([extension,extension],rows));
});
test('updater preserves published README tags and emits maintenance even for a source version bump',async()=>{
 const {candidateFiles}=await import('../scripts/lib/upstream.mjs');
 const r=(await records)[0],current={'images.lock.json':JSON.stringify(r.plan.imageLock),'README.md':'Published v26.8.1-r2-core\n','AGENTS.md':'Source Keycloak 26.8.1\n','config/java.options':'#26.8.1\n'};
 const next={...r.plan.imageLock,keycloakVersion:'26.8.2',keycloak:r.plan.imageLock.keycloak.replaceAll('26.8.1','26.8.2')};
 const files=candidateFiles(current,next,[],71);assert.equal(files['README.md'],current['README.md']);assert.equal(JSON.parse(files['changes/upstream.json']).changes[0].type,'maintenance');
});
test('only protected main dispatch may enter migration publication before any artifact or credential use',async()=>{
 const {publishMigration}=await lib;let called=false;
 for(const context of [{eventName:'pull_request',ref:'refs/pull/1/merge'},{eventName:'workflow_dispatch',ref:'refs/heads/unreviewed'}]) {
  await assert.rejects(publishMigration({context,path:'missing',out:'missing',core:{getIDToken(){called=true;}}}),/reviewed main/);
 }
 assert.equal(called,false);
});
