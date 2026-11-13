const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const lib = import('../scripts/ecr-public.mjs');
const releases = import('../scripts/lib/releases.mjs');
const source = JSON.parse(readFileSync('releases/records/v26.8.2-r4.json','utf8'));
const config = { ...JSON.parse(readFileSync('config/ecr-public.json','utf8')), enabled: true };
const context = { repo: {owner:'rambow-cloud',repo:'keycloak'}, eventName:'workflow_dispatch',ref:'refs/heads/main',
  sha: 'a'.repeat(40), runId: 123, payload: {} };
const workflow = 'rambow-cloud/keycloak/.github/workflows/ecr-public.yml@refs/heads/main';
function setup() { process.env.GITHUB_WORKFLOW_REF = workflow; process.env.GITHUB_RUN_ATTEMPT = '1'; process.env.MIRROR_TOOLS_COMMIT = context.sha; }
async function fixture() {
  setup();
  const {completionAsset} = await import('../scripts/quay-release.mjs');
  const {json} = await releases;
  const assets = new Map(Object.entries({'publication-plan.json':source.plan,'publication-record.json':source,
    'publication-complete.json':completionAsset(source),'supply-chain-verification.json':source.supplyChain}));
  let draft = false, withdrawn = false, sourceSha = source.plan.sourceCommit;
  const release = {id:source.plan.releaseId,tag_name:source.plan.tag};
  const github = {rest:{git:{getTree:async()=>({data:{tree:[{path:'releases/records/'+source.plan.tag+'.json',type:'blob'}]}})},repos:{
    getReleaseByTag:async()=>({data:{...release,draft,prerelease:false}}),
    getContent:async()=>({data:{encoding:'base64',size:json(source).length,content:Buffer.from(json(source)).toString('base64')}}),
    getCommit:async()=>({data:{sha:sourceSha}}),compareCommits:async()=>({data:{merge_base_commit:{sha:withdrawn?context.sha:source.plan.sourceCommit}}}),
    listReleaseAssets:async()=>{},getReleaseAsset:async({asset_id})=>({data:json(assets.get(asset_id))}),
    uploadReleaseAsset:async({name,data})=>{assets.set(name,JSON.parse(data.toString()));},
  }},paginate:async()=>[...assets].map(([name,value])=>({name,id:name,size:json(value).length}))};
  return {github,context,core:{info:()=>{}},tag:source.plan.tag,config,assets,
    draft:()=>{draft=true;},move:()=>{sourceSha=context.sha;},outsideMain:()=>{withdrawn=true;}};
}
async function recordFixture() {
  const {mirrorPlan} = await lib;
  const {hash,json} = await releases;
  const plan = mirrorPlan(source,config);
  const id = {runId:123,attempt:1,headSha:context.sha,planSha256:hash(json(plan))};
  return {schemaVersion:1,status:'published',publishedAt:'2026-11-13T00:00:00.000Z',plan,
    publication:{schemaVersion:1,...id,status:'published',images:plan.images,sourceVerification:source.supplyChain},
    nativePulls:['amd64','arm64'].map(architecture=>({schemaVersion:1,...id,status:'verified',architecture,
      images:plan.images.map(i=>({profile:i.profile,digest:i.digest,childDigest:i.children.find(c=>c.architecture===architecture).digest,configDigest:'sha256:'+'c'.repeat(64)}))}))};
}
test('trust excludes PRs, arbitrary branches/callers, renamed repositories and wrong audience/subject',async()=>{
  setup(); const {assertContext,validateConfig,validateToken} = await lib;
  assertContext(context,workflow);
  assert.throws(()=>assertContext({...context,eventName:'pull_request'},workflow));
  assert.throws(()=>assertContext({...context,ref:'refs/heads/feature'},workflow));
  assert.throws(()=>assertContext(context,workflow.replace('ecr-public.yml','untrusted.yml')));
  assert.throws(()=>assertContext({...context,repo:{owner:'other',repo:'keycloak'}},workflow));
  assert.throws(()=>validateConfig({...config,audience:'https://quay.io'}));
  assert.throws(()=>validateConfig({...config,subject:'repo:rambow-cloud/keycloak:environment:ecr-public-release'}));
  const claims = {iss:'https://token.actions.githubusercontent.com',aud:config.audience,sub:config.subject,repository_id:'1433566126',
    repository_owner_id:'333554680',ref:context.ref,event_name:context.eventName,workflow_ref:workflow,exp:Date.now()/1000+120};
  const token = c => 'header.'+Buffer.from(JSON.stringify(c)).toString('base64url')+'.signature';
  validateToken(token(claims),config,context);
  for(const patch of [{aud:'other'},{sub:'other'},{repository_id:'0'},{ref:'refs/pull/1/merge'},{exp:0}]) assert.throws(()=>validateToken(token({...claims,...patch}),config,context));
});
test('freeze binds nonempty source history and exact target; conflicts fail instead of rebuilding',async()=>{
  const {prepareMirror} = await lib;
  const f = await fixture(); const p = await prepareMirror(f);
  assert.equal(p.active,true); assert.equal(f.assets.get('ecr-public-mirror-plan.json').images.length,2);
  assert.equal((await prepareMirror(f)).active,true); // Same frozen inputs can recover a partial upload.
  for(const image of p.plan.images) assert.ok(image.changes.length);
  const changed = structuredClone(f.assets.get('ecr-public-mirror-plan.json')); changed.sourceCommit=context.sha;
  f.assets.set('ecr-public-mirror-plan.json',changed);
  await assert.rejects(prepareMirror(f),/already frozen/);
});
test('source draft, moved tag, non-main ancestry and disagreeing completion fail before AWS access',async()=>{
  const {prepareMirror} = await lib;
  for(const mutate of [f=>f.draft(),f=>f.move(),f=>f.outsideMain(),f=>f.assets.set('publication-complete.json',{})]) {
    const f = await fixture(); mutate(f); await assert.rejects(prepareMirror(f));
    assert.equal(f.assets.has('ecr-public-mirror-plan.json'),false);
  }
});
test('immutable record requires both native pulls, same attempt, exact children and complete source signatures',async()=>{
  const {validateMirrorRecord} = await lib;
  const r = await recordFixture(); validateMirrorRecord(r,r.plan);
  for(const mutate of [r=>r.nativePulls.pop(),r=>r.nativePulls[0].attempt++,r=>r.nativePulls[0].images[0].childDigest='sha256:'+'0'.repeat(64),
    r=>r.publication.sourceVerification.targets.pop(),r=>r.publication.images.pop()]) {
    const bad = structuredClone(r); mutate(bad); assert.throws(()=>validateMirrorRecord(bad,r.plan));
  }
});
test('record-only recovery repairs completion and complete retry does not request publication',async()=>{
  const {prepareMirror} = await lib; const f = await fixture(); const r = await recordFixture();
  f.assets.set('ecr-public-mirror-record.json',r);
  const recovered = await prepareMirror(f); assert.equal(recovered.active,false); assert.equal(recovered.complete,true);
  assert.ok(f.assets.has('ecr-public-mirror-complete.json'));
  assert.deepEqual(await prepareMirror(f),recovered);
  f.assets.set('ecr-public-mirror-complete.json',{}); await assert.rejects(prepareMirror(f),/completion conflicts/);
});
test('only explicit missing tags permit copy, equal tags reuse, conflicts and service errors fail',async()=>{
  const {describeDestination,inspectIndex} = await lib; const {hash} = await releases;
  const expected='sha256:'+'a'.repeat(64);
  assert.equal(describeDestination({status:1,stderr:'An error occurred (ImageNotFoundException)'},expected),'copy');
  assert.equal(describeDestination({status:0,stdout:JSON.stringify({imageDetails:[{imageDigest:expected}]})},expected),'reuse');
  assert.throws(()=>describeDestination({status:1,stderr:'AccessDeniedException'},expected));
  assert.throws(()=>describeDestination({status:0,stdout:JSON.stringify({imageDetails:[{imageDigest:'sha256:'+'b'.repeat(64)}]})},expected),/different digest/);
  const children=source.plan.images[0].children;
  const raw=JSON.stringify({schemaVersion:2,manifests:children.map(c=>({digest:c.digest,platform:{os:'linux',architecture:c.architecture}}))});
  inspectIndex(raw,{digest:'sha256:'+hash(raw),children});
  assert.throws(()=>inspectIndex(raw,{digest:expected,children}),/digest changed/);
  assert.throws(()=>inspectIndex(raw,{digest:'sha256:'+hash(raw),children:[children[0]]}),/architecture set/);
});
test('IAM grants and workflow boundaries exclude deletes, static keys and image rebuilds',async()=>{
  const policy=JSON.parse(readFileSync('infra/ecr-public/push-policy.json','utf8'));
  const scoped=policy.Statement.find(s=>Array.isArray(s.Action));
  assert.equal(scoped.Resource,config.repositoryArn);
  assert.equal(scoped.Action.length,6); assert.ok(scoped.Action.includes('ecr-public:PutImage'));
  assert.deepEqual(policy.Statement.find(s=>s.Action==='sts:GetServiceBearerToken').Condition,
    {StringEqualsIfExists:{'sts:AWSServiceName':'ecr-public.amazonaws.com'}});
  assert.deepEqual(policy.Statement.filter(s=>!Array.isArray(s.Action)).map(s=>s.Action).sort(),
    ['ecr-public:GetAuthorizationToken','sts:GetServiceBearerToken']);
  assert.doesNotMatch(JSON.stringify(policy),/Delete|CreateRepository|iam:|Action":"\*"/);
  const stack=JSON.parse(readFileSync('infra/ecr-public/iam-stack.json','utf8'));
  assert.deepEqual(stack.Resources.PublisherRole.Properties.Policies[0].PolicyDocument,policy);
  const executor=JSON.parse(readFileSync('infra/ecr-public/stack-executor-policy.json','utf8'));
  assert.deepEqual(executor.Statement.map(s=>s.Resource),[config.roleArn,'arn:aws:iam::060065238923:oidc-provider/token.actions.githubusercontent.com']);
  assert.ok(executor.Statement.every(s=>s.Action.every(a=>a.startsWith('iam:')&&!a.includes('*'))));
  assert.doesNotMatch(JSON.stringify(executor),/PassRole|AttachRolePolicy|CreateAccessKey/);
  const trust=stack.Resources.PublisherRole.Properties.AssumeRolePolicyDocument.Statement[0];
  assert.equal(trust.Condition.StringEquals['token.actions.githubusercontent.com:sub'],config.subject);
  const workflowText=readFileSync('.github/workflows/ecr-public.yml','utf8');
  const pub=workflowText.slice(workflowText.indexOf('\n  publish:'),workflowText.indexOf('\n  pull:'));
  assert.equal((workflowText.match(/id-token: write/g)||[]).length,1);
  assert.match(pub,/environment: ecr-public-release/); assert.match(pub,/id-token: write/);
  assert.doesNotMatch(workflowText,/secrets\.|build\.sh|GITHUB_ENV|pull_request:/);
  const {sourceProfiles,validationProfiles}=await import('../scripts/lib/image-changes.mjs');
  for(const path of ['config/ecr-public.json','scripts/ecr-public.mjs','infra/ecr-public/iam-stack.json','.github/workflows/ecr-public.yml']) {
    assert.deepEqual(sourceProfiles(path),[]);assert.deepEqual(validationProfiles(path),[]);
  }
});

test('AWS diagnostics expose only known operation/error/denial facts and never arbitrary output',async()=>{
  const {commandFailure}=await lib;
  const secret='FAKE_PRIVATE_AUTHORIZATION_VALUE';
  const error={status:254,stdout:secret,stderr:'An error occurred (AccessDeniedException) when calling the GetAuthorizationToken operation: User is not authorized to perform: sts:GetServiceBearerToken because no identity-based policy allows it. '+secret};
  const message=commandFailure('aws',error);
  assert.match(message,/AccessDeniedException; GetAuthorizationToken; denied sts:GetServiceBearerToken; identity-policy/);
  assert.doesNotMatch(message,new RegExp(secret));
  assert.match(commandFailure('aws',{...error,stderr:error.stderr.replace('no identity-based policy allows it','an explicit deny in a service control policy')}),/service-control-policy/);
  assert.equal(commandFailure('aws',{...error,stderr:secret}),'aws failed (exit 254)');
  assert.equal(commandFailure('aws',{...error,stderr:'An error occurred ('+secret+') when calling the GetAuthorizationToken operation'}),'aws failed (exit 254)');
  assert.equal(commandFailure('aws',{...error,stderr:'An error occurred (AccessDeniedException) when calling the '+secret+' operation'}),'aws failed (exit 254)');
  assert.equal(commandFailure('skopeo',error),'skopeo failed (exit 254)');
});
