'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {readFileSync}=require('node:fs');
const model=import('../docs/experiments/operator-kind/model.mjs');
const record=JSON.parse(readFileSync('releases/records/v26.8.2-r3.json','utf8'));
const inputs=JSON.parse(readFileSync('docs/experiments/operator-kind/inputs.json','utf8'));

test('operator experiment binds both profiles to the existing native published child digests',async()=>{
 const {publishedTargets}=await model;
 for(const architecture of ['amd64','arm64']) {
  const targets=publishedTargets(record,inputs,architecture);
  assert.equal(targets.length,2);
  for(const target of targets) assert.equal(target.digest,record.plan.images.find(image=>image.profile===target.profile).children.find(child=>child.architecture===architecture).digest);
 }
 assert.throws(()=>publishedTargets(record,inputs,'ppc64le'));
 assert.throws(()=>publishedTargets(record,{...inputs,release:'v26.8.2-r2'},'amd64'));
 const incomplete=structuredClone(record);incomplete.plan.images[0].children=[];
 assert.throws(()=>publishedTargets(incomplete,inputs,'amd64'));
});

test('direct Java experiment places Operator JVM options before the main class and preserves TLS/secret references',async()=>{
 const {keycloakResource,publishedTargets}=await model;
 for(const target of publishedTargets(record,inputs,'amd64')) {
  const cr=keycloakResource(target,true),container=cr.spec.unsupported.podTemplate.spec.containers[0];
  const actual=[...container.command,'-Djgroups.bind.address=10.244.0.2',...container.args,'--optimized'];
  assert(actual.indexOf('-Djgroups.bind.address=10.244.0.2')<actual.indexOf('io.quarkus.bootstrap.runner.QuarkusEntryPoint'));
  assert.equal(cr.spec.db.passwordSecret.name,'database-auth');
  assert.equal(cr.spec.additionalOptions.find(option=>option.name==='db-tls-mode').value,'verify-server');
  assert.equal(cr.spec.http.tlsSecret,'server-tls');assert.equal(container.securityContext.allowPrivilegeEscalation,false);
  assert.equal(keycloakResource(target).spec.unsupported.podTemplate.spec.containers[0].command,undefined);
 }
});

test('experiment distinguishes readiness, image-pull errors and concrete execution failures',async()=>{
 const {podOutcome}=await model;
 assert.equal(podOutcome(null),null);
 const pod={status:{containerStatuses:[{name:'keycloak',state:{waiting:{reason:'ImagePullBackOff'}}}]}};
 assert.equal(podOutcome(pod).status,'infrastructure-error');
 pod.status.containerStatuses[0].state={waiting:{reason:'RunContainerError',message:'exec /opt/keycloak/bin/kc.sh: no such file'}};
 assert.equal(podOutcome(pod).status,'failed');
 pod.status.containerStatuses[0].state={terminated:{exitCode:2,reason:'Error'}};
 assert.equal(podOutcome(pod).exitCode,2);
 pod.status.conditions=[{type:'Ready',status:'True'}];assert.equal(podOutcome(pod).status,'ready');
});

test('artifact sanitization removes raw and encoded ephemeral secrets and retains public image identities',async()=>{
 const {redact}=await model,password='ephemeral-private-password';
 const text='quay.io/rambow-cloud/keycloak '+password+' '+Buffer.from(password).toString('base64');
 assert.equal(redact(text,new Set([password])),'quay.io/rambow-cloud/keycloak [REDACTED] [REDACTED]');
 const {sourceProfiles,validationProfiles}=await import('../scripts/lib/image-changes.mjs');
 for(const path of ['docs/experiments/operator-kind/run.mjs','.github/workflows/operator-kind.yml','tests/operator-kind.test.cjs']) {
  assert.deepEqual(sourceProfiles(path),[]);assert.deepEqual(validationProfiles(path),[]);
 }
});
