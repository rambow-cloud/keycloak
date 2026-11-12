'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const {createHash}=require('node:crypto');
const implementation=import('./operator/images.mjs');
const hash=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
function fixture() {
 const config=JSON.stringify({os:'linux',architecture:'arm64',rootfs:{diff_ids:['sha256:'+'1'.repeat(64)]}}),configDigest=hash(config);
 const manifest=JSON.stringify({schemaVersion:2,config:{digest:configDigest}}),digest=hash(manifest);
 const index=JSON.stringify({schemaVersion:2,manifests:[{digest}]}),indexDigest=hash(index);
 const blobs={[configDigest]:config,[digest]:manifest,[indexDigest]:index};
 const reference='localhost/keycloak-core:candidate',target={digest,configDigest,reference,rootfsDiffIds:['sha256:'+'1'.repeat(64)]};
 const pod={metadata:{name:'core-0',uid:'pod-uid'},spec:{containers:[{image:reference}]},status:{containerStatuses:[{imageID:'docker.io/library/import@'+indexDigest,containerID:'containerd://'+'a'.repeat(64)}]}};
 const state={actualConfig:configDigest,parent:target.rootfsDiffIds[0]};
 return {pod,target,architecture:'arm64',state,blobs,call:(_command,args)=>({stdout:
  args.includes('inspecti')?JSON.stringify({status:{id:state.actualConfig}}):
  args.includes('containers')?JSON.stringify({Image:reference,SnapshotKey:'container-snapshot',Snapshotter:'overlayfs'}):
  args.includes('snapshots')?JSON.stringify({Parent:state.parent}):blobs[args.at(-1)]})};
}
test('native OCI proof follows a CRI import wrapper while requiring exact runtime config and child',async()=>{
 const {verifyRunningImage}=await implementation,f=fixture();
 assert.equal(verifyRunningImage(f).manifest,f.target.digest);
 f.pod.status.containerStatuses[0].imageID=f.target.configDigest;
 assert.equal(verifyRunningImage(f).config,f.target.configDigest);
});
test('OCI proof rejects another config, foreign architecture, corrupt content and another running rootfs',async()=>{
 const {verifyRunningImage}=await implementation;
 for(const mutate of [f=>f.state.actualConfig='sha256:'+'2'.repeat(64),f=>f.architecture='amd64',f=>f.blobs[f.target.digest]+=' ',f=>f.state.parent='sha256:'+'3'.repeat(64)]) {
  const f=fixture();mutate(f);assert.throws(()=>verifyRunningImage(f));
 }
});
