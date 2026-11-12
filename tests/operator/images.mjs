import {readFile,writeFile,readdir,mkdir,cp} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join,resolve} from 'node:path';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');

export function verifyRunningImage({pod,target,next=false,architecture,call}) {
  const expectedManifest=next?target.nextDigest:target.digest,expectedConfig=next?target.nextConfigDigest:target.configDigest;
  const imageID=pod.status.containerStatuses[0].imageID;
  const digest=imageID?.match(/sha256:[a-f0-9]{64}$/)?.[0];
  if(!digest) throw Error('CRI did not expose an immutable image identity');
  const reference=next?target.nextReference:target.reference;
  if(pod.spec.containers[0].image!==reference) throw Error('Pod uses another image reference');
  // CRI imageID can retain a temporary import alias which is no longer resolvable.
  // Resolve the immutable-in-this-run local tag, and separately bind the running
  // container's actual snapshot parent to the validated uncompressed layer chain.
  const info=JSON.parse(call('podman',['exec','operator-test-control-plane','crictl','--runtime-endpoint','unix:///run/containerd/containerd.sock','--image-endpoint','unix:///run/containerd/containerd.sock','inspecti',reference]).stdout);
  if(info.status?.id!==expectedConfig) throw Error('Running CRI image config differs from validated native artifact');
  const content=sha=>{
    const bytes=Buffer.from(call('podman',['exec','operator-test-control-plane','ctr','-n','k8s.io','content','get',sha]).stdout);
    if('sha256:'+hash(bytes)!==sha) throw Error('Node OCI content checksum mismatch');return JSON.parse(bytes);
  };
  const manifest=content(expectedManifest),config=content(expectedConfig);
  if(manifest.config.digest!==expectedConfig||config.os!=='linux'||config.architecture!==architecture||JSON.stringify(config.rootfs.diff_ids)!==JSON.stringify(next?(target.nextRootfsDiffIds??target.rootfsDiffIds):target.rootfsDiffIds)) throw Error('Running child/config/architecture binding mismatch');
  const containerID=pod.status.containerStatuses[0].containerID?.match(/^containerd:\/\/([a-f0-9]{64})$/)?.[1];
  if(!containerID) throw Error('Missing running container identity');
  const container=JSON.parse(call('podman',['exec','operator-test-control-plane','ctr','-n','k8s.io','containers','info',containerID]).stdout);
  const containerImage=container.Image??container.image,snapshotKey=container.SnapshotKey??container.snapshotKey,snapshotter=container.Snapshotter??container.snapshotter;
  if(![reference,expectedConfig,imageID].includes(containerImage)||!snapshotKey||!snapshotter) throw Error('Running container image/snapshot binding mismatch: '+JSON.stringify({containerImage,snapshotKey,snapshotter}));
  const snapshot=JSON.parse(call('podman',['exec','operator-test-control-plane','ctr','-n','k8s.io','snapshots','--snapshotter',snapshotter,'info',snapshotKey]).stdout);
  const chain=config.rootfs.diff_ids.reduce((parent,child)=>parent?'sha256:'+hash(Buffer.from(parent+' '+child)):child,'');
  if((snapshot.Parent??snapshot.parent)!==chain) throw Error('Running snapshot differs from validated native rootfs: '+JSON.stringify({actual:snapshot.Parent??snapshot.parent,expected:chain}));
  return {pod:pod.metadata.name,uid:pod.metadata.uid,imageID,reportedDigest:digest,manifest:expectedManifest,config:expectedConfig,architecture,containerImage,snapshotParent:chain};
}

export async function loadCandidateImages({profiles,architecture,ciCommit,sourceHead,runId,root,call,derive=true}) {
  const targets=[];
  for(const profile of profiles) {
    const directory=resolve('.cache/operator-input/keycloak-oci-'+profile+'-'+architecture+'-'+ciCommit);
    const archive=join(directory,'keycloak.oci.tar'),expected=(await readFile(archive+'.sha256','utf8')).trim().split(/\s+/)[0];
    // Hash streaming is unnecessary here: native archives are bounded by the producing CI contract.
    const bytes=await readFile(archive);
    if(hash(bytes)!==expected) throw Error('Downloaded OCI archive checksum mismatch');
    const scan=JSON.parse(await readFile(join(directory,'scan-summary.json'),'utf8'));
    const launcher=JSON.parse(await readFile(join(directory,'launcher.json'),'utf8'));
    if(launcher.cgoEnabled!==false||launcher.staticElf!==true||launcher.architecture!==architecture||launcher.sourceCommit!==ciCommit) throw Error('Native static launcher binding is missing');
    if(scan.status!=='complete'||scan.blocking!==0||scan.profile!==profile||scan.architecture!==architecture||scan.headSha!==sourceHead||scan.runId!==runId) throw Error('Native scan provenance/gate mismatch');
    const layout=join(root,profile+'-source'),derived=join(root,profile+'-next');
    call('skopeo',['copy','--preserve-digests','oci-archive:'+archive,'oci:'+layout+':candidate'],{timeout:300000});
    const index=JSON.parse(await readFile(join(layout,'index.json'),'utf8'));
    if(index.manifests.length!==1) throw Error('Expected a single native OCI child');
    const manifestBytes=await readFile(join(layout,'blobs/sha256',index.manifests[0].digest.slice(7)));
    if('sha256:'+hash(manifestBytes)!==index.manifests[0].digest) throw Error('Native manifest checksum mismatch');
    const manifest=JSON.parse(manifestBytes),configBytes=await readFile(join(layout,'blobs/sha256',manifest.config.digest.slice(7))),config=JSON.parse(configBytes);
    if('sha256:'+hash(configBytes)!==manifest.config.digest||config.architecture!==architecture||config.os!=='linux'||config.config.User!=='65532:65532'||
      config.config.Labels?.['org.opencontainers.image.revision']!==ciCommit||config.config.Labels?.['cloud.rambow.keycloak.profile']!==profile||
      JSON.stringify(config.config.Entrypoint)!==JSON.stringify(['/opt/keycloak/bin/kc.sh'])) throw Error('Candidate config/launcher identity mismatch');
    await cp(layout,derived,{recursive:true});
    const nextConfig=structuredClone(config);nextConfig.config.Labels={...nextConfig.config.Labels,'cloud.rambow.keycloak.operator-test-revision':'2'};
    const nextConfigBytes=Buffer.from(JSON.stringify(nextConfig)),nextConfigDigest='sha256:'+hash(nextConfigBytes);
    const nextManifest=structuredClone(manifest);nextManifest.config={...manifest.config,digest:nextConfigDigest,size:nextConfigBytes.length};
    const nextManifestBytes=Buffer.from(JSON.stringify(nextManifest)),nextDigest='sha256:'+hash(nextManifestBytes);
    await writeFile(join(derived,'blobs/sha256',nextConfigDigest.slice(7)),nextConfigBytes);
    await writeFile(join(derived,'blobs/sha256',nextDigest.slice(7)),nextManifestBytes);
    const nextIndex=structuredClone(index);nextIndex.manifests[0]={...nextIndex.manifests[0],digest:nextDigest,size:nextManifestBytes.length};
    await writeFile(join(derived,'index.json'),JSON.stringify(nextIndex));
    if(JSON.stringify(nextConfig.rootfs)!==JSON.stringify(config.rootfs)||JSON.stringify(nextManifest.layers)!==JSON.stringify(manifest.layers)) throw Error('Rolling fixture changed executable/package layers');
    const reference='localhost/keycloak-operator-'+profile+':candidate',nextReference='localhost/keycloak-operator-'+profile+':next';
    for(const [source,name,digest] of (derive?[[layout,reference,index.manifests[0].digest],[derived,nextReference,nextDigest]]:[[layout,reference,index.manifests[0].digest]])) {
      const output=join(root,profile+(name===reference?'-candidate':'-next')+'.tar');
      call('skopeo',['copy','--preserve-digests','oci:'+source+':candidate','oci-archive:'+output+':'+name],{timeout:300000});
      call('kind',['load','image-archive',output,'--name','operator-test'],{timeout:300000});
      const rows=call('podman',['exec','operator-test-control-plane','ctr','-n','k8s.io','images','list']).stdout.trim().split('\n').slice(1).map(line=>line.trim().split(/\s+/));
      const imported=rows.find(row=>row[2]===digest);
      if(!imported) throw Error('Imported candidate digest was not retained in containerd');
      if(!rows.some(row=>row[0]===name&&row[2]===digest)) call('podman',['exec','operator-test-control-plane','ctr','-n','k8s.io','images','tag',imported[0],name]);
    }
    targets.push({profile,reference,nextReference,digest:index.manifests[0].digest,nextDigest,configDigest:manifest.config.digest,nextConfigDigest,launcher,
      rootfsDiffIds:config.rootfs.diff_ids,archiveSha256:expected,scan:{headSha:scan.headSha,runId:scan.runId,runAttempt:scan.runAttempt,blocking:scan.blocking},
      derivedChange:'Only cloud.rambow.keycloak.operator-test-revision=2 is added to image config; all filesystem layers, env, command and executable inputs are retained.'});
  }
  return targets;
}
