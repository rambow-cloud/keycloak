import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {join} from 'node:path';
import {inspectCompatibility} from '../../../scripts/lib/upstream.mjs';

const hash=bytes=>'sha256:'+createHash('sha256').update(bytes).digest('hex');
export async function historicalUpgradeTargets({targets,architecture,root,evidence,call,ciCommit}) {
  const record=JSON.parse(await readFile('releases/records/v26.8.1-r5.json','utf8'));
  if(record.status!=='published'||record.plan.keycloakVersion!=='26.8.1') throw Error('Historical source record mismatch');
  const baseline=JSON.parse(await readFile('config/upstream-compatibility.json','utf8'));
  const review=await inspectCompatibility('26.8.1',25,baseline);
  if(review.warnings.length) throw Error('Historical launcher/Java review failed: '+review.warnings.join('; '));
  call('node',['scripts/launcher.mjs','--require-existing']);
  const binary=await readFile('.cache/launcher/keycloak-launcher');
  const upgraded=[];
  for(const target of targets) {
    if(target.launcher.binarySha256!==hash(binary).slice(7)||target.launcher.sourceCommit!==ciCommit) throw Error('Historical fixture launcher is not the destination native artifact');
    const published=record.plan.images.find(image=>image.profile===target.profile);
    const parent=published.children.find(child=>child.architecture===architecture).digest;
    const source='quay.io/rambow-cloud/keycloak@'+parent;
    const manifestBytes=Buffer.from(call('skopeo',['inspect','--raw','docker://'+source]).stdout);
    const configBytes=Buffer.from(call('skopeo',['inspect','--raw','--config','docker://'+source]).stdout);
    const parentManifest=JSON.parse(manifestBytes),parentConfig=JSON.parse(configBytes);
    if(hash(manifestBytes)!==parent||hash(configBytes)!==parentManifest.config.digest||parentConfig.architecture!==architecture||parentConfig.os!=='linux'||parentConfig.config.Labels?.['org.opencontainers.image.version']!=='26.8.1') throw Error('Historical published child identity mismatch');
    const reference='localhost/keycloak-operator-'+target.profile+':previous',layout=join(root,target.profile+'-previous'),output=join(root,target.profile+'-previous.tar');
    call('buildah',['build','--format','oci','--platform','linux/'+architecture,'--build-arg','SOURCE_IMAGE='+source,'--tag',reference,'--file','tests/operator/upgrade/Containerfile','.'],{timeout:300000});
    call('skopeo',['copy','--preserve-digests','containers-storage:'+reference,'oci:'+layout+':candidate'],{timeout:300000});
    const index=JSON.parse(await readFile(join(layout,'index.json'),'utf8'));
    if(index.manifests.length!==1) throw Error('Historical fixture must have one native child');
    const digest=index.manifests[0].digest,fixtureBytes=await readFile(join(layout,'blobs/sha256',digest.slice(7))),manifest=JSON.parse(fixtureBytes);
    const fixtureConfigBytes=await readFile(join(layout,'blobs/sha256',manifest.config.digest.slice(7))),config=JSON.parse(fixtureConfigBytes);
    if(hash(fixtureBytes)!==digest||hash(fixtureConfigBytes)!==manifest.config.digest||config.architecture!==architecture||config.config.User!=='65532:65532'||
      JSON.stringify(config.config.Entrypoint)!==JSON.stringify(['/opt/keycloak/bin/kc.sh'])||
      JSON.stringify(manifest.layers.slice(0,parentManifest.layers.length))!==JSON.stringify(parentManifest.layers)||manifest.layers.length!==parentManifest.layers.length+1||
      JSON.stringify(config.rootfs.diff_ids.slice(0,parentConfig.rootfs.diff_ids.length))!==JSON.stringify(parentConfig.rootfs.diff_ids)||
      JSON.stringify(config.config.Env)!==JSON.stringify(parentConfig.config.Env)) throw Error('Historical retrofit changed original layers/environment/security identity');
    call('skopeo',['copy','--preserve-digests','oci:'+layout+':candidate','oci-archive:'+output+':'+reference],{timeout:300000});
    const scanDirectory=join(evidence,target.profile+'-historical-scan');
    call('node',['scripts/scan-image.mjs',layout,scanDirectory],{timeout:1200000,env:{...process.env,BUILD_PROFILE:target.profile,BUILD_ARCH:architecture,SCAN_RUNTIME:record.plan.imageLock.runtime,SCAN_HEAD_SHA:process.env.SOURCE_HEAD}});
    const scan=JSON.parse(await readFile(join(scanDirectory,'summary.json'),'utf8'));
    if(scan.status!=='complete'||scan.architecture!==architecture||scan.profile!==target.profile) throw Error('Historical scanner/coverage failure');
    call('kind',['load','image-archive',output,'--name','operator-test'],{timeout:300000});
    const rows=call('podman',['exec','operator-test-control-plane','ctr','-n','k8s.io','images','list']).stdout.trim().split('\n').slice(1).map(line=>line.trim().split(/\s+/));
    const imported=rows.find(row=>row[2]===digest);if(!imported) throw Error('Historical fixture digest not retained');
    if(!rows.some(row=>row[0]===reference&&row[2]===digest)) call('podman',['exec','operator-test-control-plane','ctr','-n','k8s.io','images','tag',imported[0],reference]);
    upgraded.push({...target,reference,digest,configDigest:manifest.config.digest,rootfsDiffIds:config.rootfs.diff_ids,archiveSha256:hash(await readFile(output)).slice(7),
      currentVersion:'26.8.1',nextVersion:'26.8.2',nextReference:target.reference,nextDigest:target.digest,nextConfigDigest:target.configDigest,nextRootfsDiffIds:target.rootfsDiffIds,
      destination:{version:'26.8.2',digest:target.digest,configDigest:target.configDigest,archiveSha256:target.archiveSha256,scan:target.scan},
      historicalSource:{release:record.plan.tag,publishedTag:published.tag,parentDigest:parent,parentConfigDigest:parentManifest.config.digest,
        fixtureDigest:digest,retainedParentLayers:parentManifest.layers.length,addedLauncherLayers:1,launcherSha256:target.launcher.binarySha256,
        startupReview:review,historicalScan:scan,publishEligible:false},
      derivedChange:'Historical 26.8.1-r5 child plus the same static Go launcher only; destination is the exact current-run gated 26.8.2 artifact.'});
  }
  await writeFile(join(evidence,'upgrade-scope.json'),JSON.stringify({from:'26.8.1',to:'26.8.2',historicalRetrofit:true,destinationGatesUnchanged:true},null,2)+'\n');
  return upgraded;
}
