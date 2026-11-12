import {readFile,writeFile,mkdir,readdir,access} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {resolve,join} from 'node:path';
import {nativeArchitecture} from './lib/platforms.mjs';
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const architecture=nativeArchitecture();
if(process.platform!=='linux'||!['amd64','arm64'].includes(architecture)||process.env.BUILD_ARCH&&process.env.BUILD_ARCH!==architecture) throw Error('Build the launcher on its native Linux architecture');
const policyBytes=await readFile('config/launcher.json'),policy=JSON.parse(policyBytes),directory=resolve('.cache/launcher');
const names=(await readdir('launcher')).filter(name=>name.endsWith('.go')||name==='go.mod').sort();
const sourceHash=hash(Buffer.concat([policyBytes,...await Promise.all(names.map(async name=>Buffer.concat([Buffer.from(name+'\0'),await readFile('launcher/'+name)])))]));
const binary=join(directory,'keycloak-launcher'),metadata=join(directory,'launcher.json');
const requireExisting=process.argv.includes('--require-existing');
if(requireExisting) {
  const info=JSON.parse(await readFile(metadata,'utf8')),bytes=await readFile(binary);
  if(info.architecture!==architecture||info.sourceHash!==sourceHash||info.binarySha256!==hash(bytes)||info.goVersion!==policy.goVersion||info.cgoEnabled!==false) throw Error('Launcher artifact/source binding mismatch');
} else {
  await mkdir(directory,{recursive:true});
  const work=resolve('.cache/go-'+architecture),archive=join(work,'go.tar.gz');await mkdir(work,{recursive:true});
  const response=await fetch('https://go.dev/dl/go'+policy.goVersion+'.linux-'+architecture+'.tar.gz',{signal:AbortSignal.timeout(120000)});
  if(!response.ok) throw Error('Cannot download pinned Go toolchain');
  const bytes=Buffer.from(await response.arrayBuffer());
  if(hash(bytes)!==policy.linux[architecture]) throw Error('Go archive checksum mismatch');await writeFile(archive,bytes);
  const env={...process.env,CGO_ENABLED:'0',GOOS:'linux',GOARCH:architecture,GOTOOLCHAIN:'local',GOPROXY:'off',GOSUMDB:'off'};
  const run=(command,args,options={})=>{const result=spawnSync(command,args,{stdio:'inherit',env,timeout:300000,...options});if(result.status!==0)throw Error(command+' failed');};
  run('tar',['-xzf',archive,'-C',work]);const go=join(work,'go/bin/go');
  run(go,['test','./...'],{cwd:resolve('launcher')});run(go,['vet','./...'],{cwd:resolve('launcher')});
  run(go,['build','-trimpath','-ldflags=-s -w -buildid=','-o',binary,'.'],{cwd:resolve('launcher')});
  const output=await readFile(binary);
  // ELF64 little-endian, native machine; reject a dynamic interpreter segment.
  if(output.subarray(0,4).toString('hex')!=='7f454c46'||output[4]!==2||output[5]!==1||output.readUInt16LE(18)!==(architecture==='amd64'?62:183)) throw Error('Wrong native launcher format');
  const offset=Number(output.readBigUInt64LE(32)),size=output.readUInt16LE(54),count=output.readUInt16LE(56);
  for(let index=0;index<count;index++) if(output.readUInt32LE(offset+index*size)===3) throw Error('Launcher requires a dynamic interpreter');
  run(go,['version','-m',binary]);
  await writeFile(metadata,JSON.stringify({schemaVersion:1,architecture,goVersion:policy.goVersion,cgoEnabled:false,staticElf:true,sourceHash,binarySha256:hash(output),sourceCommit:process.env.GITHUB_SHA},null,2)+'\n');
}
await access(binary);console.log('Verified native static launcher '+architecture+' source '+sourceHash);
