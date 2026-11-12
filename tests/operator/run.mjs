import {mkdir,readFile,writeFile,chmod,readdir} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {spawnSync,spawn,fork} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import https from 'node:https';
import {keycloakResource,podOutcome,redact,markdown} from './model.mjs';
import {loadCandidateImages} from './images.mjs';

const root=resolve('.cache/operator-kind'),evidence=join(root,'evidence'),privateDir=join(root,'private'),tools=join(root,'tools');
const architecture=process.env.BUILD_ARCH,native=process.arch==='x64'?'amd64':process.arch;
if(process.platform!=='linux'||architecture!==native||!['amd64','arm64'].includes(native)||process.env.KIND_EXPERIMENTAL_PROVIDER!=='podman') throw Error('Native Linux and explicit Podman provider required');
const inputs=JSON.parse(await readFile('config/operator-tests.json','utf8'));
const lock=JSON.parse(await readFile('images.lock.json','utf8'));
const targets=[],secrets=new Set(),profiles=JSON.parse(process.env.OPERATOR_PROFILES??'["core","aws"]');
if(!profiles.length||profiles.some(profile=>!['core','aws'].includes(profile))) throw Error('Invalid selected Operator profiles');
await mkdir(evidence,{recursive:true});await mkdir(privateDir,{recursive:true,mode:0o700});await mkdir(tools,{recursive:true});
await chmod(privateDir,0o700);
process.env.PATH=tools+':'+process.env.PATH;process.env.KUBECONFIG=join(privateDir,'kubeconfig');
const report={schemaVersion:1,architecture,branch:process.env.SOURCE_BRANCH,commit:process.env.SOURCE_HEAD,ciCommit:process.env.GITHUB_SHA,
  runId:Number(process.env.GITHUB_RUN_ID),runAttempt:Number(process.env.GITHUB_RUN_ATTEMPT??1),inputs,database:lock.postgres,targets,results:[]};
const clean=value=>redact(value,secrets);
const save=async(name,value)=>writeFile(join(evidence,name),clean(typeof value==='string'?value:JSON.stringify(value,null,2)+'\n'));
const call=(command,args,{input,allowFailure=false,timeout=120000}={})=>{
  const result=spawnSync(command,args,{input,encoding:'utf8',timeout,maxBuffer:20000000});
  if((result.error||result.status!==0)&&!allowFailure) throw Error(clean(command+' '+args.join(' ')+': '+(result.error?.message??result.status)+'\n'+result.stdout+'\n'+result.stderr));
  return result;
};
const kubectl=(args,options)=>call('kubectl',['-n','keycloak',...args],options);
const apply=value=>kubectl(['apply','-f','-'],{input:JSON.stringify(value)});
const get=(type,name)=>{
  const result=kubectl(['get',type,...(name?[name]:[]),'-o','json'],{allowFailure:true});
  if(result.status===0) return JSON.parse(result.stdout);
  if(/NotFound|not found/.test(result.stderr)) return null;
  throw Error(clean(result.stderr));
};
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(description,read,seconds=240) {
  const deadline=Date.now()+seconds*1000;
  while(Date.now()<deadline) {const value=await read();if(value) return value;await sleep(2000);}
  throw Error('Timed out: '+description);
}
async function download(url,name,expected) {
  const response=await fetch(url,{signal:AbortSignal.timeout(120000)});
  if(!response.ok) throw Error('Pinned tool download failed: '+response.status);
  const bytes=Buffer.from(await response.arrayBuffer());
  if(createHash('sha256').update(bytes).digest('hex')!==expected) throw Error('Pinned tool checksum mismatch: '+name);
  await writeFile(join(tools,name),bytes,{mode:0o755});
}
function secret(name,data,type='Opaque') {
  for(const [key,value] of Object.entries(data)) if(/password|key$/.test(key)) secrets.add(value);
  apply({apiVersion:'v1',kind:'Secret',metadata:{name,namespace:'keycloak'},type,
    data:Object.fromEntries(Object.entries(data).map(([key,value])=>[key,Buffer.from(value).toString('base64')]))});
}
async function certificates() {
  const file=name=>join(privateDir,name);
  call('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','1','-subj','/CN=Operator Test CA','-keyout',file('ca.key'),'-out',file('ca.crt')]);
  for(const [name,dns] of [['database',['postgres']],['server',['core.keycloak.test','aws.keycloak.test']]]) {
    call('openssl',['req','-newkey','rsa:2048','-nodes','-sha256','-subj','/CN='+dns[0],'-keyout',file(name+'.key'),'-out',file(name+'.csr')]);
    await writeFile(file(name+'.ext'),'subjectAltName='+dns.map(host=>'DNS:'+host).join(',')+'\nextendedKeyUsage=serverAuth\n');
    call('openssl',['x509','-req','-in',file(name+'.csr'),'-CA',file('ca.crt'),'-CAkey',file('ca.key'),'-CAcreateserial','-days','1','-sha256','-extfile',file(name+'.ext'),'-out',file(name+'.crt')]);
  }
  const read=name=>readFile(file(name),'utf8');
  secret('database-auth',{username:'keycloak',password:randomBytes(24).toString('hex')});
  secret('database-tls',{'tls.crt':await read('database.crt'),'tls.key':await read('database.key')},'kubernetes.io/tls');
  secret('server-tls',{'tls.crt':await read('server.crt'),'tls.key':await read('server.key')},'kubernetes.io/tls');
  secret('database-ca',{'ca.crt':await read('ca.crt')});
}
function database() {
  apply({apiVersion:'v1',kind:'ConfigMap',metadata:{name:'database-config'},data:{
    '00-databases.sql':'CREATE DATABASE keycloak_core;\nCREATE DATABASE keycloak_aws;\n',
    'pg_hba.conf':'local all all trust\nhostssl all all 0.0.0.0/0 scram-sha-256\nhostssl all all ::/0 scram-sha-256\nhostnossl all all 0.0.0.0/0 reject\nhostnossl all all ::/0 reject\n'}});
  apply({apiVersion:'v1',kind:'Service',metadata:{name:'postgres'},spec:{selector:{app:'postgres'},ports:[{port:5432,targetPort:5432}]}});
  apply({apiVersion:'apps/v1',kind:'Deployment',metadata:{name:'postgres'},spec:{replicas:1,selector:{matchLabels:{app:'postgres'}},template:{metadata:{labels:{app:'postgres'}},spec:{
    initContainers:[{name:'prepare-tls',image:lock.postgres,command:['sh','-ceu','cp /source/tls.crt /tls/server.crt; cp /source/tls.key /tls/server.key; chown postgres:postgres /tls/*; chmod 600 /tls/server.key'],
      volumeMounts:[{name:'tls-source',mountPath:'/source',readOnly:true},{name:'tls',mountPath:'/tls'}]}],
    containers:[{name:'postgres',image:lock.postgres,args:['-c','ssl=on','-c','ssl_cert_file=/tls/server.crt','-c','ssl_key_file=/tls/server.key','-c','hba_file=/etc/postgres-test/pg_hba.conf'],
      env:[{name:'POSTGRES_USER',valueFrom:{secretKeyRef:{name:'database-auth',key:'username'}}},{name:'POSTGRES_PASSWORD',valueFrom:{secretKeyRef:{name:'database-auth',key:'password'}}},{name:'POSTGRES_DB',value:'postgres'}],
      ports:[{containerPort:5432}],resources:{requests:{cpu:'100m',memory:'128Mi'},limits:{memory:'512Mi'}},
      readinessProbe:{exec:{command:['pg_isready','-U','keycloak','-d','postgres']},periodSeconds:2},
      volumeMounts:[{name:'tls',mountPath:'/tls',readOnly:true},{name:'config',mountPath:'/etc/postgres-test',readOnly:true},{name:'init',mountPath:'/docker-entrypoint-initdb.d',readOnly:true}]}],
    volumes:[{name:'tls-source',secret:{secretName:'database-tls'}},{name:'tls',emptyDir:{}},{name:'config',configMap:{name:'database-config',items:[{key:'pg_hba.conf',path:'pg_hba.conf'}]}},
      {name:'init',configMap:{name:'database-config',items:[{key:'00-databases.sql',path:'00-databases.sql'}]}}]
  }}}});
  kubectl(['rollout','status','deployment/postgres','--timeout=180s']);
}
async function snapshot(prefix) {
  const resources=get('pods,statefulsets,jobs,keycloaks,keycloakrealmimports,services,deployments');
  await save(prefix+'-resources.json',resources);
  await save(prefix+'-events.json',get('events'));
  for(const pod of resources.items.filter(item=>item.kind==='Pod')) {
    for(const container of [...pod.spec.initContainers??[],...pod.spec.containers??[]]) {
      const result=kubectl(['logs',pod.metadata.name,'-c',container.name,'--tail=1500'],{allowFailure:true});
      await save(prefix+'-'+pod.metadata.name+'-'+container.name+'.log',result.stdout+result.stderr);
      if([...pod.status.initContainerStatuses??[],...pod.status.containerStatuses??[]].some(status=>status.name===container.name&&status.restartCount>0)) {
        const previous=kubectl(['logs',pod.metadata.name,'-c',container.name,'--previous','--tail=1500'],{allowFailure:true});
        await save(prefix+'-'+pod.metadata.name+'-'+container.name+'-previous.log',previous.stdout+previous.stderr);
      }
    }
  }
}
async function server(target,phase,resource) {
  await save(target.profile+'-'+phase+'-cr.json',resource);apply(resource);
  const outcome=await until(target.profile+' '+phase,()=>{
    const pods=serverPods(target);
    for(const pod of pods) {
      const result=podOutcome(pod);
      if(result?.status==='infrastructure-error'||result?.status==='failed') throw Error('Operator server failed: '+JSON.stringify(result));
    }
    return pods.length===2&&pods.every(pod=>podOutcome(pod)?.status==='ready')&&{status:'ready',pods};
  });
  const template=get('statefulset',target.profile).spec.template.spec.containers[0];
  if(template.command?.length||template.args.some(argument=>argument==='-cp'||argument.includes('QuarkusEntryPoint'))) throw Error('Stock Operator command was overridden');
  for(const pod of outcome.pods) if(![target.digest,target.configDigest].some(digest=>pod.status.containerStatuses[0].imageID.endsWith(digest))) throw Error('Running candidate native identity mismatch');
  const result={profile:target.profile,phase,status:'passed',command:template.command??null,args:template.args,
    pods:outcome.pods.map(pod=>({name:pod.metadata.name,uid:pod.metadata.uid,imageID:pod.status.containerStatuses[0].imageID}))};
  await snapshot(target.profile+'-'+phase);report.results.push(result);return result;
}
function serverPods(target) {return get('pods').items.filter(pod=>[target.profile+'-0',target.profile+'-1'].includes(pod.metadata.name)&&!pod.metadata.deletionTimestamp);}
function expose(target) {
  const service=get('service',target.profile+'-service');
  if(!service?.spec.selector) throw Error('Operator service is missing');
  apply({apiVersion:'v1',kind:'Service',metadata:{name:'operator-probe'},spec:{type:'NodePort',selector:service.spec.selector,ports:[{port:8443,targetPort:8443,nodePort:30443}]}});
}
async function apiClient(target) {
  const hostname=target.profile+'.keycloak.test',port=18443;
  const ca=await readFile(join(privateDir,'ca.crt'));
  const request=(path,method='GET',body,token)=>new Promise((resolve,reject)=>{
    const isJson=body&&typeof body==='object';if(isJson) body=JSON.stringify(body);
    const req=https.request({hostname:'127.0.0.1',port,servername:hostname,ca,rejectUnauthorized:true,path,method,
      headers:{Host:hostname,...(body?{'Content-Type':isJson?'application/json':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)}:{}),...(token?{Authorization:'Bearer '+token}:{})}},response=>{
      const parts=[];response.on('data',part=>parts.push(part));response.on('end',()=>{
        const text=Buffer.concat(parts).toString('utf8');
        try {resolve({status:response.statusCode,json:text?JSON.parse(text):null});}
        catch {reject(Error('Unexpected non-JSON HTTPS response, HTTP '+response.statusCode));}
      });
    });req.setTimeout(10000,()=>req.destroy(Error('HTTPS request timeout')));req.on('error',reject);req.end(body);
  });
  return {request,hostname,ca:ca.toString('utf8')};
}
async function apiCheck(target) {
    const {request,hostname}=await apiClient(target);
    const discovery=await until('verified HTTPS discovery',async()=>{
      try {return await request('/realms/master/.well-known/openid-configuration');} catch(error) {if(error.code==='ECONNREFUSED'||error.code==='ECONNRESET') return null;throw error;}
    },60);
    if(discovery.status!==200||discovery.json.issuer!=='https://'+hostname+'/realms/master') throw Error('Verified HTTPS discovery mismatch');
    const admin=get('secret',target.profile+'-initial-admin');
    const username=Buffer.from(admin.data.username,'base64').toString(),password=Buffer.from(admin.data.password,'base64').toString();
    secrets.add(username);secrets.add(password);
    const token=await request('/realms/master/protocol/openid-connect/token','POST',new URLSearchParams({client_id:'admin-cli',grant_type:'password',username,password}).toString());
    if(token.status!==200||!token.json.access_token) throw Error('Admin token request failed, HTTP '+token.status);
    secrets.add(token.json.access_token);if(token.json.refresh_token) secrets.add(token.json.refresh_token);
    const info=await request('/admin/serverinfo','GET',undefined,token.json.access_token);
    if(info.status!==200||info.json.systemInfo?.version!==inputs.keycloakVersion) throw Error('Admin API version verification failed');
    const tls=kubectl(['exec','deployment/postgres','--','psql','-U','keycloak','-d','postgres','-Atc',"select bool_and(ssl)::text from pg_stat_ssl s join pg_stat_activity a using(pid) where a.datname='keycloak_"+target.profile+"';"]).stdout.trim();
    if(tls!=='true') throw Error('Database connections are missing or not all TLS');
    report.results.push({profile:target.profile,phase:'verified-https-admin-and-db-tls',status:'passed',issuer:discovery.json.issuer,databaseTls:true});
    return {request,token:token.json.access_token};
}
async function restart(target) {
  const uid=get('pod',target.profile+'-0').metadata.uid;
  kubectl(['delete','pod',target.profile+'-0','--wait=true','--timeout=60s']);
  await until('Operator restart recovery',()=>{
    const pod=get('pod',target.profile+'-0');return pod?.metadata.uid!==uid&&podOutcome(pod)?.status==='ready'&&serverPods(target).length===2;
  });
  await apiCheck(target);report.results.push({profile:target.profile,phase:'restart-recovery',status:'passed'});
}
async function realmImport(target) {
  const name=target.profile+'-realm-import';
  apply({apiVersion:'k8s.keycloak.org/v2beta1',kind:'KeycloakRealmImport',metadata:{name},spec:{keycloakCRName:target.profile,realm:{realm:'operator-'+target.profile,displayName:'Imported '+target.profile,enabled:true}}});
  const result=await until('Realm Import execution',()=>{
    const job=get('job',name);if(!job) return null;
    const pods=get('pods').items.filter(pod=>pod.metadata.ownerReferences?.some(owner=>owner.uid===job.metadata.uid));
    const failure=pods.map(pod=>podOutcome(pod)).find(Boolean);
    if(failure?.status==='infrastructure-error') throw Error(JSON.stringify(failure));
    if(failure?.status==='failed') throw Error('Realm Import execution failed: '+JSON.stringify(failure));
    const cr=get('keycloakrealmimport',name);
    const done=cr.status?.conditions?.some(condition=>condition.type==='Done'&&String(condition.status).toLowerCase()==='true');
    return job.status?.succeeded&&done?{status:'passed',job,pods}:null;
  });
  await snapshot(name);
  const {request,token}=await apiCheck(target);
  const realm=await request('/admin/realms/operator-'+target.profile,'GET',undefined,token);
  if(realm.status!==200||realm.json.realm!=='operator-'+target.profile||realm.json.displayName!=='Imported '+target.profile) throw Error('Imported realm API verification failed');
  const logs=kubectl(['logs','job/'+name,'--tail=1000']).stdout;
  if(/Quarkus augmentation completed|Changes detected in configuration|Updating the configuration and installing/.test(logs)) throw Error('Realm Import performed runtime augmentation');
  const resultRecord={profile:target.profile,phase:'realm-import',status:'passed',command:result.job.spec.template.spec.containers[0].command,args:result.job.spec.template.spec.containers[0].args,
    doneCondition:true,realm:realm.json.realm,podExitCodes:result.pods.flatMap(pod=>pod.status.containerStatuses.map(container=>container.state.terminated.exitCode)),runtimeAugmentation:false};
  report.results.push(resultRecord);
}
async function rollingUpdate(resource,target) {
  const realm='operator-'+target.profile,{request,token}=await apiCheck(target);
  const clientId='operator-traffic',username='traffic-'+target.profile,password=randomBytes(24).toString('hex');secrets.add(password);
  const client=await request('/admin/realms/'+realm+'/clients','POST',{clientId,enabled:true,publicClient:true,directAccessGrantsEnabled:true,standardFlowEnabled:false},token);
  if(client.status!==201) throw Error('Cannot create rolling-traffic client, HTTP '+client.status);
  const user=await request('/admin/realms/'+realm+'/users','POST',{username,enabled:true,firstName:'Operator',lastName:'Test',email:username+'@example.test',emailVerified:true,requiredActions:[],credentials:[{type:'password',value:password,temporary:false}]},token);
  if(user.status!==201) throw Error('Cannot create rolling-traffic user, HTTP '+user.status);
  const connection=await apiClient(target),worker=fork(resolve('tests/operator/traffic.mjs'),[],{stdio:['ignore','ignore','ignore','ipc']});
  let readyResolve,readyReject,finishedResolve,finishedReject,stats;
  const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});
  const finished=new Promise((resolve,reject)=>{finishedResolve=resolve;finishedReject=reject;});
  worker.on('message',message=>{
    if(message.type==='ready') readyResolve();
    if(message.type==='finished') {stats=message.stats;if(!stats.rounds) readyReject(Error('Traffic baseline failed'));finishedResolve(stats);}
  });
  worker.on('error',error=>{readyReject(error);finishedReject(error);});
  worker.on('exit',code=>{if(!stats) {const error=Error('Traffic worker exited without evidence: '+code);readyReject(error);finishedReject(error);}});
  worker.send({type:'start',configuration:{hostname:connection.hostname,ca:connection.ca,realm,clientId,username,password}});
  const old=serverPods(target),oldUIDs=new Set(old.map(pod=>pod.metadata.uid)),watches=[];
  const timeline=[];let observed;
  try {
    await Promise.race([ready,sleep(60000).then(()=>{throw Error('Traffic baseline timeout');})]);
    for(const pod of old) {
      const process=spawn('kubectl',['-n','keycloak','logs',pod.metadata.name,'--follow','--timestamps'],{stdio:['ignore','pipe','pipe']});
      const watch={name:pod.metadata.name,uid:pod.metadata.uid,process,text:''};
      process.stdout.on('data',bytes=>{watch.text+=bytes.toString();});process.stderr.on('data',bytes=>{watch.text+=bytes.toString();});
      watches.push(watch);
    }
    await until('Old-Pod log streams',()=>watches.every(watch=>watch.text.length>0),30);
    resource.spec.image=target.nextReference;apply(resource);
    observed=await until('Auto two-replica image rolling replacement',()=>{
      const pods=serverPods(target),readyPods=pods.filter(pod=>podOutcome(pod)?.status==='ready').length;
      const cr=get('keycloak',target.profile),jobs=get('jobs').items.filter(job=>job.metadata.labels?.app==='keycloak-update-job');
      timeline.push({at:new Date().toISOString(),readyPods,pods:pods.map(pod=>({name:pod.metadata.name,uid:pod.metadata.uid,image:pod.spec.containers[0].image,ready:podOutcome(pod)?.status==='ready'}))});
      if(readyPods<1) throw Error('Auto update lost all ready replicas');
      if(stats?.failures.length) throw Error('Authenticated traffic failed during rollout');
      for(const pod of pods) {const state=podOutcome(pod);if(state?.status==='failed'||state?.status==='infrastructure-error') throw Error('Updated server failed: '+JSON.stringify(state));}
      const job=jobs[0];
      const jobPods=job?get('pods').items.filter(pod=>pod.metadata.ownerReferences?.some(owner=>owner.uid===job.metadata.uid)):[];
      for(const pod of jobPods) {const state=podOutcome(pod);if(state?.status==='failed'||state?.status==='infrastructure-error') throw Error('Auto compatibility Job failed: '+JSON.stringify(state));}
      const used=cr.status?.conditions?.find(condition=>condition.type==='RecreateUpdateUsed');
      const rolling=used&&String(used.status).toLowerCase()==='false';
      return pods.length===2&&readyPods===2&&pods.every(pod=>!oldUIDs.has(pod.metadata.uid)&&pod.spec.containers[0].image===target.nextReference)&&job?.status?.succeeded&&rolling?{job,jobPods,pods,condition:used}:null;
    },300);
    await sleep(2000);
  } finally {
    if(worker.connected) worker.send({type:'stop'});
    stats=await Promise.race([finished,sleep(10000).then(()=>{worker.kill();throw Error('Traffic worker did not finish');})]);
    await save(target.profile+'-traffic.json',stats);await save(target.profile+'-rolling-timeline.json',timeline);
    for(const watch of watches) {watch.process.kill();await save(target.profile+'-old-'+watch.name+'-'+watch.uid+'.log',watch.text);}
  }
  if(stats.failures.length||stats.rounds<3||stats.refresh<3||stats.userinfo<3) throw Error('Incomplete or failed authenticated rollout traffic');
  for(const watch of watches) if(!/Keycloak stopped in/.test(watch.text)) throw Error('Missing graceful JVM shutdown for '+watch.name);
  const codes=observed.jobPods.flatMap(pod=>[...pod.status.initContainerStatuses??[],...pod.status.containerStatuses??[]].map(status=>status.state.terminated?.exitCode));
  if(codes.length<2||codes.some(code=>code!==0)) throw Error('Compatibility metadata/check did not both exit zero');
  for(const pod of observed.pods) if(![target.nextDigest,target.nextConfigDigest].some(digest=>pod.status.containerStatuses[0].imageID.endsWith(digest))) throw Error('Updated native OCI imageID mismatch');
  await snapshot(target.profile+'-rolling-complete');await apiCheck(target);
  report.results.push({profile:target.profile,phase:'auto-image-rolling-update',status:'passed',fromDigest:target.digest,toDigest:target.nextDigest,
    oldPods:old.map(pod=>({name:pod.metadata.name,uid:pod.metadata.uid})),newPods:observed.pods.map(pod=>({name:pod.metadata.name,uid:pod.metadata.uid,imageID:pod.status.containerStatuses[0].imageID})),
    compatibilityExitCodes:codes,recreateUpdateUsed:false,minReadyReplicas:Math.min(...timeline.map(sample=>sample.readyPods)),gracefulShutdownPods:watches.map(watch=>watch.name),traffic:stats});
}

let clusterCreated=false;
try {
  await Promise.all([
    download('https://github.com/kubernetes-sigs/kind/releases/download/v'+inputs.kind.version+'/kind-linux-'+architecture,'kind',inputs.kind[architecture]),
    download('https://dl.k8s.io/release/v'+inputs.kubectl.version+'/bin/linux/'+architecture+'/kubectl','kubectl',inputs.kubectl[architecture])
  ]);
  await save('versions.txt',call('podman',['version']).stdout+call('kind',['version']).stdout+call('kubectl',['version','--client','-o','json']).stdout);
  await writeFile(join(root,'kind.json'),JSON.stringify({kind:'Cluster',apiVersion:'kind.x-k8s.io/v1alpha4',nodes:[{role:'control-plane',extraPortMappings:[{containerPort:30443,hostPort:18443,listenAddress:'127.0.0.1',protocol:'TCP'}]}]}));
  call('kind',['create','cluster','--name','operator-test','--image',inputs.node,'--config',join(root,'kind.json'),'--kubeconfig',process.env.KUBECONFIG,'--wait','180s'],{timeout:480000});clusterCreated=true;
  await save('nodes.json',JSON.parse(call('kubectl',['get','nodes','-o','json']).stdout));
  if(!JSON.parse(call('kubectl',['get','nodes','-o','json']).stdout).items.every(node=>node.status.nodeInfo.architecture===architecture)) throw Error('Nonnative Kubernetes node');
  targets.push(...await loadCandidateImages({profiles,architecture,ciCommit:process.env.GITHUB_SHA,sourceHead:process.env.SOURCE_HEAD,runId:report.runId,root,call}));
  const upstream=join(root,'upstream');
  call('git',['init',upstream]);call('git',['-C',upstream,'remote','add','origin','https://github.com/keycloak/keycloak-k8s-resources.git']);
  call('git',['-C',upstream,'fetch','--depth=1','origin',inputs.operatorResourcesCommit]);call('git',['-C',upstream,'checkout','--detach','FETCH_HEAD']);
  if(call('git',['-C',upstream,'rev-parse','HEAD']).stdout.trim()!==inputs.operatorResourcesCommit) throw Error('Operator resource commit mismatch');
  await writeFile(join(root,'kustomization.yaml'),JSON.stringify({apiVersion:'kustomize.config.k8s.io/v1beta1',kind:'Kustomization',resources:['./upstream/kubernetes'],
    images:[{name:'quay.io/keycloak/keycloak-operator',newName:'quay.io/keycloak/keycloak-operator',digest:inputs.operator[architecture]}]}));
  call('kubectl',['create','namespace','keycloak']);call('kubectl',['apply','-k',root]);
  call('kubectl',['wait','--for=condition=Established','crd/keycloaks.k8s.keycloak.org','crd/keycloakrealmimports.k8s.keycloak.org','--timeout=60s']);
  kubectl(['rollout','status','deployment/keycloak-operator','--timeout=180s']);
  const operator=get('pods').items.find(pod=>pod.metadata.labels?.['app.kubernetes.io/name']==='keycloak-operator');
  if(!operator.status.containerStatuses[0].imageID.includes(inputs.operator[architecture])) throw Error('Operator native imageID mismatch');
  await certificates();database();
  for(const target of targets) {
    const resource=keycloakResource(target);await server(target,'stock-operator-launch',resource);expose(target);
    await apiCheck(target);await restart(target);await realmImport(target);
    await rollingUpdate(resource,target);
    kubectl(['delete','keycloakrealmimport',target.profile+'-realm-import','--ignore-not-found=true']);
    kubectl(['delete','keycloak',target.profile,'--wait=true','--timeout=60s']);
    kubectl(['delete','jobs','--all','--wait=true','--timeout=60s']);
    kubectl(['delete','service','operator-probe','--wait=true']);
  }
} catch(error) {
  report.error=clean(error.stack??error.message);process.exitCode=1;
} finally {
  if(clusterCreated) {
    try {await snapshot('final');} catch(error) {await save('collection-error.txt',error.message);}
    const nodeLogs=call('podman',['logs','operator-test-control-plane'],{allowFailure:true});
    await save('kind-node.log',nodeLogs.stdout+nodeLogs.stderr);
    call('kind',['delete','cluster','--name','operator-test'],{allowFailure:true});
  }
  await save('results.json',report);await save('summary.md',markdown(report));
  console.log(clean(JSON.stringify({architecture,results:report.results.map(({profile,phase,status})=>({profile,phase,status})),error:report.error},null,2)));
}
