import {mkdir,readFile,writeFile,chmod} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {spawnSync,spawn} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import https from 'node:https';
import {publishedTargets,keycloakResource,podOutcome,redact,markdown} from './model.mjs';

const root=resolve('.cache/operator-kind'),evidence=join(root,'evidence'),privateDir=join(root,'private'),tools=join(root,'tools');
const architecture=process.env.BUILD_ARCH,native=process.arch==='x64'?'amd64':process.arch;
if(process.platform!=='linux'||architecture!==native||!['amd64','arm64'].includes(native)||process.env.KIND_EXPERIMENTAL_PROVIDER!=='podman') throw Error('Native Linux and explicit Podman provider required');
const inputs=JSON.parse(await readFile('docs/experiments/operator-kind/inputs.json','utf8'));
const record=JSON.parse(await readFile('releases/records/'+inputs.release+'.json','utf8'));
const lock=JSON.parse(await readFile('images.lock.json','utf8'));
const targets=publishedTargets(record,inputs,architecture),secrets=new Set();
await mkdir(evidence,{recursive:true});await mkdir(privateDir,{recursive:true,mode:0o700});await mkdir(tools,{recursive:true});
await chmod(privateDir,0o700);
process.env.PATH=tools+':'+process.env.PATH;process.env.KUBECONFIG=join(privateDir,'kubeconfig');
const report={schemaVersion:1,architecture,release:inputs.release,branch:process.env.GITHUB_REF_NAME,commit:process.env.GITHUB_SHA,
  runId:Number(process.env.GITHUB_RUN_ID),runAttempt:Number(process.env.GITHUB_RUN_ATTEMPT??1),inputs,targets,results:[]};
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
async function until(description,read,seconds=180) {
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
    }
  }
}
async function server(target,phase,resource) {
  await save(target.profile+'-'+phase+'-cr.json',resource);apply(resource);
  const command=resource.spec.unsupported.podTemplate.spec.containers[0].command;
  if(command) {
    await until('Operator command reconciliation',()=>JSON.stringify(get('statefulset',target.profile)?.spec.template.spec.containers[0].command)===JSON.stringify(command));
    const old=get('pod',target.profile+'-0');
    if(old&&JSON.stringify(old.spec.containers[0].command)!==JSON.stringify(command)) kubectl(['delete','pod',old.metadata.name,'--wait=true','--timeout=60s']);
  }
  const outcome=await until(target.profile+' '+phase,()=>{
    const pod=get('pod',target.profile+'-0');
    if(JSON.stringify(pod?.spec.containers[0].command)!==JSON.stringify(command)) return null;
    const result=podOutcome(pod);
    if(result?.status==='infrastructure-error') throw Error(JSON.stringify(result));
    return result&&{...result,pod};
  });
  const result={profile:target.profile,phase,status:outcome.status,reason:outcome.reason,exitCode:outcome.exitCode,
    command:outcome.pod.spec.containers[0].command??null,args:outcome.pod.spec.containers[0].args,imageID:outcome.pod.status.containerStatuses?.[0]?.imageID};
  if(outcome.status==='ready'&&!result.imageID?.includes(target.digest)) throw Error('Native published child imageID mismatch');
  await snapshot(target.profile+'-'+phase);report.results.push(result);return result;
}
async function apiCheck(target) {
  const hostname=target.profile+'.keycloak.test',port=18443;
  const ca=await readFile(join(privateDir,'ca.crt'));
  const portForward=spawn('kubectl',['-n','keycloak','port-forward','pod/'+target.profile+'-0',port+':8443','--address=127.0.0.1'],{stdio:'ignore'});
  const forwardClosed=new Promise(resolve=>portForward.once('close',resolve));
  const request=(path,method='GET',body,token)=>new Promise((resolve,reject)=>{
    const req=https.request({hostname:'127.0.0.1',port,servername:hostname,ca,rejectUnauthorized:true,path,method,
      headers:{Host:hostname,...(body?{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)}:{}),...(token?{Authorization:'Bearer '+token}:{})}},response=>{
      const parts=[];response.on('data',part=>parts.push(part));response.on('end',()=>{
        try {resolve({status:response.statusCode,json:JSON.parse(Buffer.concat(parts).toString('utf8'))});}
        catch {reject(Error('Unexpected non-JSON HTTPS response, HTTP '+response.statusCode));}
      });
    });req.setTimeout(10000,()=>req.destroy(Error('HTTPS request timeout')));req.on('error',reject);req.end(body);
  });
  try {
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
  } finally {portForward.kill();await forwardClosed;}
}
async function restart(target) {
  const uid=get('pod',target.profile+'-0').metadata.uid;
  kubectl(['delete','pod',target.profile+'-0','--wait=true','--timeout=60s']);
  await until('Operator restart recovery',()=>{
    const pod=get('pod',target.profile+'-0');return pod?.metadata.uid!==uid&&podOutcome(pod)?.status==='ready';
  });
  await apiCheck(target);report.results.push({profile:target.profile,phase:'restart-recovery',status:'passed'});
}
async function realmImport(target) {
  const name=target.profile+'-realm-import';
  apply({apiVersion:'k8s.keycloak.org/v2beta1',kind:'KeycloakRealmImport',metadata:{name},spec:{keycloakCRName:target.profile,realm:{realm:'operator-'+target.profile,enabled:true}}});
  const result=await until('Realm Import execution',()=>{
    const job=get('job',name);if(!job) return null;
    const pods=get('pods').items.filter(pod=>pod.metadata.ownerReferences?.some(owner=>owner.uid===job.metadata.uid));
    const failure=pods.map(pod=>podOutcome(pod)).find(Boolean);
    if(failure?.status==='infrastructure-error') throw Error(JSON.stringify(failure));
    return job.status?.succeeded?{status:'completed',job}:failure?.status==='failed'?{...failure,job}:null;
  });
  await snapshot(name);
  const resultRecord={profile:target.profile,phase:'realm-import',status:result.status,command:result.job.spec.template.spec.containers[0].command,args:result.job.spec.template.spec.containers[0].args,message:result.message,reason:result.reason,exitCode:result.exitCode};
  if(result.status!=='completed'&&!JSON.stringify(result).includes('/opt/keycloak/bin/kc.sh')) throw Error('Unexpected Realm Import failure; inspect sanitized evidence');
  report.results.push(resultRecord);
}
async function updateCompatibility(resource,target) {
  resource.spec.update={strategy:'Auto'};resource.spec.additionalOptions.push({name:'log-level',value:'INFO'});apply(resource);
  const observed=await until('Auto compatibility job execution',()=>{
    const jobs=get('jobs').items.filter(job=>job.metadata.labels?.app==='keycloak-update-job');
    const job=jobs[0];if(!job) return null;
    const pod=get('pods').items.find(pod=>pod.metadata.ownerReferences?.some(owner=>owner.uid===job.metadata.uid));
    if(!pod) return null;
    const failure=podOutcome(pod);if(failure?.status==='infrastructure-error') throw Error(JSON.stringify(failure));
    return failure?.status==='failed'||job.status?.succeeded?{job,pod,failure}:null;
  });
  await snapshot(target.profile+'-auto-update');
  report.results.push({profile:target.profile,phase:'auto-update-compatibility',status:observed.job.status?.succeeded?'job-completed':'job-failed',
    initContainers:observed.job.spec.template.spec.initContainers.map(({command,args})=>({command,args})),
    containers:observed.job.spec.template.spec.containers.map(({command,args})=>({command,args})),failure:observed.failure,
    limitation:'A compatibility-job observation is not a successful rolling-upgrade test; rolling updates were not enabled at image build time.'});
}

let clusterCreated=false;
try {
  await Promise.all([
    download('https://github.com/kubernetes-sigs/kind/releases/download/v'+inputs.kind.version+'/kind-linux-'+architecture,'kind',inputs.kind[architecture]),
    download('https://dl.k8s.io/release/v'+inputs.kubectl.version+'/bin/linux/'+architecture+'/kubectl','kubectl',inputs.kubectl[architecture])
  ]);
  await save('versions.txt',call('podman',['version']).stdout+call('kind',['version']).stdout+call('kubectl',['version','--client','-o','json']).stdout);
  call('kind',['create','cluster','--name','operator-test','--image',inputs.node,'--kubeconfig',process.env.KUBECONFIG,'--wait','180s'],{timeout:480000});clusterCreated=true;
  await save('nodes.json',JSON.parse(call('kubectl',['get','nodes','-o','json']).stdout));
  if(!JSON.parse(call('kubectl',['get','nodes','-o','json']).stdout).items.every(node=>node.status.nodeInfo.architecture===architecture)) throw Error('Nonnative Kubernetes node');
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
    let resource=keycloakResource(target),result=await server(target,'default',resource);
    if(result.status!=='ready') {
      const logs=kubectl(['logs',target.profile+'-0','--tail=200'],{allowFailure:true}).stdout;
      if(!/Unknown option|Unmatched argument|kc\.sh|Could not find or load main class/.test(logs+JSON.stringify(result))) throw Error('Unexpected default deployment failure');
      resource=keycloakResource(target,true);result=await server(target,'direct-java-pod-template',resource);
      if(result.status!=='ready') throw Error('Direct Java podTemplate failed; inspect native evidence');
    }
    await apiCheck(target);await restart(target);await realmImport(target);
    if(target.profile==='core') await updateCompatibility(resource,target);
    kubectl(['delete','keycloakrealmimport',target.profile+'-realm-import','--ignore-not-found=true']);
    kubectl(['delete','keycloak',target.profile,'--wait=true','--timeout=60s']);
    kubectl(['delete','jobs','--all','--wait=true','--timeout=60s']);
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
