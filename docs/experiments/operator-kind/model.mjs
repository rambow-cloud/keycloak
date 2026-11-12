export function publishedTargets(record,inputs,architecture) {
  if(record.plan.tag!==inputs.release||record.plan.keycloakVersion!==inputs.keycloakVersion||!['amd64','arm64'].includes(architecture)) throw Error('Experiment publication identity mismatch');
  return ['core','aws'].map(profile=>{
    const image=record.plan.images.find(image=>image.profile===profile);
    const children=image?.children?.filter(child=>child.architecture===architecture);
    if(children?.length!==1||!/^sha256:[a-f0-9]{64}$/.test(children[0].digest)) throw Error('Missing unique published native child');
    return {profile,index:image.digest,digest:children[0].digest,reference:'quay.io/rambow-cloud/keycloak@'+children[0].digest};
  });
}

export function keycloakResource(target,javaOverride=false) {
  const profile=target.profile;
  const container={name:'keycloak',volumeMounts:[{name:'database-ca',mountPath:'/etc/keycloak-test',readOnly:true}],
    securityContext:{runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,allowPrivilegeEscalation:false,capabilities:{drop:['ALL']}}};
  if(javaOverride) {
    // Keep Operator-added -D arguments before the Java main class.
    container.command=['/usr/bin/java','@/opt/keycloak/java.options'];
    container.args=['-cp','/opt/keycloak/lib/quarkus-run.jar','io.quarkus.bootstrap.runner.QuarkusEntryPoint','--verbose','start'];
  }
  const url=(profile==='aws'?'jdbc:aws-wrapper:postgresql':'jdbc:postgresql')+'://postgres:5432/keycloak_'+profile+(profile==='aws'?'?wrapperPlugins=':'');
  return {apiVersion:'k8s.keycloak.org/v2beta1',kind:'Keycloak',metadata:{name:profile,namespace:'keycloak'},spec:{
    instances:1,image:target.reference,startOptimized:true,
    db:{vendor:'postgres',host:'postgres',database:'keycloak_'+profile,usernameSecret:{name:'database-auth',key:'username'},passwordSecret:{name:'database-auth',key:'password'}},
    http:{tlsSecret:'server-tls'},hostname:{hostname:'https://'+profile+'.keycloak.test'},ingress:{enabled:false},
    resources:{requests:{cpu:'250m',memory:'768Mi'},limits:{cpu:'2',memory:'1536Mi'}},
    additionalOptions:[{name:'db-url',value:url},{name:'db-tls-mode',value:'verify-server'},{name:'db-tls-trust-store-file',value:'/etc/keycloak-test/ca.crt'}],
    unsupported:{podTemplate:{spec:{containers:[container],volumes:[{name:'database-ca',secret:{secretName:'database-ca'}}]}}}
  }};
}

export function podOutcome(pod) {
  if(pod?.status?.conditions?.some(condition=>condition.type==='Ready'&&condition.status==='True')) return {status:'ready'};
  for(const container of [...pod?.status?.initContainerStatuses??[],...pod?.status?.containerStatuses??[]]) {
    const state=container.state??{};
    const termination=state.terminated??container.lastState?.terminated;
    if(termination&&termination.exitCode!==0) return {status:'failed',container:container.name,exitCode:termination.exitCode,message:termination.message??'',reason:termination.reason};
    if(['ErrImagePull','ImagePullBackOff','InvalidImageName'].includes(state.waiting?.reason)) return {status:'infrastructure-error',reason:state.waiting.reason,message:state.waiting.message};
    if(['RunContainerError','CreateContainerError','StartError'].includes(state.waiting?.reason)) return {status:'failed',container:container.name,...state.waiting};
  }
  return null;
}

export function redact(text,secrets) {
  let result=String(text);
  for(const value of [...secrets].filter(value=>value.length>=8).sort((a,b)=>b.length-a.length)) {
    result=result.split(value).join('[REDACTED]').split(Buffer.from(value).toString('base64')).join('[REDACTED]');
  }
  return result;
}

export function markdown(report) {
  return '# Keycloak Operator experiment ('+report.architecture+')\n\n'+
    'Source: `'+report.commit+'`; branch: `'+report.branch+'`; run: '+report.runId+', attempt '+report.runAttempt+'.\n\n'+
    '| Profile | Phase | Result |\n| --- | --- | --- |\n'+report.results.map(result=>'| '+result.profile+' | '+result.phase+' | '+result.status+' |').join('\n')+
    '\n\n'+(report.error?'Experiment error: '+report.error.replaceAll('|','\\|')+'\n\n':'')+
    'Published images were reused without rebuilding or pushing. The podTemplate workaround is unsupported upstream. Single-node kind results do not establish production, HA, cloud/RDS, FIPS, realm-import or rolling-upgrade compatibility beyond the individually recorded observations. No vulnerability scan was run by this experiment.\n';
}
