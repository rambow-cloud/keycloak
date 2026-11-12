export function keycloakResource(target) {
  const profile=target.profile;
  const container={name:'keycloak',volumeMounts:[{name:'database-ca',mountPath:'/etc/keycloak-test',readOnly:true}],
    imagePullPolicy:'Never',securityContext:{runAsNonRoot:true,runAsUser:65532,runAsGroup:65532,readOnlyRootFilesystem:true,allowPrivilegeEscalation:false,capabilities:{drop:['ALL']}}};
  container.volumeMounts.push({name:'keycloak-data',mountPath:'/opt/keycloak/data'},{name:'temporary',mountPath:'/tmp'});
  const podSpec={containers:[container],volumes:[{name:'database-ca',secret:{secretName:'database-ca'}},{name:'keycloak-data',emptyDir:{}},{name:'temporary',emptyDir:{}}],
    securityContext:{fsGroup:65532,fsGroupChangePolicy:'OnRootMismatch'}};
  const url=(profile==='aws'?'jdbc:aws-wrapper:postgresql':'jdbc:postgresql')+'://postgres:5432/keycloak_'+profile+(profile==='aws'?'?wrapperPlugins=':'');
  return {apiVersion:'k8s.keycloak.org/v2beta1',kind:'Keycloak',metadata:{name:profile,namespace:'keycloak'},spec:{
    instances:2,image:target.reference,startOptimized:true,update:{strategy:'Auto'},
    db:{vendor:'postgres',host:'postgres',database:'keycloak_'+profile,usernameSecret:{name:'database-auth',key:'username'},passwordSecret:{name:'database-auth',key:'password'}},
    http:{tlsSecret:'server-tls'},hostname:{hostname:'https://'+profile+'.keycloak.test'},ingress:{enabled:false},
    resources:{requests:{cpu:'250m',memory:'768Mi'},limits:{cpu:'2',memory:'1536Mi'}},
    additionalOptions:[{name:'db-url',value:url},{name:'db-tls-mode',value:'verify-server'},{name:'db-tls-trust-store-file',value:'/etc/keycloak-test/ca.crt'}],
    unsupported:{podTemplate:{spec:podSpec}}
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
  return '# Native Go launcher Operator integration ('+report.architecture+')\n\n'+
    'Source: `'+report.commit+'`; branch: `'+report.branch+'`; run: '+report.runId+', attempt '+report.runAttempt+'.\n\n'+
    '| Profile | Phase | Result |\n| --- | --- | --- |\n'+report.results.map(result=>'| '+result.profile+' | '+result.phase+' | '+result.status+' |').join('\n')+
    '\n\n'+(report.error?'Experiment error: '+report.error.replaceAll('|','\\|')+'\n\n':'')+
    'Experiment: '+(report.experiment??'same-version-image-replacement')+'. Exact native CI destination artifacts were loaded into disposable kind without registry publication. Historical upgrade sources retain published layers plus the same native launcher only; their reported CVEs do not make them publishable. Stock Operator commands were used; podTemplate changes only supplied test image-pull policy, volumes and security context. Two replicas on one node do not certify production HA or cloud database behavior.\n';
}
