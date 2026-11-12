import https from 'node:https';
let stopped=false,configuration;
process.on('message',async message=>{
  if(message.type==='stop') {stopped=true;return;}
  if(message.type!=='start'||configuration) return;
  configuration=message.configuration;
  const {hostname,ca,username,password,realm,clientId}=configuration;
  const stats={startedAt:new Date().toISOString(),rounds:0,requests:0,login:0,refresh:0,userinfo:0,failures:[],maxLatencyMs:0};
  const request=(path,body,token)=>new Promise((resolve,reject)=>{
    const start=Date.now();
    const req=https.request({hostname:'127.0.0.1',port:18443,servername:hostname,ca,rejectUnauthorized:true,path,method:body?'POST':'GET',
      headers:{Host:hostname,...(body?{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(body)}:{}),...(token?{Authorization:'Bearer '+token}:{})}},response=>{
      const parts=[];response.on('data',part=>parts.push(part));response.on('end',()=>{
        stats.requests++;stats.maxLatencyMs=Math.max(stats.maxLatencyMs,Date.now()-start);
        if(response.statusCode!==200) return reject(Error('HTTP '+response.statusCode+' '+path));
        try {resolve(JSON.parse(Buffer.concat(parts).toString('utf8')));}catch {reject(Error('Non-JSON response'));}
      });
    });req.setTimeout(5000,()=>req.destroy(Error('Request timeout')));
    req.on('error',error=>reject(Error(error.message+'; '+(body?'POST':'GET')+' '+path+'; code='+(error.code??'unknown')+'; reusedSocket='+req.reusedSocket)));
    req.end(body);
  });
  const endpoint='/realms/'+realm+'/protocol/openid-connect/';
  let session;
  while(!stopped) {
    try {
      const login=await request(endpoint+'token',new URLSearchParams({client_id:clientId,grant_type:'password',username,password,scope:'openid'}).toString());stats.login++;
      if(!session) session=login;
      session=await request(endpoint+'token',new URLSearchParams({client_id:clientId,grant_type:'refresh_token',refresh_token:session.refresh_token}).toString());stats.refresh++;
      const user=await request(endpoint+'userinfo',undefined,session.access_token);stats.userinfo++;
      if(user.preferred_username!==username) throw Error('Session identity changed');
      stats.rounds++;
      if(stats.rounds===1) process.send({type:'ready'});
    }catch(error){stats.failures.push({at:new Date().toISOString(),message:error.message});stopped=true;}
    if(!stopped) await new Promise(resolve=>setTimeout(resolve,250));
  }
  stats.finishedAt=new Date().toISOString();process.send({type:'finished',stats},()=>process.exit(stats.failures.length?1:0));
});
