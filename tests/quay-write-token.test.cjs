const {test}=require('node:test');
const assert=require('node:assert/strict');
const lib=import('../scripts/lib/quay-auth.mjs');
const credentials={username:'rambow-cloud+github_keycloak',token:'transient-password'};
test('registry deletion token uses only the fixed Quay repository pull/push scope and masks all credentials',async()=>{
 const {quayRegistryWriteToken}=await lib,masks=[];
 const token=await quayRegistryWriteToken({credentials,mask:s=>masks.push(s),fetchImpl:async(url,options)=>{
  const parsed=new URL(url);assert.equal(parsed.origin+parsed.pathname,'https://quay.io/v2/auth');
  assert.equal(parsed.searchParams.get('service'),'quay.io');assert.equal(parsed.searchParams.get('scope'),'repository:rambow-cloud/keycloak:pull,push');
  assert.equal(options.method,'GET');assert.equal(options.redirect,'error');assert(options.signal instanceof AbortSignal);
  assert.equal(options.headers.Authorization,'Basic '+Buffer.from(credentials.username+':'+credentials.token).toString('base64'));
  return new Response(JSON.stringify({token:'bounded-bearer'}));
 }});
 assert.equal(token,'bounded-bearer');assert(masks.includes(credentials.token));assert(masks.includes(Buffer.from(credentials.username+':'+credentials.token).toString('base64')));assert(masks.includes(token));
});
test('registry bearer requests fail closed for network errors, denials and malformed/oversized responses',async()=>{
 const {quayRegistryWriteToken}=await lib;
 for(const response of [new Response('',{status:401}),new Response('',{status:403}),new Response('not-json'),new Response(JSON.stringify({token:''})),new Response(JSON.stringify({token:'bad\nvalue'})),new Response('x'.repeat(65537))]) {
  await assert.rejects(quayRegistryWriteToken({credentials,mask:()=>{},fetchImpl:async()=>response}),/Quay/);
 }
 await assert.rejects(quayRegistryWriteToken({credentials,mask:()=>{},fetchImpl:async()=>{throw Error('network');}}),/request failed/);
});
test('invalid identities and missing masking cannot initiate a token request',async()=>{
 const {quayRegistryWriteToken}=await lib;let requests=0;
 for(const candidate of [{username:'another-org+robot',token:'x'},{...credentials,token:'\n'},{...credentials,token:''}]) await assert.rejects(quayRegistryWriteToken({credentials:candidate,mask:()=>{},fetchImpl:async()=>{requests++;}}));
 await assert.rejects(quayRegistryWriteToken({credentials,fetchImpl:async()=>{requests++;}}));assert.equal(requests,0);
});
