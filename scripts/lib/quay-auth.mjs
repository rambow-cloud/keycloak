export const quayAudience = 'https://quay.io';
export const quaySubject = 'repo:rambow-cloud@333554680/keycloak@1433566126:environment:quay-release';
const issuer = 'https://token.actions.githubusercontent.com';
const endpoint = 'https://quay.io/oauth2/federation/robot/token';

// Skopeo delete requests wildcard actions by default. Quay deletion needs only
// repository pull/push; provide that bounded bearer rather than widening rights.
export async function quayRegistryWriteToken({credentials,mask,fetchImpl=fetch}) {
  if(!/^rambow-cloud\+[a-z0-9_]+$/.test(credentials?.username??'')||typeof credentials?.token!=='string'||credentials.token.length>16384||! /^[\x21-\x7e]+$/.test(credentials.token)||typeof mask!=='function') throw Error('Valid transient Quay robot credentials and masking are required');
  mask(credentials.token);
  const basic=Buffer.from(credentials.username+':'+credentials.token).toString('base64');mask(basic);
  const url=new URL('https://quay.io/v2/auth');
  url.searchParams.set('service','quay.io');
  url.searchParams.set('scope','repository:rambow-cloud/keycloak:pull,push');
  let response;
  try {response=await fetchImpl(url.href,{method:'GET',headers:{Authorization:'Basic '+basic,Accept:'application/json'},redirect:'error',signal:AbortSignal.timeout(20000)});}
  catch {throw Error('Quay bounded registry-token request failed');}
  if(!response.ok) {await response.body?.cancel();throw Error('Quay bounded registry-token request denied (HTTP '+response.status+')');}
  let body;
  try {
    const reader=response.body.getReader(),chunks=[];let size=0;
    while(true) {const {done,value}=await reader.read();if(done) break;size+=value.byteLength;if(size>65536) {await reader.cancel();throw Error('oversized');}chunks.push(Buffer.from(value));}
    body=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {throw Error('Quay registry-token response is invalid or oversized');}
  if(typeof body?.token==='string'&&body.token.length) mask(body.token);
  if(typeof body?.token!=='string'||body.token.length>16384||! /^[\x21-\x7e]+$/.test(body.token)) throw Error('Quay registry bearer is invalid');
  return body.token;
}

// Quay verifies the JWT signature. These local checks catch a wrong job/context
// before sending its token to the exchange endpoint; they do not replace verification.
export async function federatedQuayCredentials({ username, context, getIDToken, mask,
  fetchImpl = fetch, now = () => Date.now() }) {
  if (!/^rambow-cloud\+[a-z0-9_]+$/.test(username ?? '')) throw new Error('Configure the repository-scoped Quay robot as Environment variable QUAY_USERNAME.');
  if (context?.repo?.owner !== 'rambow-cloud' || context?.repo?.repo !== 'keycloak' ||
      !(context.eventName === 'workflow_dispatch' && context.ref === 'refs/heads/main' ||
        context.eventName === 'release' && /^refs\/tags\/v\d+\.\d+\.\d+-r[1-9]\d*$/.test(context.ref))) {
    throw new Error('Quay federation is limited to formal releases and main recovery.');
  }
  if (typeof getIDToken !== 'function' || typeof mask !== 'function') throw new Error('GitHub OIDC and secret masking are required. Static-token fallback is disabled.');
  let oidc;
  try { oidc = await getIDToken(quayAudience); }
  catch { throw new Error('GitHub OIDC request failed; the publisher requires id-token: write.'); }
  if (typeof oidc !== 'string' || oidc.length > 16384 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(oidc)) throw new Error('GitHub returned an invalid OIDC token.');
  mask(oidc);
  let claims;
  try { claims = JSON.parse(Buffer.from(oidc.split('.')[1], 'base64url').toString('utf8')); }
  catch { throw new Error('GitHub returned invalid OIDC claims.'); }
  if (claims.iss !== issuer || claims.sub !== quaySubject ||
      !(claims.aud === quayAudience || Array.isArray(claims.aud) && claims.aud.includes(quayAudience)) ||
      claims.ref !== context.ref || claims.event_name !== context.eventName ||
      !Number.isFinite(claims.exp) || claims.exp * 1000 <= now() + 30000) {
    throw new Error('GitHub OIDC claims do not match the Quay audience, immutable environment subject or release context.');
  }
  const authorization = Buffer.from(username + ':' + oidc).toString('base64');
  mask(authorization);
  let response;
  try {
    response = await fetchImpl(endpoint, { method: 'GET', headers: { Authorization: 'Basic ' + authorization, Accept: 'application/json' },
      redirect: 'error', signal: AbortSignal.timeout(20000) });
  } catch { throw new Error('Quay federation request failed (network, TLS or redirect).'); }
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error('Quay federation denied (HTTP ' + response.status + '). Check robot permissions, issuer, subject and audience.');
  }
  let body;
  try {
    const reader = response.body.getReader();
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 65536) { await reader.cancel(); throw new Error('oversized response'); }
      chunks.push(Buffer.from(value));
    }
    body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch { throw new Error('Quay federation returned an invalid or oversized response.'); }
  if (typeof body?.token === 'string' && body.token.length > 0) mask(body.token);
  if (typeof body?.token !== 'string' || body.token.length > 16384 || !/^[\x21-\x7e]+$/.test(body.token)) throw new Error('Quay federation did not return a valid short-lived robot token.');
  return { username, token: body.token };
}
