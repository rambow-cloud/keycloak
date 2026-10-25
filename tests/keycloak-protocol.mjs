// Protocol-level tests run outside the production image. They create and remove an isolated test realm.
import { randomUUID, randomBytes, createPublicKey, verify } from 'node:crypto';
import assert from 'node:assert/strict';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

export async function verifyKeycloak({ baseUrl, managementUrl, username, password, durationSeconds = 0 }) {
  const base = baseUrl.replace(/\/$/, '');
  const realm = 'verify-' + randomUUID();
  const clientId = 'verification-client';
  const clientSecret = randomBytes(32).toString('hex');
  let adminToken;
  let expires = 0;
  let created = false;
  async function request(path, options = {}) {
    const response = await fetch(base + path, { ...options, signal: AbortSignal.timeout(15000) });
    // Do not print response bodies, tokens, or credential-bearing request data.
    if (!response.ok) throw new Error('Keycloak request failed: ' + options.method + ' ' + path + ' (' + response.status + ')');
    return response;
  }
  async function admin(path, method, data) {
    if (Date.now() >= expires) {
      const response = await request('/realms/master/protocol/openid-connect/token', {
        method: 'POST', body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username, password }),
      });
      const token = await response.json();
      adminToken = token.access_token;
      expires = Date.now() + Math.max(1, token.expires_in - 5) * 1000;
    }
    return request(path, { method, headers: { Authorization: 'Bearer ' + adminToken, 'Content-Type': 'application/json' },
      body: data === undefined ? undefined : JSON.stringify(data) });
  }
  if (managementUrl) {
    let ready = false;
    for (let attempt = 0; attempt < 90; attempt++) {
      try {
        const response = await fetch(managementUrl.replace(/\/$/, '') + '/health/ready', { signal: AbortSignal.timeout(3000) });
        if (response.ok && (await response.json()).status === 'UP') { ready = true; break; }
      } catch { /* Startup polling, not repeated functional verification. */ }
      await delay(2000);
    }
    assert(ready, 'Keycloak did not become ready');
  }
  try {
    await admin('/admin/realms', 'POST', { realm, enabled: true });
    created = true;
    await admin('/admin/realms/' + realm + '/clients', 'POST', {
      clientId, secret: clientSecret, enabled: true, publicClient: false, serviceAccountsEnabled: true, standardFlowEnabled: false,
    });
    const issuer = base + '/realms/' + realm;
    const discovery = await (await request('/realms/' + realm + '/.well-known/openid-configuration')).json();
    assert.equal(discovery.issuer, issuer);
    const jwks = await (await request('/realms/' + realm + '/protocol/openid-connect/certs')).json();
    const start = Date.now();
    let rounds = 0;
    do {
      const user = 'probe-' + randomUUID();
      // Writes force database work; cached token issuance alone cannot demonstrate reconnection.
      const createdUser = await admin('/admin/realms/' + realm + '/users', 'POST', { username: user, enabled: true });
      const location = createdUser.headers.get('location');
      assert(location, 'User creation did not return a location');
      await admin('/admin/realms/' + realm + '/users/' + location.split('/').pop(), 'DELETE');
      const response = await request('/realms/' + realm + '/protocol/openid-connect/token', {
        method: 'POST', body: new URLSearchParams({ grant_type: 'client_credentials', client_id: clientId, client_secret: clientSecret }),
      });
      const { access_token: accessToken } = await response.json();
      const [header64, payload64, signature64] = accessToken.split('.');
      const header = JSON.parse(Buffer.from(header64, 'base64url'));
      const claims = JSON.parse(Buffer.from(payload64, 'base64url'));
      assert.equal(header.alg, 'RS256');
      const key = jwks.keys.find(k => k.kid === header.kid && k.use === 'sig');
      assert(key, 'Signing key missing from JWKS');
      assert(verify('RSA-SHA256', Buffer.from(header64 + '.' + payload64), createPublicKey({ key, format: 'jwk' }), Buffer.from(signature64, 'base64url')));
      assert.equal(claims.iss, issuer);
      assert.equal(claims.azp, clientId);
      assert(claims.exp > Date.now() / 1000);
      rounds++;
      if (Date.now() - start >= durationSeconds * 1000) break;
      await delay(Math.min(30000, durationSeconds * 1000 - (Date.now() - start)));
    } while (true);
    console.log('Passed realm creation, database writes, discovery, and signed client-credentials tokens (' + rounds + ' rounds).');
  } finally {
    if (created) await admin('/admin/realms/' + realm, 'DELETE');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await verifyKeycloak({ baseUrl: process.env.VERIFY_BASE_URL, managementUrl: process.env.VERIFY_MANAGEMENT_URL,
    username: process.env.VERIFY_ADMIN_USERNAME, password: process.env.VERIFY_ADMIN_PASSWORD });
}
