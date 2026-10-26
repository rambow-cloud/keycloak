'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFile } = require('node:fs/promises');
const auth = import('../scripts/lib/quay-auth.mjs');
const context = { repo: { owner: 'rambow-cloud', repo: 'keycloak' }, eventName: 'release', ref: 'refs/tags/v26.8.1-r1' };
const now = 1800000000000;
const token = claims => 'header.' + Buffer.from(JSON.stringify(claims)).toString('base64url') + '.signature';
async function fixture(overrides = {}, options = {}) {
  const { federatedQuayCredentials, quayAudience, quaySubject } = await auth;
  const masks = [], requests = [], audiences = [];
  const ctx = options.context ?? context;
  const claims = { iss: 'https://token.actions.githubusercontent.com', sub: quaySubject, aud: quayAudience,
    exp: now / 1000 + 300, ref: ctx.ref, event_name: ctx.eventName, ...overrides };
  const oidc = token(claims);
  const args = { username: 'rambow-cloud+github_keycloak', context: ctx, now: () => now,
    mask: value => masks.push(value), getIDToken: async audience => { audiences.push(audience); return oidc; },
    fetchImpl: async (...args) => { requests.push(args); return Response.json({ token: 'temporary-quay-credential' }); }, ...options };
  return { invoke: () => federatedQuayCredentials(args), args, masks, requests, audiences, oidc };
}

test('formal publication and main recovery exchange explicit-audience OIDC with masked credentials', async () => {
  for (const ctx of [context, { ...context, eventName: 'workflow_dispatch', ref: 'refs/heads/main' }]) {
    const f = await fixture({}, { context: ctx });
    assert.deepEqual(await f.invoke(), { username: f.args.username, token: 'temporary-quay-credential' });
    assert.deepEqual(f.audiences, ['https://quay.io']);
    const [url, options] = f.requests[0];
    assert.equal(url, 'https://quay.io/oauth2/federation/robot/token');
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal instanceof AbortSignal);
    const encoded = options.headers.Authorization.slice('Basic '.length);
    assert.equal(Buffer.from(encoded, 'base64').toString(), f.args.username + ':' + f.oidc);
    assert.deepEqual(f.masks, [f.oidc, encoded, 'temporary-quay-credential']);
  }
});

test('fork, PR, manual branch and invalid robot contexts cannot request credentials', async () => {
  for (const options of [
    { context: { ...context, repo: { owner: 'fork', repo: 'keycloak' } } },
    { context: { ...context, eventName: 'pull_request', ref: 'refs/pull/1/merge' } },
    { context: { ...context, eventName: 'workflow_dispatch', ref: 'refs/heads/feature' } },
    { context: { ...context, ref: 'refs/tags/latest' } },
    { username: 'another-org+robot' }, { getIDToken: undefined }, { mask: undefined },
  ]) {
    const f = await fixture({}, options);
    await assert.rejects(f.invoke());
    assert.equal(f.audiences.length, 0);
    assert.equal(f.requests.length, 0);
  }
});

test('wrong audience, subject, issuer, expired token and mismatched run are rejected before exchange', async () => {
  for (const claims of [ { aud: 'https://github.com/rambow-cloud' }, { sub: 'repo:rambow-cloud/keycloak:ref:refs/heads/main' },
    { iss: 'https://untrusted.example' }, { exp: now / 1000 + 10 }, { ref: 'refs/heads/feature' }, { event_name: 'pull_request' } ]) {
    const f = await fixture(claims);
    await assert.rejects(f.invoke(), /claims do not match/);
    assert.equal(f.requests.length, 0);
  }
  const f = await fixture({ aud: ['other', 'https://quay.io'] });
  await f.invoke();
});

test('OIDC service failure and malformed JWTs expose no credential-bearing error details', async () => {
  for (const getIDToken of [async () => { throw new Error('private-service-response'); }, async () => 'not-a-jwt',
    async () => 'header.bm90LWpzb24.signature']) {
    const f = await fixture({}, { getIDToken });
    await assert.rejects(f.invoke(), error => !error.message.includes('private-service-response') && /OIDC/.test(error.message));
    assert.equal(f.requests.length, 0);
  }
});

test('Quay authorization, redirect and network failures are sanitized and never retried', async () => {
  for (const status of [301, 401, 403, 500]) {
    let calls = 0;
    const f = await fixture({}, { fetchImpl: async () => { calls++; return new Response('credential-in-error-body', { status }); } });
    await assert.rejects(f.invoke(), error => error.message.includes('HTTP ' + status) && !error.message.includes('credential-in-error-body'));
    assert.equal(calls, 1);
  }
  const f = await fixture({}, { fetchImpl: async (_url, options) => {
    assert.equal(options.redirect, 'error');
    throw new Error('Authorization: private-header');
  } });
  await assert.rejects(f.invoke(), error => /network, TLS or redirect/.test(error.message) && !error.message.includes('private-header'));
});

test('Quay malformed, missing, oversized and unsafe tokens fail closed', async () => {
  for (const value of ['not-json', JSON.stringify({}), JSON.stringify({ token: '' }), JSON.stringify({ token: 'unsafe\nvalue' }),
    JSON.stringify({ token: 'x'.repeat(17000) }), JSON.stringify({ token: 'x'.repeat(70000) }), 'null']) {
    const f = await fixture({}, { fetchImpl: async () => new Response(value) });
    await assert.rejects(f.invoke(), /Quay federation/);
  }
});

test('only protected publisher gets OIDC; no static secret, token output or environment persistence', async () => {
  const workflow = await readFile(require('node:path').join(__dirname, '../.github/workflows/release.yml'), 'utf8');
  const publisher = workflow.slice(workflow.indexOf('\n  publish:'), workflow.indexOf('\n  audit:'));
  assert.equal((workflow.match(/id-token: write/g) ?? []).length, 1);
  assert.match(publisher, /id-token: write/);
  assert.match(publisher, /environment: quay-release/);
  assert.match(publisher, /vars\.QUAY_USERNAME/);
  assert.doesNotMatch(workflow, /secrets\.QUAY_|QUAY_TOKEN|GITHUB_ENV/);
  const module = await import('../scripts/release-image.mjs');
  assert.equal(typeof module.publishReleaseImages, 'function');
});
