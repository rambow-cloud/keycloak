'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const catalog = import('../scripts/release-catalog.mjs');
const actions = { __typename: 'Bot', id: 'MDM6Qm90NDE4OTgyODI=' };
const codesmith = { __typename: 'Bot', id: 'BOT_kgDOCWWZcg' };
const canonical = '<!-- quay-catalog:v1 -->\n<!-- catalog-body:' + 'a'.repeat(64) + ' -->\n';
const footer = '<!-- codesmith:footer -->\n---\n<a href="https://app.blacksmith.sh/rambow-cloud/codesmith/keycloak/pr/23?ref=test">Review</a>\n<!-- /codesmith:footer -->';
const context = { repo: { owner: 'rambow-cloud', repo: 'keycloak' } };
function fixture(changes = {}) {
  const pr = { number: 23, body: canonical + '\n' + footer, head: { sha: 'b'.repeat(40) } };
  const current = { body: pr.body, headRefOid: pr.head.sha, editor: codesmith,
    userContentEdits: { totalCount: 2, pageInfo: { hasNextPage: false }, nodes: [{ editor: codesmith }, { editor: actions }] }, ...changes };
  const queries = [];
  const github = { graphql: async (query, variables) => { queries.push({ query, variables }); return { repository: { pullRequest: current } }; } };
  return { pr, current, context, github, queries };
}

test('only a complete known-bot audit can exclude the appended footer', async () => {
  const { canonicalCatalogBody } = await catalog;
  const f = fixture();
  assert.equal(await canonicalCatalogBody(f), canonical);
  assert.deepEqual(f.queries[0].variables, { owner: 'rambow-cloud', name: 'keycloak', number: 23 });
  assert.match(f.queries[0].query, /userContentEdits\(first:100\)/);
  assert.equal(await canonicalCatalogBody({ ...f, pr: { ...f.pr, body: canonical } }), canonical);
  assert.equal(f.queries.length, 1);
});

test('human, unknown and deleted editors block footer normalization even with spoofed bot IDs', async () => {
  const { canonicalCatalogBody } = await catalog;
  for (const editor of [{ __typename: 'User', id: actions.id }, { __typename: 'Bot', id: 'untrusted-bot' }, null]) {
    const f = fixture(); f.current.userContentEdits.nodes.push({ editor }); f.current.userContentEdits.totalCount++;
    await assert.rejects(canonicalCatalogBody(f), /pinned automation bots/);
  }
  for (const editor of [actions, { __typename: 'User', id: codesmith.id }, null]) {
    await assert.rejects(canonicalCatalogBody(fixture({ editor })), /pinned automation bots/);
  }
});

test('audit races and incomplete or missing history fail closed', async () => {
  const { canonicalCatalogBody } = await catalog;
  for (const changes of [{ body: 'concurrent edit' }, { headRefOid: 'c'.repeat(40) },
    { userContentEdits: null }, { userContentEdits: { totalCount: 0, nodes: [], pageInfo: { hasNextPage: false } } },
    { userContentEdits: { totalCount: 3, nodes: [{ editor: codesmith }], pageInfo: { hasNextPage: false } } },
    { userContentEdits: { totalCount: 1, nodes: [{ editor: codesmith }], pageInfo: { hasNextPage: true } } }]) {
    await assert.rejects(canonicalCatalogBody(fixture(changes)), /pinned automation bots/);
  }
  const f = fixture(); f.github.graphql = async () => { throw new Error('audit unavailable'); };
  await assert.rejects(canonicalCatalogBody(f), /audit unavailable/);
});

test('extra content, other PR links, repeated, malformed and oversized footers are not ignored', async () => {
  const { canonicalCatalogBody } = await catalog;
  for (const suffix of [footer + '\nhuman edit', footer.replace('/pr/23?', '/pr/24?'), footer + '\n' + footer,
    footer.replace('<!-- /codesmith:footer -->', ''), footer.replace('Review', 'x'.repeat(9000)),
    footer.replace('Review', '<!-- catalog-head:spoof -->')]) {
    const f = fixture(); f.pr.body = canonical + '\n' + suffix;
    await assert.rejects(canonicalCatalogBody(f), /Unexpected catalog footer/);
    assert.equal(f.queries.length, 0);
  }
});
