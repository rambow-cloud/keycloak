'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { validateIssue, checkDispatchedPullRequest } = require('../scripts/issue-policy.cjs');
const lib = import('../scripts/lib/upstream.mjs');
const bot = { login: 'github-actions[bot]' };
const mainSha = 'a'.repeat(40);
const headSha = 'b'.repeat(40);
// Fixed historical fixtures: later real version bumps must not change these behavioral cases.
const pinned = ref => ref + '@sha256:' + 'a'.repeat(64);
const lock = { keycloakVersion: '26.8.1', javaVersion: 25, platform: 'linux/amd64',
  keycloak: pinned('quay.io/keycloak/keycloak:26.8.1'), runtime: pinned('gcr.io/distroless/java25-debian13:nonroot'),
  builder: pinned('docker.io/library/eclipse-temurin:25-jdk-noble'), postgres: pinned('docker.io/library/postgres:17-bookworm'),
  awsDependencies: { wrapperVersion: '4.5.0', lockFile: 'dependencies/aws/dependencies.lock.json' } };
const baseFiles = { 'images.lock.json': JSON.stringify(lock, null, 2) + '\n', 'README.md': 'Keycloak 26.8.1\n',
  'AGENTS.md': 'Keycloak 26.8.1\n', 'config/java.options': '# Aligned with Keycloak 26.8.1\n',
  'config/upstream-compatibility.json': JSON.stringify({ javaMajor: 25 }) };

test('OCI resolver authenticates and verifies actual manifest bytes', async () => {
  const { resolveImageDigest } = await import('../scripts/lib/oci.mjs');
  const { sha256 } = await lib;
  const manifest = JSON.stringify({ schemaVersion: 2, manifests: [] });
  const calls = [];
  const fetcher = async (url, options) => {
    calls.push(String(url));
    if (calls.length === 1) return new Response('', { status: 401, headers: { 'www-authenticate': 'Bearer realm="https://auth.example/token",service="registry",scope="repository:library/test:pull"' } });
    if (calls.length === 2) return Response.json({ access_token: 'test-token' });
    assert.equal(options.headers.Authorization, 'Bearer test-token');
    return new Response(manifest, { headers: { 'docker-content-digest': 'sha256:' + sha256(manifest) } });
  };
  assert.equal(await resolveImageDigest('docker.io/library/test:25', fetcher), 'docker.io/library/test:25@sha256:' + sha256(manifest));
  assert.equal(new URL(calls[1]).searchParams.get('scope'), 'repository:library/test:pull');
  await assert.rejects(resolveImageDigest('gcr.io/distroless/test:nonroot', async () => new Response(manifest, { headers: { 'docker-content-digest': 'sha256:wrong' } })), /digest mismatch/);
  await assert.rejects(resolveImageDigest('gcr.io/distroless/test:nonroot', async () => Response.json({ schemaVersion: 1 })), /Invalid OCI/);
  await assert.rejects(resolveImageDigest('untrusted.example/test:tag', fetcher), /unapproved/);
  await assert.rejects(resolveImageDigest('gcr.io/distroless/test:nonroot', async () => new Response('', { status: 401, headers: { 'www-authenticate': 'Bearer realm="http://insecure/token"' } })), /HTTPS/);
});

test('release selection ignores prereleases and never downgrades across release lines', async () => {
  const { chooseVersion } = await lib;
  for (const release of [{ tag_name: '26.8.0' }, { tag_name: '26.7.99' }, { tag_name: '27.0.0', prerelease: true }, { tag_name: '27.0.0-RC1' }, { tag_name: '27.0.0', draft: true }]) assert.equal(chooseVersion('26.8.1', release), '26.8.1');
  assert.equal(chooseVersion('26.8.1', { tag_name: '26.8.10' }), '26.8.10');
  assert.equal(chooseVersion('26.8.1', { tag_name: '27.0.0' }), '27.0.0');
});

test('compatibility fails closed for changed launcher, newer LTS, or unrecognized support docs', async () => {
  const { sha256, inspectCompatibility } = await lib;
  const baseline = { javaMajor: 25, startupScriptSha256: sha256('reviewed launcher') };
  const inspect = (startup, docs) => inspectCompatibility('26.8.1', 25, baseline, async url => new Response(url.endsWith('kc.sh') ? startup : docs));
  assert.deepEqual((await inspect('reviewed launcher', '* OpenJDK 21 (LTS)\n* OpenJDK 25 (LTS)')).warnings, []);
  assert.match((await inspect('new launcher', '* OpenJDK 25 (LTS)')).warnings.join(), /kc.sh/);
  assert.match((await inspect('reviewed launcher', '* OpenJDK 25 (LTS)\n* OpenJDK 29 (LTS)')).warnings.join(), /latest supported Java LTS is 29/);
  assert.match((await inspect('reviewed launcher', 'format changed')).warnings.join(), /Cannot determine/);
});

test('candidate preserves unrelated locks and auto-merge excludes larger or incompatible upgrades', async () => {
  const { candidateFiles, autoMergeEligible, issueBody } = await lib;
  const next = { ...lock, keycloakVersion: '26.8.2', keycloak: 'quay.io/keycloak/keycloak:26.8.2@sha256:new' };
  const files = candidateFiles(baseFiles, next, []);
  assert.deepEqual(JSON.parse(files['images.lock.json']).awsDependencies, lock.awsDependencies);
  assert.equal(JSON.parse(files['images.lock.json']).postgres, lock.postgres);
  assert.match(files['config/java.options'], /26\.8\.2/);
  assert.equal(candidateFiles(baseFiles, next, ['review required'])['config/java.options'], baseFiles['config/java.options']);
  assert.equal(autoMergeEligible(lock, next, []), true);
  assert.equal(autoMergeEligible(lock, { ...next, keycloakVersion: '26.9.0' }, []), false);
  assert.equal(autoMergeEligible(lock, { ...next, javaVersion: 29 }, []), false);
  assert.equal(autoMergeEligible(lock, { ...next, runtime: 'gcr.io/distroless/java29-debian13:nonroot@sha256:new' }, []), false);
  assert.equal(autoMergeEligible(lock, next, ['launcher changed']), false);
  validateIssue({ number: 11, state: 'open', title: '[Maintenance]: Refresh images', body: issueBody() });
});

test('generated PR guards refuse edited bodies, files, or commits', async () => {
  const { pullBody, assertBotOwned } = await lib;
  const body = pullBody(11, lock, lock, baseFiles, [], headSha);
  const pr = { user: bot, body };
  const commit = { author: bot, sha: headSha };
  assertBotOwned(pr, commit, baseFiles);
  assert.throws(() => assertBotOwned({ ...pr, body: body + 'human note' }, commit, baseFiles), /edited/);
  assert.throws(() => assertBotOwned(pr, commit, { ...baseFiles, 'README.md': 'human change' }), /edited/);
  assert.throws(() => assertBotOwned(pr, { ...commit, sha: mainSha }, baseFiles), /untracked commits/);
  assert.throws(() => assertBotOwned(pr, { ...commit, author: { login: 'maintainer' } }, baseFiles), /human/);
});

async function fixture({ changed = true, existing = false, edited = false, runs = [], warnings = [], releaseVersion = lock.keycloakVersion, staleBase = false } = {}) {
  const { candidateFiles, pullBody, issueBody } = await lib;
  const calls = [];
  const next = { ...lock, keycloakVersion: releaseVersion, ...(changed ? { runtime: lock.runtime.split('@')[0] + '@sha256:' + 'c'.repeat(64) } : {}) };
  const branchFiles = candidateFiles(baseFiles, next, warnings);
  const pr = { number: 12, node_id: 'PR_test', state: 'open', user: bot, html_url: 'https://example.test/pull/12',
    head: { sha: headSha, ref: 'chore/11-upstream-images', repo: { full_name: 'rambow-cloud/keycloak' } },
    body: pullBody(11, lock, next, branchFiles, warnings, headSha) + (edited ? 'human note' : '') };
  let autoMerge = false;
  const write = (name, data) => async args => { calls.push({ name, args }); return { data: typeof data === 'function' ? data(args) : data }; };
  const github = { rest: {
    repos: {
      get: async () => ({ data: { default_branch: 'main', full_name: 'rambow-cloud/keycloak' } }),
      getContent: async ({ path, ref }) => ({ data: { encoding: 'base64', content: Buffer.from((ref === headSha ? branchFiles : baseFiles)[path]).toString('base64') } }),
      getLatestRelease: async () => ({ data: { tag_name: releaseVersion } }),
      getCommit: async () => ({ data: { sha: headSha, author: bot, parents: [{ sha: staleBase ? 'old' : mainSha }] } }),
    },
    git: {
      getRef: async () => ({ data: { object: { sha: mainSha } } }),
      getCommit: async () => ({ data: { tree: { sha: 'main-tree' } } }),
      createTree: write('tree', { sha: 'new-tree' }),
      createCommit: write('commit', { sha: headSha }),
      createRef: write('branch', {}), updateRef: write('update-branch', {}),
    },
    issues: {
      create: write('issue', { number: 11 }),
      get: async () => ({ data: { number: 11, state: 'open', title: '[Maintenance]: Refresh images', body: issueBody() } }),
    },
    pulls: { list: () => {}, create: write('pr', args => ({ ...pr, body: args.body, draft: args.draft })),
      get: async () => ({ data: pr }), update: write('update-pr', {}) },
    actions: { listWorkflowRuns: () => {}, createWorkflowDispatch: write('dispatch', {}) },
  }, paginate: async method => method === github.rest.pulls.list ? (existing ? [pr] : []) : runs,
  graphql: async (query, args) => {
    if (query.startsWith('query')) return { repository: { pullRequest: { id: pr.node_id, headRefOid: headSha, isDraft: false, autoMergeRequest: autoMerge ? {} : null } } };
    calls.push({ name: query.includes('disablePullRequestAutoMerge') ? 'disable-auto-merge' : 'enable-auto-merge', args });
    autoMerge = !query.includes('disablePullRequestAutoMerge');
    return {};
  } };
  return { calls, args: { github, context: { repo: { owner: 'rambow-cloud', repo: 'keycloak' }, ref: 'refs/heads/main' },
    core: { info() {}, warning() {} }, resolve: async ref => Object.values(next).find(value => typeof value === 'string' && value.startsWith(ref + '@')),
    inspect: async () => ({ warnings }) } };
}

test('updater is quiet on unchanged inputs and dry runs have no writes', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  for (const options of [{ changed: false }, { changed: true }]) {
    const f = await fixture(options);
    const result = await runUpstreamUpdate({ ...f.args, dryRun: options.changed });
    assert.equal(result.changed, options.changed);
    assert.deepEqual(f.calls, []);
  }
});

test('new updates create an Issue first, dispatch both checks and enable protected auto-merge', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  const f = await fixture();
  await runUpstreamUpdate(f.args);
  assert.deepEqual(f.calls.map(c => c.name), ['issue', 'tree', 'commit', 'branch', 'pr', 'dispatch', 'dispatch', 'enable-auto-merge']);
  validateIssue({ ...f.calls[0].args, number: 11, state: 'open' });
  assert.equal(f.calls.find(c => c.name === 'enable-auto-merge').args.sha, headSha);
  assert.equal(f.calls.filter(c => c.name === 'dispatch')[1].args.inputs.pull_request_number, '12');
});

test('larger upgrades are drafted and never enabled for auto-merge', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  const f = await fixture({ releaseVersion: '27.0.0' });
  await runUpstreamUpdate(f.args);
  assert.equal(f.calls.find(c => c.name === 'pr').args.draft, true);
  assert.equal(f.calls.some(c => c.name === 'enable-auto-merge'), false);
});

test('unchanged open candidate avoids writes/builds; missing dispatches can be recovered', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  for (const runs of [[{ head_sha: headSha, conclusion: 'failure' }], []]) {
    const f = await fixture({ existing: true, runs });
    await runUpstreamUpdate(f.args);
    assert.deepEqual(f.calls.map(c => c.name), runs.length ? ['enable-auto-merge'] : ['dispatch', 'dispatch', 'enable-auto-merge']);
  }
});

test('new base commits refresh a candidate for strict protection, using a non-forced update', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  const f = await fixture({ existing: true, staleBase: true });
  await runUpstreamUpdate(f.args);
  assert.equal(f.calls.find(c => c.name === 'update-branch').args.force, false);
  assert.deepEqual(f.calls.find(c => c.name === 'commit').args.parents, [headSha, mainSha]);
  assert.equal(f.calls.some(c => c.name === 'issue'), false);
});

test('human edits and nondefault updater refs fail before any write', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  const f = await fixture({ existing: true, edited: true });
  await assert.rejects(runUpstreamUpdate(f.args), /edited/);
  assert.deepEqual(f.calls, []);
  await assert.rejects(runUpstreamUpdate({ ...f.args, context: { ...f.args.context, ref: 'refs/heads/untrusted' } }), /default branch/);
});

test('dispatched Issue policy accepts only the exact local open PR head', async () => {
  const { issueBody } = await lib;
  const context = { repo: { owner: 'rambow-cloud', repo: 'keycloak' }, sha: headSha, ref: 'refs/heads/update', payload: { repository: { default_branch: 'main' } } };
  const pr = { state: 'open', body: 'Closes #11', head: { sha: headSha, ref: 'update', repo: { full_name: 'rambow-cloud/keycloak' } }, base: { ref: 'main' } };
  const github = { rest: { pulls: { get: async () => ({ data: pr }) }, issues: { get: async () => ({ data: { number: 11, state: 'open', title: '[Maintenance]: Refresh', body: issueBody() } }) } } };
  await checkDispatchedPullRequest({ github, context, number: '12' });
  await assert.rejects(checkDispatchedPullRequest({ github, context: { ...context, sha: mainSha }, number: '12' }), /exact head|open local PR head/);
  pr.head.repo.full_name = 'fork/keycloak';
  await assert.rejects(checkDispatchedPullRequest({ github, context, number: '12' }), /open local PR head/);
});
