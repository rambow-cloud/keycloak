'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { validateIssue, checkDispatchedPullRequest } = require('../scripts/issue-policy.cjs');
const lib = import('../scripts/lib/upstream.mjs');
const bot = { login: 'test-updater[bot]', type: 'Bot', id: 123456, node_id: 'BOT_updater_fixture' };
const mainSha = 'a'.repeat(40);
const headSha = 'b'.repeat(40);
const actionsEditor = { __typename: 'Bot', id: bot.node_id };
const footerEditor = { __typename: 'Bot', id: 'BOT_kgDOCWWZcg' };
const footerFor = number => '\n<!-- codesmith:footer -->\n---\n<a href="https://app.blacksmith.sh/rambow-cloud/codesmith/keycloak/pr/' + number + '?autoLogin=true">View</a>\n<!-- /codesmith:footer -->';
const footerSnapshot = pr => ({ body: pr.body, headRefOid: pr.head.sha, editor: footerEditor,
  userContentEdits: { totalCount: 2, pageInfo: { hasNextPage: false }, nodes: [{ editor: footerEditor }, { editor: actionsEditor }] } });
// Fixed historical fixtures: later real version bumps must not change these behavioral cases.
const pinned = ref => ref + '@sha256:' + 'a'.repeat(64);
const lock = { keycloakVersion: '26.8.1', javaVersion: 25, platform: 'linux/amd64',
  keycloak: pinned('quay.io/keycloak/keycloak:26.8.1'), runtime: pinned('gcr.io/distroless/java25-debian13:nonroot'),
  builder: pinned('docker.io/library/eclipse-temurin:25-jdk-noble'), postgres: pinned('docker.io/library/postgres:17-bookworm'),
  awsDependencies: { wrapperVersion: '4.5.0', lockFile: 'dependencies/aws/dependencies.lock.json' } };
const baseFiles = { 'images.lock.json': JSON.stringify(lock, null, 2) + '\n', 'README.md': 'Keycloak 26.8.1\n',
  'changes/upstream.json': JSON.stringify({ schemaVersion: 1, changes: [] }) + '\n',
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
  assertBotOwned(pr, commit, baseFiles, bot);
  assert.throws(() => assertBotOwned({ ...pr, body: body + 'human note' }, commit, baseFiles, bot), /edited/);
  assert.throws(() => assertBotOwned(pr, commit, { ...baseFiles, 'README.md': 'human change' }, bot), /edited/);
  assert.throws(() => assertBotOwned(pr, { ...commit, sha: mainSha }, baseFiles, bot), /untracked commits/);
  assert.throws(() => assertBotOwned(pr, { ...commit, author: { login: 'maintainer' } }, baseFiles, bot), /human/);
  for (const author of [{ ...bot, id: bot.id + 1 }, { ...bot, node_id: 'other' }, { ...bot, type: 'User' }]) {
    assert.throws(() => assertBotOwned(pr, { ...commit, author }, baseFiles, bot), /human\/unknown/);
  }
});

async function fixture({ changed = true, existing = false, edited = false, runs = [], warnings = [], releaseVersion = lock.keycloakVersion, staleBase = false,
  footer = false, editSnapshot = snapshot => snapshot, changedInput = 'runtime' } = {}) {
  const { candidateFiles, pullBody, issueBody } = await lib;
  const calls = [];
  const next = { ...lock, keycloakVersion: releaseVersion, ...(changed ? { [changedInput]: lock[changedInput].split('@')[0] + '@sha256:' + 'c'.repeat(64) } : {}) };
  const branchFiles = candidateFiles(baseFiles, next, warnings, 11);
  const pr = { number: 12, node_id: 'PR_test', state: 'open', user: bot, html_url: 'https://example.test/pull/12',
    head: { sha: headSha, ref: 'chore/11-upstream-images', repo: { full_name: 'rambow-cloud/keycloak' } },
    body: pullBody(11, lock, next, branchFiles, warnings, headSha) + (edited ? 'human note' : '') + (footer ? footerFor(12) : '') };
  let autoMerge = false;
  const write = (name, data) => async args => { calls.push({ name, args }); return { data: typeof data === 'function' ? data(args) : data }; };
  const github = { rest: {
    repos: {
      get: async () => ({ data: { default_branch: 'main', full_name: 'rambow-cloud/keycloak' } }),
      getContent: async ({ path, ref }) => ({ data: { encoding: 'base64', content: Buffer.from((ref === headSha ? branchFiles : baseFiles)[path]).toString('base64') } }),
      getLatestRelease: async () => ({ data: { tag_name: releaseVersion } }),
      createRelease: write('release', {}),
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
    if (query.includes('userContentEdits')) return { repository: { pullRequest: editSnapshot(footerSnapshot(pr)) } };
    if (query.startsWith('query')) return { repository: { pullRequest: { id: pr.node_id, headRefOid: headSha, isDraft: false, autoMergeRequest: autoMerge ? {} : null } } };
    calls.push({ name: query.includes('disablePullRequestAutoMerge') ? 'disable-auto-merge' : 'enable-auto-merge', args });
    autoMerge = !query.includes('disablePullRequestAutoMerge');
    return {};
  } };
  return { calls, pr, branchFiles, args: { github, identity: bot, context: { repo: { owner: 'rambow-cloud', repo: 'keycloak' }, ref: 'refs/heads/main' },
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

test('new App updates create an Issue first and rely on native checks without duplicate dispatch or publication', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  const f = await fixture();
  await runUpstreamUpdate(f.args);
  assert.deepEqual(f.calls.map(c => c.name), ['issue', 'tree', 'commit', 'branch', 'pr', 'enable-auto-merge']);
  const tree = f.calls.find(c => c.name === 'tree');
  const note = JSON.parse(tree.args.tree.find(e => e.path === 'changes/upstream.json').content);
  assert.equal(note.changes[0].type,'fix');
  assert.deepEqual(note.changes[0].issues,[11]);
  assert.ok(note.changes[0].summary.includes('runtime digest'));
  validateIssue({ ...f.calls[0].args, number: 11, state: 'open' });
  assert.equal(f.calls.find(c => c.name === 'enable-auto-merge').args.sha, headSha);
  assert.equal(f.calls.some(c => c.name === 'dispatch'), false);
});

test('larger upgrades are drafted and never enabled for auto-merge', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  const f = await fixture({ releaseVersion: '27.0.0' });
  await runUpstreamUpdate(f.args);
  assert.equal(f.calls.find(c => c.name === 'pr').args.draft, true);
  assert.equal(f.calls.some(c => c.name === 'enable-auto-merge'), false);
});

test('unchanged App candidate avoids duplicate builds and does not automatically retry failed checks', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  for (const runs of [[{ head_sha: headSha, conclusion: 'failure' }], []]) {
    const f = await fixture({ existing: true, runs });
    await runUpstreamUpdate(f.args);
    assert.deepEqual(f.calls.map(c => c.name), ['enable-auto-merge']);
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

test('missing or legacy workflow identity fails closed before any write; dry-run remains read-only', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  for (const identity of [undefined, { ...bot, login: 'github-actions[bot]' }, { ...bot, type: 'User' }, { ...bot, id: 0 }]) {
    const f = await fixture();
    await assert.rejects(runUpstreamUpdate({ ...f.args, identity }), /dedicated GitHub App/);
    assert.deepEqual(f.calls, []);
  }
  const f = await fixture();
  await runUpstreamUpdate({ ...f.args, identity: undefined, dryRun: true });
  assert.deepEqual(f.calls, []);
});

test('legacy or foreign PR authors require an explicit migration without overwrite or approval', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  for (const user of [{ ...bot, login: 'github-actions[bot]' }, { ...bot, id: bot.id + 1 }, { ...bot, node_id: 'other' }]) {
    const f = await fixture({ existing: true });
    f.pr.user = user;
    await assert.rejects(runUpstreamUpdate(f.args), /not owned by the configured App/);
    assert.deepEqual(f.calls, []);
  }
});

test('App configuration rejects a different minted App and pins the complete bot identity', async () => {
  const { validateUpdaterApp, updaterApp } = await lib;
  assert.equal(validateUpdaterApp(updaterApp, updaterApp.slug), updaterApp);
  for (const config of [{ ...updaterApp, clientId: '' }, { ...updaterApp, appId: 0 }, { ...updaterApp, bot: { ...updaterApp.bot, login: 'other[bot]' } }]) {
    assert.throws(() => validateUpdaterApp(config), /configuration\/token identity/);
  }
  assert.throws(() => validateUpdaterApp(updaterApp, 'different-app'), /configuration\/token identity/);
  assert.throws(() => validateUpdaterApp({ ...updaterApp, bot: null }), /dedicated GitHub App/);
});

test('builder-only refresh writes only a branch/PR and cannot create a Release or dispatch publication', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  const f = await fixture({ changedInput: 'builder' });
  await runUpstreamUpdate(f.args);
  const tree = f.calls.find(c => c.name === 'tree');
  const candidate = JSON.parse(tree.args.tree.find(e => e.path === 'images.lock.json').content);
  assert.notEqual(candidate.builder, lock.builder);
  assert.equal(candidate.runtime, lock.runtime);
  assert.equal(candidate.keycloak, lock.keycloak);
  assert.equal(f.calls.find(c => c.name === 'branch').args.ref, 'refs/heads/chore/11-upstream-images');
  assert.equal(f.calls.some(c => ['release', 'dispatch'].includes(c.name)), false);
  assert.match(f.calls.find(c => c.name === 'pr').args.body, /GitHub App PR events trigger CI/);
});

test('publication event boundary excludes push, PR, schedule and upstream dispatch events', () => {
  const { readFileSync } = require('node:fs');
  const workflow = readFileSync(require('node:path').join(__dirname, '../.github/workflows/release.yml'), 'utf8').replaceAll('\r', '');
  const triggers = workflow.match(/^on:\n([\s\S]*?)^permissions:/m)?.[1];
  assert.ok(triggers, 'release workflow must have explicit top-level event mappings');
  assert.deepEqual([...triggers.matchAll(/^  ([a-z_]+):/gm)].map(m => m[1]), ['release', 'workflow_dispatch']);
  assert.match(triggers, /types: \[published, released\]/);
  assert.match(triggers, /release_tag:[\s\S]*?required: true/);
});

test('plain generated bodies need no footer attribution lookup', async () => {
  const { canonicalUpstreamBody } = await import('../scripts/upstream-update.mjs');
  const f = await fixture({ existing: true });
  assert.equal(await canonicalUpstreamBody({ ...f.args, github: { graphql() { throw new Error('Unexpected lookup'); } }, pr: f.pr }), f.pr.body);
});

test('attributable footer reuses unchanged checks and permits a non-forced base refresh', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  for (const staleBase of [false, true]) {
    const f = await fixture({ existing: true, footer: true, staleBase, runs: [{ head_sha: headSha, conclusion: 'success' }] });
    await runUpstreamUpdate(f.args);
    if (!staleBase) assert.deepEqual(f.calls.map(c => c.name), ['enable-auto-merge']);
    else {
      assert.equal(f.calls.find(c => c.name === 'update-branch').args.force, false);
      assert.ok(f.calls.some(c => c.name === 'update-pr'));
    }
    assert.equal(f.calls.some(c => c.name === 'issue' || c.name === 'dispatch'), false);
  }
});

test('malformed, foreign, duplicate and oversized footer envelopes fail before writes', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  const mutations = [
    body => body + '\nextra human note',
    body => body + footerFor(12),
    body => body.replace('/pr/12?', '/pr/99?'),
    body => body.replace('/rambow-cloud/', '/other-owner/'),
    body => body.replace('View</a>', 'x'.repeat(8192) + '</a>'),
    body => body.replace('View</a>', '<!-- generated-head-sha:' + mainSha + ' --></a>'),
    body => body.replace('<!-- /codesmith:footer -->', ''),
  ];
  for (const mutate of mutations) {
    const f = await fixture({ existing: true, footer: true });
    f.pr.body = mutate(f.pr.body);
    await assert.rejects(runUpstreamUpdate(f.args), /Unexpected upstream PR footer/);
    assert.deepEqual(f.calls, []);
  }
});

test('footer attribution rejects human or unknown editors, missing history and stale snapshots', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  const mutations = [
    s => ({ ...s, body: s.body + '\nconcurrent edit' }),
    s => ({ ...s, headRefOid: mainSha }),
    s => ({ ...s, editor: actionsEditor }),
    s => ({ ...s, editor: { __typename: 'User', id: footerEditor.id } }),
    s => ({ ...s, editor: { __typename: 'Bot', id: 'unknown-bot' } }),
    s => { s.userContentEdits.nodes[1].editor = { __typename: 'User', id: 'human' }; return s; },
    s => { s.userContentEdits.nodes[1].editor = { __typename: 'Bot', id: 'unknown-bot' }; return s; },
    s => { s.userContentEdits.nodes[1].editor = null; return s; },
    s => { s.userContentEdits.pageInfo.hasNextPage = true; return s; },
    s => { s.userContentEdits.totalCount = 3; return s; },
    s => ({ ...s, userContentEdits: undefined }),
    s => ({ ...s, userContentEdits: { totalCount: 0, nodes: [], pageInfo: { hasNextPage: false } } }),
    () => null,
  ];
  for (const editSnapshot of mutations) {
    const f = await fixture({ existing: true, footer: true, editSnapshot });
    await assert.rejects(runUpstreamUpdate(f.args), /edit history/);
    assert.deepEqual(f.calls, []);
  }
});

test('attributed footers cannot hide generated-body, file or commit edits', async () => {
  const { runUpstreamUpdate } = await import('../scripts/upstream-update.mjs');
  for (const change of ['body', 'files', 'commit']) {
    const f = await fixture({ existing: true, footer: true });
    if (change === 'body') f.pr.body = f.pr.body.replace('Refresh upstream image inputs', 'Change reviewed scope');
    if (change === 'files') f.branchFiles['README.md'] += 'Human edit\n';
    if (change === 'commit') f.args.github.rest.repos.getCommit = async () => ({ data: { sha: mainSha, author: bot } });
    await assert.rejects(runUpstreamUpdate(f.args), /edited|untracked commits/);
    assert.deepEqual(f.calls, []);
  }
});

test('dispatched Issue policy accepts only the exact local open PR head', async () => {
  const { issueBody } = await lib;
  const context = { repo: { owner: 'rambow-cloud', repo: 'keycloak' }, sha: headSha, ref: 'refs/heads/update', payload: { repository: { default_branch: 'main' } } };
  const pr = { state: 'open', body: 'Closes #11', head: { sha: headSha, ref: 'update', repo: { full_name: 'rambow-cloud/keycloak' } }, base: { ref: 'main' } };
  const github = { rest: { pulls: { get: async () => ({ data: pr }), listFiles() {} }, issues: { get: async () => ({ data: { number: 11, state: 'open', title: '[Maintenance]: Refresh', body: issueBody() } }) } }, paginate: async () => [] };
  await checkDispatchedPullRequest({ github, context, number: '12' });
  await assert.rejects(checkDispatchedPullRequest({ github, context: { ...context, sha: mainSha }, number: '12' }), /exact head|open local PR head/);
  pr.head.repo.full_name = 'fork/keycloak';
  await assert.rejects(checkDispatchedPullRequest({ github, context, number: '12' }), /open local PR head/);
});
