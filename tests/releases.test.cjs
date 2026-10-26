'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const lib = import('../scripts/lib/releases.mjs');
const orchestration = import('../scripts/quay-release.mjs');
const catalog = import('../scripts/release-catalog.mjs');
const publishing = import('../scripts/lib/quay-publish.mjs');
const sha = 'a'.repeat(40);
const tools = 'b'.repeat(40);
const digest = char => 'sha256:' + char.repeat(64);
const lock = { keycloakVersion: '26.8.1', platform: 'linux/amd64', javaVersion: 25 };
const lockText = JSON.stringify(lock) + '\n';
const bot = { login: 'github-actions[bot]' };
const profileImages = () => ['core', 'aws'].map((profile, i) => ({ profile, artifactId: i + 1,
  artifactName: 'keycloak-oci-' + profile + '-amd64-' + sha, tag: '26.8.1-r1-' + profile,
  digest: digest(i ? 'd' : 'c'), archiveSha256: 'e'.repeat(64) }));
async function planFixture(overrides = {}) {
  const { hash } = await lib;
  return { schemaVersion: 1, registry: 'quay.io/rambow-cloud/keycloak', tag: 'v26.8.1-r1', releaseId: 42,
    keycloakVersion: '26.8.1', revision: 1, sourceCommit: sha, toolsCommit: tools,
    sourceRun: { id: 1000, attempt: 1 }, lockSha256: hash(lockText), imageLock: lock,
    aliases: [], previousAliases: {}, images: profileImages(), ...overrides };
}
async function recordFixture(plan) {
  plan ??= await planFixture();
  return { schemaVersion: 1, status: 'published', publishedAt: '2026-10-26T01:00:00.000Z', publishRunId: 2000, validationToolsCommit: plan.toolsCommit, plan,
    aliasChanges: plan.aliases.map(a => ({ tag: a.tag, profile: a.profile, fromDigest: plan.previousAliases[a.tag],
      toDigest: plan.images.find(i => i.profile === a.profile).digest })) };
}

test('release versions and aliases require explicit, non-reserved identities', async () => {
  const { parseRelease, validateAliases, canonicalTag } = await lib;
  assert.deepEqual(parseRelease('v26.8.1-r2'), { tag: 'v26.8.1-r2', keycloakVersion: '26.8.1', revision: 2 });
  for (const invalid of ['26.8.1', 'v26.8.1', 'v26.8.1-r0', 'v26.8.1-r01', 'v26.8.1-r1-rc1', '../v26.8.1-r1']) assert.throws(() => parseRelease(invalid));
  assert.equal(canonicalTag('v26.8.1-r1', 'aws'), '26.8.1-r1-aws');
  const alias = { tag: 'extention-v26.8.1', profile: 'aws', keycloakVersion: '26.8.1' };
  validateAliases({ schemaVersion: 1, aliases: [alias] });
  for (const bad of [{ ...alias, profile: undefined }, { ...alias, keycloakVersion: undefined }, { ...alias, tag: 'latest' }, { ...alias, tag: '26.8.1-r1-core' }, { ...alias, tag: 'bad/tag' }]) assert.throws(() => validateAliases({ schemaVersion: 1, aliases: [bad] }));
  assert.throws(() => validateAliases({ schemaVersion: 1, aliases: [alias, alias] }));
});

test('catalog validates bindings, preserves history and renders deterministic digest pull commands', async () => {
  const { validateCatalog, resolveTag, renderCatalog, assertNewRevision } = await lib;
  const aliases = [{ tag: 'extention-v26.8.1', profile: 'aws', keycloakVersion: '26.8.1' }];
  const first = await recordFixture(await planFixture({ aliases, previousAliases: { 'extention-v26.8.1': null } }));
  const second = await recordFixture(await planFixture({ tag: 'v26.8.1-r2', revision: 2, releaseId: 43,
    aliases, previousAliases: { 'extention-v26.8.1': digest('d') },
    images: profileImages().map(i => ({ ...i, tag: '26.8.1-r2-' + i.profile, digest: digest('f') })) }));
  second.publishedAt = '2026-10-27T01:00:00.000Z'; second.publishRunId = 2001;
  validateCatalog([first, second]);
  assert.equal(resolveTag([first, second], 'extention-v26.8.1').digest, digest('f'));
  assert.equal(resolveTag([first, second], 'extention-v26.8.1', 'v26.8.1-r1').digest, digest('d'));
  assert.equal(resolveTag([first, second], '26.8.1-r1-core').reference, 'quay.io/rambow-cloud/keycloak@' + digest('c'));
  assert.equal(renderCatalog([first, second]), renderCatalog([second, first]));
  for (const records of [[], [first], [first, second]]) assert.match(renderCatalog(records), /[^\n]\n$/);
  assert.match(renderCatalog([first, second]), /podman pull quay\.io\/rambow-cloud\/keycloak@sha256:/);
  assert.throws(() => validateCatalog([first, first]), /Duplicate/);
  assert.throws(() => validateCatalog([second]), /continuous/);
  assert.throws(() => assertNewRevision([first, second], 'v26.8.1-r1'), /higher/);
  assert.throws(() => resolveTag([first], 'unknown'), /No recorded/);
});

test('CI selection never falls back from the newest failed exact-commit run', async () => {
  const { selectRun, chooseArtifacts } = await lib;
  const base = { id: 10, head_sha: sha, event: 'push', head_branch: 'main', repository: { full_name: 'rambow-cloud/keycloak' }, head_repository: { full_name: 'rambow-cloud/keycloak' } };
  const runs = [base, { ...base, id: 11, conclusion: 'failure' }, { ...base, id: 12, head_sha: tools }, { ...base, id: 13, event: 'pull_request' }, { ...base, id: 14, head_repository: { full_name: 'fork/keycloak' } }];
  assert.equal(selectRun(runs, { sha, main: 'main', tag: 'v26.8.1-r1' }).id, 11);
  const artifacts = profileImages().map(i => ({ id: i.artifactId, name: i.artifactName, expired: false, size_in_bytes: 1000 }));
  assert.equal(chooseArtifacts(artifacts, sha).length, 2);
  assert.throws(() => chooseArtifacts([artifacts[0]], sha), /Missing/);
  assert.throws(() => chooseArtifacts([...artifacts, artifacts[0]], sha), /ambiguous/);
});

async function apiFixture({ records = [], runs, assets = {}, ancestor = true, prerelease = false, badLock = false, expired = false } = {}) {
  const { json } = await lib;
  const calls = [];
  const release = { id: 42, tag_name: 'v26.8.1-r1', draft: false, prerelease };
  let sourceRuns = runs ?? [{ id: 1000, run_attempt: 1, path: '.github/workflows/ci.yml', status: 'completed', conclusion: 'success',
    head_sha: sha, event: 'push', head_branch: 'main', repository: { full_name: 'rambow-cloud/keycloak' }, head_repository: { full_name: 'rambow-cloud/keycloak' } }];
  const artifacts = profileImages().map(i => ({ id: i.artifactId, name: i.artifactName, expired, size_in_bytes: 1000 }));
  const assetNames = Object.keys(assets);
  const github = { rest: {
    repos: {
      get: async () => ({ data: { default_branch: 'main' } }), getReleaseByTag: async () => ({ data: release }),
      getCommit: async () => ({ data: { sha } }), compareCommits: async () => ({ data: { merge_base_commit: { sha: ancestor ? sha : tools } } }),
      getContent: async ({ path }) => {
        const text = path === 'images.lock.json' ? (badLock ? json({ ...lock, keycloakVersion: '26.7.0' }) : lockText) :
          path === 'releases/aliases.json' ? json({ schemaVersion: 1, aliases: [] }) : json(records.find(r => path.endsWith(r.plan.tag + '.json')));
        return { data: { encoding: 'base64', content: Buffer.from(text).toString('base64'), size: text.length } };
      },
      listReleaseAssets() {},
      getReleaseAsset: async ({ asset_id }) => ({ data: Buffer.from(json(assets[assetNames[asset_id - 1]])) }),
      uploadReleaseAsset: async args => { calls.push({ name: 'upload', args }); return { data: {} }; },
    },
    git: { getRef: async () => ({ data: { object: { sha: tools } } }), getTree: async () => ({ data: { tree: records.map(r => ({ path: 'releases/records/' + r.plan.tag + '.json', type: 'blob' })) } }) },
    actions: { listWorkflowRuns() {}, listWorkflowRunArtifacts() {}, getWorkflowRunAttempt: async ({ run_id, attempt_number }) => ({ data: { ...sourceRuns.find(r => r.id === run_id), run_attempt: attempt_number } }), createWorkflowDispatch: async args => {
      calls.push({ name: 'dispatch', args }); sourceRuns = [{ id: 1001, run_attempt: 1, path: '.github/workflows/ci.yml', status: 'completed', conclusion: 'success',
        head_sha: sha, event: 'workflow_dispatch', head_branch: 'v26.8.1-r1', repository: { full_name: 'rambow-cloud/keycloak' }, head_repository: { full_name: 'rambow-cloud/keycloak' } }];
    } },
  }, paginate: async method => {
    if (method === github.rest.actions.listWorkflowRuns) return sourceRuns;
    if (method === github.rest.actions.listWorkflowRunArtifacts) return artifacts;
    if (method === github.rest.repos.listReleaseAssets) return assetNames.map((name, i) => ({ id: i + 1, name, size: 1000 }));
    throw new Error('Unexpected API');
  } };
  return { github, context: { repo: { owner: 'rambow-cloud', repo: 'keycloak' }, eventName: 'workflow_dispatch', ref: 'refs/heads/main', payload: {} },
    core: { info() {} }, tag: release.tag_name, maxPolls: 2, pause: async () => {}, calls, release };
}

test('preparation enforces release/main/lock identity and skips prereleases/duplicates without writes', async () => {
  const { prepareRelease } = await orchestration;
  for (const options of [{ ancestor: false }, { badLock: true }]) await assert.rejects(prepareRelease(await apiFixture(options)), /main history|image lock/);
  const pre = await apiFixture({ prerelease: true });
  assert.equal((await prepareRelease(pre)).skipped, true);
  assert.deepEqual(pre.calls, []);
  const done = await apiFixture({ records: [await recordFixture()] });
  assert.equal((await prepareRelease(done)).complete, true);
  assert.deepEqual(done.calls, []);
  const f = await apiFixture();
  await assert.rejects(prepareRelease({ ...f, context: { ...f.context, ref: 'refs/heads/untrusted' } }), /from main/);
  const ready = await prepareRelease(f);
  assert.equal(ready.sourceRun.id, 1000);
});

test('missing CI is dispatched once, failures stop, and frozen inputs never drift or rebuild', async () => {
  const { prepareRelease } = await orchestration;
  const missing = await apiFixture({ runs: [] });
  assert.equal((await prepareRelease(missing)).sourceRun.id, 1001);
  assert.equal(missing.calls.length, 1);
  const failed = await apiFixture();
  const originalPaginate = failed.github.paginate;
  failed.github.paginate = async (method, args) => method === failed.github.rest.actions.listWorkflowRuns
    ? (await originalPaginate(method, args)).map(r => ({ ...r, conclusion: 'failure' })) : originalPaginate(method, args);
  await assert.rejects(prepareRelease(failed), /CI failed/);
  assert.deepEqual(failed.calls, []);
  const frozen = await planFixture();
  const expired = await apiFixture({ assets: { 'publication-plan.json': frozen }, expired: true });
  await assert.rejects(prepareRelease(expired), /Frozen OCI artifacts/);
  assert.deepEqual(expired.calls, []);
  const recordOnly = await apiFixture({ assets: { 'publication-plan.json': frozen, 'publication-record.json': await recordFixture(frozen) }, expired: true });
  assert.equal((await prepareRelease(recordOnly)).recordOnly, true);
  assert.deepEqual(recordOnly.calls, []);
});

test('a newly dispatched source CI may take time to appear without redispatching or reusing old artifacts', async () => {
  const { prepareRelease } = await orchestration;
  const f = await apiFixture({ expired: true });
  const paginate = f.github.paginate;
  const oldRuns = await paginate(f.github.rest.actions.listWorkflowRuns);
  let polls = 0;
  f.github.paginate = async (method, args) => {
    if (method === f.github.rest.actions.listWorkflowRuns && ++polls === 2) return oldRuns;
    const data = await paginate(method, args);
    return method === f.github.rest.actions.listWorkflowRunArtifacts && polls >= 3 ? data.map(a => ({ ...a, expired: false })) : data;
  };
  const p = await prepareRelease({ ...f, maxPolls: 3 });
  assert.equal(p.sourceRun.id, 1001);
  assert.equal(f.calls.filter(c => c.name === 'dispatch').length, 1);
});

test('freeze requires both exact artifact scan evidences and is immutable across retries', async () => {
  const { prepareRelease, freezeRelease, makeFrozenPlan } = await orchestration;
  const f = await apiFixture();
  const prepared = await prepareRelease(f);
  const scans = profileImages().map(i => ({ ...i, sourceCommit: sha, sourceRunId: 1000, lockSha256: prepared.lockSha256 }));
  const plan = makeFrozenPlan(prepared, scans);
  assert.throws(() => makeFrozenPlan(prepared, scans.slice(0, 1)), /evidence/);
  assert.throws(() => makeFrozenPlan({ ...prepared, frozen: plan }, scans.map(i => ({ ...i, digest: digest('f') }))), /differ/);
  await freezeRelease({ ...f, prepared, scans });
  assert.deepEqual(f.calls.map(c => c.name), ['upload']);
  const retry = await apiFixture({ assets: { 'publication-plan.json': plan } });
  await freezeRelease({ ...retry, prepared: { ...prepared, frozen: plan }, scans });
  assert.deepEqual(retry.calls, []);
});

test('duplicate release events do not automatically retry an earlier failed publication', async () => {
  const { prepareRelease } = await orchestration;
  const f = await apiFixture();
  f.release.created_at = '2026-10-26T01:00:00Z';
  f.context.eventName = 'release'; f.context.runId = 2001; f.context.payload.release = { id: 42 };
  const paginate = f.github.paginate;
  f.github.paginate = async (method, args) => args.workflow_id === 'release.yml'
    ? [{ id: 2000, head_branch: f.tag, head_sha: sha, created_at: '2026-10-26T01:00:01Z', conclusion: 'failure' }]
    : paginate(method, args);
  assert.equal((await prepareRelease(f)).skipped, true);
  assert.deepEqual(f.calls, []);
  f.github.paginate = async (method, args) => args.workflow_id === 'release.yml'
    ? [{ id: 2000, head_branch: f.tag, head_sha: sha, created_at: '2026-10-26T01:00:01Z', conclusion: 'skipped' }]
    : paginate(method, args);
  assert.equal((await prepareRelease(f)).sourceRun.id, 1000);
});

test('publication rejects all immutable conflicts before copying and never moves aliases early', async () => {
  const { publishImages } = await publishing;
  const plan = await planFixture({ aliases: [{ tag: 'extention-v26.8.1', profile: 'aws', keycloakVersion: '26.8.1' }], previousAliases: { 'extention-v26.8.1': null } });
  const copies = [];
  const adapter = { inspect: async ref => ref.endsWith('-aws') ? digest('f') : null,
    copy: async (image, ref) => { copies.push(ref); return image.digest; } };
  await assert.rejects(publishImages(plan, adapter, { runId: 2000 }), /Immutable/);
  assert.deepEqual(copies, []);
  adapter.inspect = async () => null;
  adapter.copy = async (image, ref) => { copies.push(ref); if (image.profile === 'aws') throw new Error('registry outage'); return image.digest; };
  const progress = [];
  await assert.rejects(publishImages(plan, adapter, { runId: 2000, progress: s => progress.push(s) }), /outage/);
  assert.equal(copies.some(ref => ref.includes('extention')), false);
  assert.equal(progress.at(-1).status, 'partial');
});

test('partial retry reuses canonical tags, records alias history and rejects external alias edits', async () => {
  const { publishImages } = await publishing;
  const plan = await planFixture({ aliases: [{ tag: 'extention-v26.8.1', profile: 'aws', keycloakVersion: '26.8.1' }], previousAliases: { 'extention-v26.8.1': null } });
  const state = new Map([['quay.io/rambow-cloud/keycloak:26.8.1-r1-core', digest('c')]]);
  const copies = [];
  const adapter = { inspect: async ref => state.get(ref) ?? null, copy: async (image, ref) => { copies.push(ref); state.set(ref, image.digest); return image.digest; } };
  const record = await publishImages(plan, adapter, { runId: 2000, now: () => '2026-10-26T01:00:00.000Z' });
  assert.equal(copies.length, 2);
  assert.ok(copies[1].endsWith(':extention-v26.8.1'));
  assert.equal(record.aliasChanges[0].toDigest, digest('d'));
  await publishImages(plan, adapter, { runId: 2000 });
  assert.equal(copies.length, 2);
  state.set('quay.io/rambow-cloud/keycloak:extention-v26.8.1', digest('f'));
  await assert.rejects(publishImages(plan, adapter, { runId: 2000 }), /outside recorded history/);
});

test('catalog guard validates real bot ownership, allowlisted diff, published asset and generated Markdown', async () => {
  const { assertCatalogOwned, catalogBody } = await catalog;
  const { json, renderCatalog } = await lib;
  const record = await recordFixture(await planFixture({ toolsCommit: 'a6bca23dd39652b70c38db10953a2e2a18ac3360' }));
  const recordPath = 'releases/records/' + record.plan.tag + '.json';
  const files = { [recordPath]: json(record), 'releases/README.md': renderCatalog([record]) };
  const f = await apiFixture({ records: [record], assets: { 'publication-record.json': record } });
  const pr = { number: 12, user: bot, head: { sha, ref: 'chore/11-record-release-v26.8.1-r1', repo: { full_name: 'rambow-cloud/keycloak' } }, body: catalogBody(11, record, sha, files) };
  f.github.rest.pulls = { listFiles() {} };
  f.github.rest.repos.getCommit = async () => ({ data: { sha, author: bot } });
  const oldContent = f.github.rest.repos.getContent;
  f.github.rest.repos.getContent = async args => files[args.path] ? ({ data: { encoding: 'base64', size: files[args.path].length, content: Buffer.from(files[args.path]).toString('base64') } }) : oldContent(args);
  let changed = [{ filename: recordPath, status: 'added' }, { filename: 'releases/README.md', status: 'modified' }];
  const oldPaginate = f.github.paginate;
  f.github.paginate = async (method, args) => method === f.github.rest.pulls.listFiles ? changed : oldPaginate(method, args);
  await assertCatalogOwned({ ...f, pr });
  const appended = { ...pr, body: pr.body + '\n<!-- codesmith:footer -->\n---\n<a href="https://app.blacksmith.sh/rambow-cloud/codesmith/keycloak/pr/12?ref=test">Review</a>\n<!-- /codesmith:footer -->' };
  let auditedBody = appended.body;
  const knownEditor = { __typename: 'Bot', id: 'BOT_kgDOCWWZcg' };
  f.github.graphql = async () => ({ repository: { pullRequest: { body: auditedBody, headRefOid: sha, editor: knownEditor,
    userContentEdits: { totalCount: 1, pageInfo: { hasNextPage: false }, nodes: [{ editor: knownEditor }] } } } });
  await assertCatalogOwned({ ...f, pr: appended });
  auditedBody = appended.body.replace('No alias configuration', 'Altered alias configuration');
  await assert.rejects(assertCatalogOwned({ ...f, pr: { ...appended, body: auditedBody } }), /edited/);
  files['releases/README.md'] += '\n';
  await assertCatalogOwned({ ...f, pr: { ...pr, body: catalogBody(11, record, sha, files) } });
  files['releases/README.md'] += '\n';
  await assert.rejects(assertCatalogOwned({ ...f, pr: { ...pr, body: catalogBody(11, record, sha, files) } }), /Markdown/);
  files['releases/README.md'] = renderCatalog([record]);
  await assert.rejects(assertCatalogOwned({ ...f, pr: { ...pr, body: pr.body + 'human edit' } }), /edited/);
  await assert.rejects(assertCatalogOwned({ ...f, pr: { ...pr, user: { login: 'maintainer' } } }), /bot-owned/);
  changed = [...changed, { filename: 'releases/aliases.json', status: 'modified' }];
  await assert.rejects(assertCatalogOwned({ ...f, pr }), /allowlist/);
});

test('ordinary PRs cannot rewrite published records or add records without publication evidence', async () => {
  const { checkRecordChanges } = await catalog;
  const f = await apiFixture();
  f.github.rest.pulls = { listFiles() {} };
  let files = [{ filename: 'releases/records/v26.8.1-r1.json', status: 'modified' }];
  const previous = f.github.paginate;
  f.github.paginate = async (method, args) => method === f.github.rest.pulls.listFiles ? files : previous(method, args);
  await assert.rejects(checkRecordChanges({ ...f, pr: { number: 1, head: { sha } } }), /append-only/);
  files = [{ filename: 'README.md', status: 'modified' }];
  await checkRecordChanges({ ...f, pr: { number: 1, head: { sha } } });
});

test('catalog creation is Issue-first and scopes native auto-merge to generated files with explicit checks', async () => {
  const { ensureCatalogPR } = await catalog;
  const { validateIssue } = require('../scripts/issue-policy.cjs');
  const record = await recordFixture();
  const f = await apiFixture({ assets: { 'publication-record.json': record } });
  const head = 'f'.repeat(40);
  let files = {};
  let pr;
  let branch;
  const write = (name, value) => async args => { f.calls.push({ name, args }); return { data: typeof value === 'function' ? value(args) : value }; };
  f.github.rest.issues = { create: write('issue', { number: 77 }) };
  f.github.rest.git.getCommit = async () => ({ data: { tree: { sha: 'base-tree' } } });
  f.github.rest.git.createTree = write('tree', args => { files = Object.fromEntries(args.tree.map(e => [e.path, e.content])); return { sha: 'new-tree' }; });
  f.github.rest.git.createCommit = write('commit', { sha: head });
  f.github.rest.git.createRef = write('branch', args => { branch = args; return {}; });
  f.github.rest.repos.getCommit = async () => ({ data: { sha: head, author: bot, parents: [{ sha: tools }] } });
  f.github.rest.pulls = { list() {}, listFiles() {}, create: write('pr', args => {
    assert.equal(branch?.ref, 'refs/heads/' + args.head, 'PR head must already exist');
    assert.equal(branch?.sha, head, 'PR branch must point to the generated commit');
    pr = { number: 78, user: bot, body: args.body, head: { sha: head, ref: args.head, repo: { full_name: 'rambow-cloud/keycloak' } }, html_url: 'https://github.com/rambow-cloud/keycloak/pull/78' };
    return pr;
  }) };
  const getContent = f.github.rest.repos.getContent;
  f.github.rest.repos.getContent = async args => args.ref === head && files[args.path]
    ? { data: { encoding: 'base64', size: files[args.path].length, content: Buffer.from(files[args.path]).toString('base64') } } : getContent(args);
  f.github.rest.git.getTree = async args => ({ data: { tree: args.tree_sha === head ? [{ path: 'releases/records/' + record.plan.tag + '.json', type: 'blob' }] : [] } });
  const paginate = f.github.paginate;
  f.github.paginate = async (method, args) => {
    if (method === f.github.rest.pulls.list) return [];
    if (method === f.github.rest.pulls.listFiles) return Object.keys(files).map(filename => ({ filename, status: filename.endsWith('.json') ? 'added' : 'modified' }));
    return paginate(method, args);
  };
  f.github.graphql = async query => {
    if (query.startsWith('query')) return { repository: { pullRequest: { id: 'PR_78', headRefOid: head, isDraft: false, autoMergeRequest: null } } };
    f.calls.push({ name: 'enable-auto-merge' }); return {};
  };
  const result = await ensureCatalogPR({ ...f, record });
  assert.equal(result.number, 78);
  assert.equal(f.calls[0].name, 'issue');
  assert.ok(f.calls.findIndex(c => c.name === 'commit') < f.calls.findIndex(c => c.name === 'branch'));
  assert.ok(f.calls.findIndex(c => c.name === 'branch') < f.calls.findIndex(c => c.name === 'pr'));
  validateIssue({ ...f.calls[0].args, state: 'open', number: 77 });
  assert.deepEqual(Object.keys(files).sort(), ['releases/README.md', 'releases/records/v26.8.1-r1.json']);
  assert.equal(f.calls.filter(c => c.name === 'dispatch').length, 2);
  assert.equal(f.calls.at(-1).name, 'enable-auto-merge');
});

test('the required catalog policy revokes native auto-merge after a human edit', async () => {
  const { checkCatalogPullRequest } = await catalog;
  const f = await apiFixture();
  let disabled = false;
  const pr = { number: 78, user: bot, body: 'edited description', auto_merge: {}, head: { sha, ref: 'chore/77-record-release-v26.8.1-r1', repo: { full_name: 'rambow-cloud/keycloak' } } };
  f.github.graphql = async query => {
    if (query.startsWith('query')) return { repository: { pullRequest: { id: 'PR_78', headRefOid: sha, autoMergeRequest: {} } } };
    assert.match(query, /disablePullRequestAutoMerge/); disabled = true; return {};
  };
  await assert.rejects(checkCatalogPullRequest({ ...f, pr }), /bot-owned/);
  assert.equal(disabled, true);
});
