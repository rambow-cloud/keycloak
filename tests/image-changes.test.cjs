'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const lib = import('../scripts/lib/image-changes.mjs');
const oldSha = 'a'.repeat(40), newSha = 'b'.repeat(40);
const oid = value => createHash('sha1').update(value).digest('hex');
const lock = { keycloakVersion: '26.8.1', javaVersion: 25, platform: 'linux/amd64', keycloak: 'keycloak@one', runtime: 'runtime@one', builder: 'builder@one', postgres: 'pg@one', awsDependencies: { wrapperVersion: '4.5.0' } };
const entry = { type: 'fix', summary: 'Correct the AWS database connection retry behavior.', issues: [5], profiles: ['aws'] };
const files = { Containerfile: 'container-source', 'scripts/build.sh': 'build-source', 'config/java.options': 'java-flags',
  'dependencies/aws/dependencies.lock.json': 'providers', 'tests/verify-fixture.json': 'fixture', 'README.md': 'documentation' };
function source(ref = oldSha, patches = {}, nextLock = lock) {
  const content = { ...files, ...patches, 'images.lock.json': JSON.stringify(nextLock) };
  for (const key of Object.keys(content)) if (content[key] === null) delete content[key];
  return { ref, lock: nextLock, content, containerfile:content.Containerfile, files: Object.fromEntries(Object.entries(content).map(([path, value]) => [path, { sha: oid(value), mode: '100644', type: 'blob' }])) };
}
function fixture(current, previous = source()) {
  const sources = { [oldSha]: previous, [newSha]: current };
  const reads = [];
  const github = { rest: {
    git: { getTree: async ({ tree_sha }) => { reads.push(['tree', tree_sha]); return { data: { tree: Object.entries(sources[tree_sha].files).map(([path, value]) => ({ path, ...value })) } }; } },
    repos: { getContent: async ({ path, ref }) => { reads.push(['content', path, ref]); const value = sources[ref].content[path]; if (value === undefined) throw new Error('missing file'); return { data: { size: value.length, encoding: 'base64', content: Buffer.from(value).toString('base64') } }; },
      compareCommits: async ({ base }) => ({ data: { merge_base_commit: { sha: base } } }) },
    issues: { get: async ({ issue_number }) => { reads.push(['issue', issue_number]); return { data: { number: issue_number, title: '[Maintenance]: Correct image behavior', state: 'closed', body:
      ['Maintenance goal','Scope','Security and compatibility','Acceptance criteria','Validation plan'].map(h => '### ' + h + '\nSubstantive reviewed implementation details.').join('\n\n') } }; } },
  } };
  return { github, repo: { owner: 'rambow-cloud', repo: 'keycloak' }, sourceCommit: newSha, reads,
    records: [{ publishedAt: '2026-10-26T00:00:00.000Z', publishRunId: 1, plan: { sourceCommit: oldSha, images: [{ profile: 'core' }, { profile: 'aws' }] } }] };
}

test('semantic fingerprints and CI scope distinguish metadata, AWS-only inputs, shared inputs and validation', async () => {
  const { classifyCI, fingerprint } = await lib;
  const base = source();
  const docs = source(newSha, { 'README.md': 'new docs', 'dependencies/aws/README.md': 'provider documentation', 'releases/records/a.json': 'metadata', 'changes/30.json': '{}' });
  assert.deepEqual(classifyCI(base, docs).profiles, []);
  assert.equal(fingerprint(base, 'core'), fingerprint(docs, 'core'));
  const nested = source(oldSha, {}, {...lock,awsDependencies:{sdkVersion:'2',wrapperVersion:'4'}});
  const reordered = source(newSha, {}, {...lock,awsDependencies:{wrapperVersion:'4',sdkVersion:'2'}});
  assert.equal(fingerprint(nested,'aws'),fingerprint(reordered,'aws'));
  assert.deepEqual(classifyCI(base, source(newSha, {}, { ...lock, awsDependencies: { wrapperVersion: '4.5.1' } })).profiles, ['aws']);
  assert.deepEqual(classifyCI(base, source(newSha, { 'dependencies/aws/dependencies.lock.json': 'new-providers' })).profiles, ['aws']);
  assert.deepEqual(classifyCI(base, source(newSha, {}, { ...lock, runtime: 'runtime@new' })).profiles, ['core','aws']);
  const builder = source(newSha, {}, { ...lock, builder: 'builder@new' });
  assert.deepEqual(classifyCI(base, builder).profiles, ['core','aws']);
  for (const profile of ['core','aws']) assert.notEqual(fingerprint(base, profile), fingerprint(builder, profile));
  assert.deepEqual(classifyCI(base, source(newSha, {}, { ...lock, postgres: 'pg@new' })).imageChanges, []);
  assert.deepEqual(classifyCI(base, source(newSha, {}, { ...lock, postgres: 'pg@new' })).profiles, ['core','aws']);
  assert.deepEqual(classifyCI(base, source(newSha, { 'scripts/verify-image.sh': 'new-check' })).profiles, ['core','aws']);
  assert.deepEqual(classifyCI(base, source(newSha, { 'tests/AwsHttpTransport.java': 'new-check' })).profiles, ['aws']);
  assert.deepEqual(classifyCI(base, source(newSha, { 'unknown-runtime-source': 'new' })).profiles, ['core','aws']);
});

test('no image changes produce no release work or note/Issue lookups', async () => {
  const { assessRelease } = await lib;
  const f = fixture(source(newSha, { 'README.md': 'updated documentation' }));
  assert.deepEqual((await assessRelease(f)).profiles, []);
  assert.equal(f.reads.some(r => r[0] === 'issue'), false);
  assert.equal(f.reads.filter(r => r[0] === 'tree').length, 2);
});

test('Containerfile stage dependencies isolate AWS/core changes and unknown syntax stays conservative', async () => {
  const { fingerprint, containerInputs } = await lib;
  const text = 'ARG BASE\nFROM ${BASE} AS runtime\nENV SHARED=1\nFROM runtime AS aws\nENV AWS_ONLY=1\nFROM runtime AS core\nENV CORE_ONLY=1\n';
  const base = source(oldSha, {Containerfile:text});
  const aws = source(newSha, {Containerfile:text.replace('AWS_ONLY=1','AWS_ONLY=2')});
  assert.equal(fingerprint(base,'core'),fingerprint(aws,'core'));
  assert.notEqual(fingerprint(base,'aws'),fingerprint(aws,'aws'));
  const core = source(newSha, {Containerfile:text.replace('CORE_ONLY=1','CORE_ONLY=2')});
  assert.equal(fingerprint(base,'aws'),fingerprint(core,'aws'));
  const ambiguous = 'FROM runtime\nCOPY --from=${dynamic} /a /b\n';
  assert.equal(containerInputs(ambiguous,'core'),ambiguous);
});

test('AWS-only changes require reviewed nonempty Issue-linked notes and leave core unpublished', async () => {
  const { assessRelease, fingerprint } = await lib;
  const current = source(newSha, { 'dependencies/aws/dependencies.lock.json': 'fixed providers', 'changes/5-retries.json': JSON.stringify({ schemaVersion: 1, changes: [entry] }) });
  const f = fixture(current);
  const intent = await assessRelease(f);
  assert.deepEqual(intent.profiles, ['aws']);
  assert.equal(intent.images[0].inputSha256, fingerprint(current, 'aws'));
  assert.deepEqual(intent.images[0].changes[0].issues, [5]);
  assert.equal(f.reads.filter(r => r[0] === 'issue').length, 1);
});

test('missing, empty, placeholder, wrongly scoped and rewritten change fragments stop publication', async () => {
  const { assessRelease, validateChanges } = await lib;
  for (const note of [undefined, { schemaVersion: 1, changes: [] }, { schemaVersion: 1, changes: [{ ...entry, profiles: ['core'] }] },
    { schemaVersion: 1, changes: [{ ...entry, summary: 'No image changes are needed for this release.' }] }]) {
    const patches = { 'dependencies/aws/dependencies.lock.json': 'new providers', ...(note ? { 'changes/5.json': JSON.stringify(note) } : {}) };
    await assert.rejects(assessRelease(fixture(source(newSha, patches))), /changes|summary/i);
  }
  const prior = source(oldSha, { 'changes/5.json': JSON.stringify({ schemaVersion: 1, changes: [entry] }) });
  const current = source(newSha, { 'dependencies/aws/dependencies.lock.json': 'new providers', 'changes/5.json': JSON.stringify({ schemaVersion: 1, changes: [{ ...entry, summary: 'Rewrite an already published change fragment.' }] }) });
  await assert.rejects(assessRelease(fixture(current, prior)), /cannot be removed or rewritten/);
  assert.throws(() => validateChanges([{ ...entry, issues: [] }]), /Issue/);
});

test('CI fails closed for incomplete Git trees and does not silently skip failed assessment', async () => {
  const { snapshot, assessCI } = await lib;
  const f = fixture(source(newSha));
  f.github.rest.git.getTree = async () => ({ data: { truncated: true, tree: [] } });
  await assert.rejects(snapshot(f.github, f.repo, newSha), /incomplete/);
  await assert.rejects(assessCI({ github: f.github, context: { repo: f.repo, sha: newSha, eventName: 'push', payload: { before: oldSha } } }), /incomplete/);
});

test('manual main/tag CI reuses release assessment; metadata PR CI skips and missing notes fail', async () => {
  const { assessCI } = await lib;
  const f = fixture(source(newSha, { 'README.md': 'new documentation' }));
  f.github.rest.repos.get = async () => ({ data: { default_branch: 'main' } });
  let assessments = 0;
  const request = { github: f.github, context: { repo: f.repo, sha: newSha, eventName: 'workflow_dispatch', ref: 'refs/heads/main', payload: {} },
    assessReleaseForCI: async sha => { assert.equal(sha, newSha); assessments++; return { profiles: [] }; } };
  assert.deepEqual((await assessCI(request)).profiles, []);
  assert.deepEqual((await assessCI({ ...request, context: { ...request.context, ref: 'refs/tags/v26.8.1-r2' } })).profiles, []);
  assert.equal(assessments, 2);
  assert.deepEqual((await assessCI({ ...request, context: { ...request.context, eventName: 'pull_request', payload: { pull_request: { base: { sha: oldSha }, head: { sha: newSha } } } } })).profiles, []);
});
