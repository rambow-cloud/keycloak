'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const lib = import('../scripts/lib/trivy.mjs');
const reporter = import('../scripts/trivy-comment.mjs');

test('planned scan profiles distinguish an intentional skip from a failed or missing required scan', async () => {
  const { plannedScanProfiles } = await reporter;
  const impact = { name:'Image impact', conclusion:'success' };
  assert.deepEqual(plannedScanProfiles([impact, {name:'Build aws',conclusion:'failure'}], 'failure'), ['aws']);
  assert.deepEqual(plannedScanProfiles([impact, {name:'Build core',conclusion:'skipped'}, {name:'Build and verify',conclusion:'success'}], 'success'), []);
  const skippedMatrix = {name:'Build ${{ matrix.profile }}',conclusion:'skipped'};
  assert.deepEqual(plannedScanProfiles([impact, skippedMatrix, {name:'Build and verify',conclusion:'success'}], 'success'), []);
  assert.deepEqual(plannedScanProfiles([impact, skippedMatrix, {name:'Build and verify',conclusion:'failure'}], 'failure'), ['core','aws']);
  assert.deepEqual(plannedScanProfiles([impact, skippedMatrix], 'success'), ['core','aws']);
  assert.deepEqual(plannedScanProfiles([impact], 'failure'), ['core','aws']);
  assert.deepEqual(plannedScanProfiles([{...impact,conclusion:'failure'},{name:'Build aws',conclusion:'skipped'}], 'failure'), ['core','aws']);
  const { renderReport } = await lib;
  const body = renderReport({}, {runUrl:'https://github.com/rambow-cloud/keycloak/actions/runs/1',headSha:'a'.repeat(40),runId:1,runAttempt:1,conclusion:'success',expectedProfiles:[]});
  assert.match(body,/SKIPPED/); assert.doesNotMatch(body,/FAILED \/ missing/);
});
const headSha = 'a'.repeat(40);
const policy = { version: '0.76.1', linuxAmd64Sha256: 'a'.repeat(64), blockingSeverities: ['HIGH', 'CRITICAL'], blockUnfixed: false };
const scanContext = { profile: 'core', headSha, runId: 100, runAttempt: 1, policy };
const vuln = (id, severity, fixed = '') => ({ VulnerabilityID: id, Severity: severity, FixedVersion: fixed, PkgName: 'test-package', InstalledVersion: '1.0' });
const report = findings => ({ SchemaVersion: 2, ArtifactType: 'container_image', CreatedAt: '2026-10-26T00:00:00Z',
  Metadata: { OS: { Family: 'debian', Name: '13' } }, Results: [
    { Class: 'os-pkgs', Type: 'debian', Target: 'Debian 13', Vulnerabilities: findings },
    { Class: 'lang-pkgs', Type: 'jar', Target: 'keycloak.jar' },
  ] });

test('scanner checksum rejects modified archives before execution', async () => {
  const { verifyScannerArchive } = await lib;
  const bytes = Buffer.from('trusted archive');
  const digest = createHash('sha256').update(bytes).digest('hex');
  verifyScannerArchive(bytes, digest);
  assert.throws(() => verifyScannerArchive(Buffer.from('modified archive'), digest), /checksum mismatch/);
});

test('gate blocks fixable HIGH/CRITICAL while retaining all severities and unfixed findings', async () => {
  const { summarize, validateSummary, gateSummary } = await lib;
  const data = report([vuln('CVE-2026-10001', 'HIGH', '1.1'), vuln('CVE-2026-10002', 'CRITICAL'), vuln('CVE-2026-10003', 'LOW', '1.2')]);
  data.Results[0].Vulnerabilities.push(data.Results[0].Vulnerabilities[0]);
  const summary = summarize(data, scanContext);
  assert.equal(summary.total, 3);
  assert.equal(summary.blocking, 1);
  assert.equal(summary.counts.CRITICAL.total, 1);
  assert.equal(summary.counts.CRITICAL.fixable, 0);
  validateSummary(summary, scanContext);
  assert.throws(() => gateSummary(summary), /blocked 1/);
  gateSummary(summarize(report([vuln('CVE-2026-10002', 'CRITICAL')]), scanContext));
  assert.equal(summarize(data, { ...scanContext, policy: { ...policy, blockUnfixed: true } }).blocking, 2);
});

test('missing coverage, malformed data, mismatched provenance and scanner failures fail closed', async () => {
  const { summarize, validateSummary, gateSummary } = await lib;
  const data = report([]);
  assert.throws(() => summarize({ ...data, Results: [] }, scanContext), /coverage/);
  assert.throws(() => summarize(report([vuln('bad', 'IMAGINARY')]), scanContext), /severity/);
  const summary = summarize(data, scanContext);
  assert.throws(() => validateSummary({ ...summary, headSha: 'b'.repeat(40) }, scanContext), /match/);
  assert.throws(() => validateSummary({ ...summary, total: 1 }, scanContext), /counts/);
  assert.throws(() => gateSummary({ ...summary, status: 'error' }), /failed/);
  assert.throws(() => gateSummary({ ...summary, osEosl: true }), /end-of-life/);
});

test('RHEL coverage requires nonempty RPM and Java results while unsupported OS scans remain blocked', async () => {
  const { summarize, gateSummary } = await lib;
  const data = report([vuln('CVE-2026-12345', 'HIGH', '2.0')]);
  data.Metadata.OS = { Family: 'redhat', Name: '10.2' };
  data.Results[0].Type = 'redhat';
  data.Results[0].Packages = [{ Name: 'glibc' }];
  data.Results[1].Packages = [{ Name: 'org.keycloak:keycloak-services' }];
  const context = { ...scanContext, expectedOS: 'redhat' };
  assert.throws(() => summarize(data, scanContext), /coverage/);
  assert.throws(() => gateSummary(summarize(data, context)), /blocked/);
  for (const index of [0, 1]) {
    const missing = structuredClone(data);
    missing.Results[index].Packages = [];
    assert.throws(() => summarize(missing, context), /coverage/);
  }
  assert.throws(() => summarize(data, { ...context, expectedOS: 'alpaquita' }), /Unsupported/);
});

test('experimental runtime inputs reject floating images, unapproved sources and executable path injection', async () => {
  const { validateCandidate } = await import('../experiments/runtime-comparison.mjs');
  const candidate = { runtime: 'dhi.io/eclipse-temurin:25-debian13@sha256:' + 'a'.repeat(64), javaPath: '/opt/java/openjdk/25-jre/bin/java', expectedOS: 'debian' };
  validateCandidate(candidate);
  for (const patch of [{runtime:'dhi.io/eclipse-temurin:25-debian13'}, {runtime:'untrusted.example/jre@sha256:'+'a'.repeat(64)},
    {javaPath:'/tmp/java;exit'}, {javaPath:'/usr/../tmp/java'}, {expectedOS:'unknown'}]) assert.throws(() => validateCandidate({...candidate,...patch}), /Invalid/);
});

test('comments escape artifact content, remain bounded and show failed/missing profiles', async () => {
  const { summarize, renderReport, commentMarker } = await lib;
  const malicious = '<script>@team\n![link](https://attacker.example) | `';
  const data = report(Array.from({ length: 50 }, (_, i) => ({ ...vuln('CVE-2026-' + (10000 + i), 'HIGH', '&'.repeat(256)), PkgName: malicious.repeat(10), InstalledVersion: malicious.repeat(10) })));
  const summary = summarize(data, scanContext);
  assert.equal(summary.findings.length, 20);
  const body = renderReport({ core: summary }, { runUrl: 'https://github.com/rambow-cloud/keycloak/actions/runs/100', headSha, runId: 100, runAttempt: 1, conclusion: 'failure' });
  assert.ok(body.startsWith(commentMarker));
  assert.ok(body.length < 60000);
  for (const unsafe of ['<script>', '@team', '![link]']) assert.equal(body.includes(unsafe), false);
  assert.match(body, /Top 20 of 50/);
  assert.match(body, /FAILED \/ missing report/);
  assert.match(body, /CI run and full JSON artifacts/);
});

async function fixture({ event = 'pull_request', stale = false, newer = false, comments = [], missing = false, foreign = false } = {}) {
  const { summarize } = await lib;
  const calls = [];
  const run = { id: 100, run_attempt: 1, workflow_id: 99, repository: { full_name: 'rambow-cloud/keycloak' },
    path: '.github/workflows/ci.yml', status: 'completed', conclusion: 'success', event,
    head_sha: headSha, head_branch: 'feature', head_repository: { full_name: 'fork-owner/keycloak' } };
  const pr = { number: 12, state: 'open', head: { sha: stale ? 'b'.repeat(40) : headSha, ref: 'feature', repo: { full_name: foreign ? 'other/keycloak' : 'fork-owner/keycloak' } },
    base: { ref: 'main', repo: { full_name: 'rambow-cloud/keycloak' } } };
  const artifacts = missing ? [] : ['core', 'aws'].map((profile, i) => ({ id: i + 1, name: 'trivy-' + profile + '-1', size_in_bytes: 1000, expired: false }));
  const github = { rest: {
    repos: { get: async () => ({ data: { default_branch: 'main' } }), listPullRequestsAssociatedWithCommit() {} },
    actions: { getWorkflowRun: async () => ({ data: run }), getWorkflow: async () => ({ data: { path: '.github/workflows/ci.yml' } }), listWorkflowRuns() {}, listWorkflowRunArtifacts() {} },
    pulls: { get: async () => ({ data: pr }) },
    issues: { listComments() {}, createComment: async args => { calls.push({ action: 'create', ...args }); return { data: { html_url: 'https://example.test/comment' } }; },
      updateComment: async args => { calls.push({ action: 'update', ...args }); return { data: { html_url: 'https://example.test/comment' } }; } },
  }, paginate: async method => {
    if (method === github.rest.repos.listPullRequestsAssociatedWithCommit) return [pr];
    if (method === github.rest.actions.listWorkflowRuns) return newer ? [{ ...run, id: 101 }] : [run];
    if (method === github.rest.actions.listWorkflowRunArtifacts) return artifacts;
    if (method === github.rest.issues.listComments) return comments;
    throw new Error('Unexpected API');
  } };
  return { github, context: { repo: { owner: 'rambow-cloud', repo: 'keycloak' } }, runId: 100, core: { info() {}, warning() {} }, calls, run, pr,
    loadSummary: async artifact => summarize(report([]), { ...scanContext, profile: artifact.profile }) };
}

test('reporter associates fork and bot-dispatched runs using API data, never artifact PR numbers', async () => {
  const { prepareReport, publishReport } = await reporter;
  for (const event of ['pull_request', 'workflow_dispatch']) {
    const f = await fixture({ event });
    const prepared = await prepareReport(f);
    assert.deepEqual(prepared.prs, [12]);
    await publishReport({ ...f, prepared });
    assert.equal(f.calls[0].issue_number, 12);
    assert.equal(f.calls[0].action, 'create');
  }
});

test('stale, unrelated and newer-run results cannot write comments', async () => {
  const { prepareReport, publishReport } = await reporter;
  for (const options of [{ stale: true }, { foreign: true }, { newer: true }, { event: 'push' }]) {
    const f = await fixture(options);
    assert.equal(await prepareReport(f), null);
    assert.deepEqual(f.calls, []);
  }
  const f = await fixture();
  const prepared = await prepareReport(f);
  f.pr.head.sha = 'b'.repeat(40);
  await publishReport({ ...f, prepared });
  assert.deepEqual(f.calls, []);
});

test('reporter updates one bot comment, preserves human comments and skips identical/newer reports', async () => {
  const { prepareReport, publishReport } = await reporter;
  const { commentMarker } = await lib;
  const comments = [{ id: 1, user: { login: 'maintainer' }, body: commentMarker + '\nhuman comment' },
    { id: 2, user: { login: 'github-actions[bot]' }, body: commentMarker + '\nold report' }];
  const f = await fixture({ comments });
  const prepared = await prepareReport(f);
  await publishReport({ ...f, prepared });
  assert.equal(f.calls[0].action, 'update');
  assert.equal(f.calls[0].comment_id, 2);
  comments[1].body = f.calls[0].body;
  await publishReport({ ...f, prepared });
  assert.equal(f.calls.length, 1);
  comments[1].body = commentMarker + '\n<!-- run-order:101:1 -->\nnewer report';
  await publishReport({ ...f, prepared });
  assert.equal(f.calls.length, 1);
});

test('missing or malformed artifacts produce an incomplete-scan comment rather than a clean scan claim', async () => {
  const { prepareReport, publishReport } = await reporter;
  const f = await fixture({ missing: true });
  await publishReport({ ...f, prepared: await prepareReport(f) });
  assert.match(f.calls[0].body, /FAILED \/ missing report/);
  const invalid = await fixture();
  await publishReport({ ...invalid, prepared: await prepareReport(invalid), loadSummary: async () => ({ headSha: 'bad' }) });
  assert.match(invalid.calls[0].body, /FAILED \/ missing report/);
});

test('rerun attempts reject old artifacts and merged PRs still receive their report after auto-merge', async () => {
  const { prepareReport } = await reporter;
  const f = await fixture();
  f.run.run_attempt = 2;
  f.pr.state = 'closed';
  f.pr.merged_at = '2026-10-26T00:00:00Z';
  const prepared = await prepareReport(f);
  assert.deepEqual(prepared.artifacts, []);
  assert.deepEqual(prepared.prs, [12]);
});
