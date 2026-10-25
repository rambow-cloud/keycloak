'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { issueNumbers, validateIssue, checkPullRequest } = require('../scripts/issue-policy.cjs');
const valid = () => ({ number: 42, state: 'open', title: '[Maintenance]: Refresh runtime', body: '### Maintenance goal\nUpdate Java.\n\n### Scope\nRuntime base.\n\n### Security and compatibility\nRetest PostgreSQL startup.\n\n### Acceptance criteria\n- [ ] New digest builds and starts.\n\n### Validation plan\nRun image verification.\n' });
test('only standalone local closing references count; duplicates are collapsed', () => {
  assert.deepEqual(issueNumbers('Closes #42\nCloses #7\nCloses #42'), [42, 7]);
  for (const body of ['', 'Related #42', 'Closes other/repo#42', 'Closes https://github.com/other/repo/issues/42']) assert.throws(() => issueNumbers(body));
});
test('complete maintenance, feature, and bug issues pass', () => {
  validateIssue(valid());
  for (const [prefix, sections] of [
    ['[Feature]: ', ['Problem and motivation', 'Proposed solution', 'Security and compatibility', 'Acceptance criteria', 'Validation plan']],
    ['[Bug]: ', ['Problem description', 'Reproduction steps', 'Expected behavior', 'Actual behavior', 'Environment', 'Sanitized logs', 'Acceptance criteria', 'Validation plan']],
  ]) validateIssue({ ...valid(), title: prefix + 'Example', body: sections.map(s => '### ' + s + '\nA concrete answer.\n').join('\n') });
});
test('closed issues, PRs, missing fields, placeholders, and malformed titles fail', () => {
  assert.throws(() => validateIssue({ ...valid(), state: 'closed' }));
  assert.throws(() => validateIssue({ ...valid(), pull_request: {} }));
  assert.throws(() => validateIssue({ ...valid(), title: 'Refresh runtime' }));
  assert.throws(() => validateIssue({ ...valid(), title: '[Maintenance]:' }));
  assert.throws(() => validateIssue({ ...valid(), body: valid().body.replace('Update Java.', '_No response_') }));
  assert.throws(() => validateIssue({ ...valid(), body: valid().body.replace('### Scope\nRuntime base.', '') }));
  assert.throws(() => validateIssue({ ...valid(), body: valid().body + '\n### Scope\nDuplicate' }));
});
test('API integration checks every referenced issue in the current repository', async () => {
  const calls = [];
  const context = { repo: { owner: 'rambow-cloud', repo: 'keycloak' }, payload: { pull_request: { body: 'Closes #42\nCloses #7' } } };
  const github = { rest: { issues: { get: async args => { calls.push(args); return { data: { ...valid(), number: args.issue_number } }; } } } };
  await checkPullRequest({ github, context });
  assert.deepEqual(calls.map(c => [c.owner, c.repo, c.issue_number]), [['rambow-cloud', 'keycloak', 42], ['rambow-cloud', 'keycloak', 7]]);
  github.rest.issues.get = async () => { throw new Error('Not found'); };
  await assert.rejects(checkPullRequest({ github, context }), /Not found/);
});

