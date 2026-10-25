'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const run = extra => spawnSync(process.execPath, ['scripts/verify-external.mjs'], {
  encoding: 'utf8', env: { ...process.env, VERIFY_ALLOW_MUTATION: '', VERIFY_BASE_URL: '', VERIFY_ADMIN_USERNAME: '', VERIFY_ADMIN_PASSWORD: '', VERIFY_IAM_REFRESH: '', VERIFY_DURATION_SECONDS: '', ...extra },
});
test('external verification refuses accidental mutation or credential-bearing/insecure URLs before networking', () => {
  const consent = run({});
  assert.notEqual(consent.status, 0);
  assert.match(consent.stderr, /VERIFY_ALLOW_MUTATION/);
  for (const base of ['http://staging.invalid', 'https://user:password@staging.invalid', 'https://staging.invalid?secret=value']) {
    const result = run({ VERIFY_ALLOW_MUTATION: 'dedicated-staging', VERIFY_BASE_URL: base, VERIFY_ADMIN_USERNAME: 'admin', VERIFY_ADMIN_PASSWORD: 'redacted' });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /HTTPS|must not contain/);
  }
});
test('IAM refresh verification refuses a run shorter than the token lifetime', () => {
  const result = run({ VERIFY_ALLOW_MUTATION: 'dedicated-staging', VERIFY_BASE_URL: 'https://staging.invalid', VERIFY_ADMIN_USERNAME: 'admin', VERIFY_ADMIN_PASSWORD: 'redacted', VERIFY_IAM_REFRESH: 'true', VERIFY_DURATION_SECONDS: '30' });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /at least 960/);
});
