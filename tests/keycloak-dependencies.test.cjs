const { test } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtemp, readFile, writeFile, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join } = require('node:path');
const { createHash } = require('node:crypto');
const lib = import('../scripts/keycloak-dependencies.mjs');
const bytes = Buffer.from('checksum-locked test artifact');
const lock = { schemaVersion: 1, keycloakVersion: '26.8.1', upstreamVersion: '33.6.0-jre', upstreamSha256: 'a'.repeat(64),
  version: '33.7.2-jre', sha256: createHash('sha256').update(bytes).digest('hex') };

test('Guava override binds the exact upstream version, source checksum and safe artifact path', async () => {
  const { validateOverride } = await lib;
  const result = validateOverride(lock, '26.8.1');
  assert.equal(result.path, 'lib/lib/main/com.google.guava.guava-33.6.0-jre.jar');
  assert.equal(new URL(result.url).origin, 'https://repo.maven.apache.org');
  for (const patch of [{ version: '../escape' }, { upstreamVersion: '../../escape' }, { url: 'https://evil.example/x.jar' },
    { sha256: 'bad' }, { upstreamSha256: lock.sha256 }, { version: lock.upstreamVersion }, { schemaVersion: 2 }]) {
    assert.throws(() => validateOverride({ ...lock, ...patch }, '26.8.1'), /Invalid Guava/);
  }
  assert.throws(() => validateOverride(lock, '26.8.2'), /review\/retire/);
});

test('locked download and cache reuse produce distinct original/patched integrity manifests', async () => {
  const { prepareOverride } = await lib;
  const output = await mkdtemp(join(tmpdir(), 'keycloak-guava-'));
  try {
    let downloads = 0;
    const fetcher = async (url, options) => {
      downloads++;
      assert.equal(url, 'https://repo.maven.apache.org/maven2/com/google/guava/guava/33.7.2-jre/guava-33.7.2-jre.jar');
      assert.equal(options.redirect, 'error');
      return new Response(bytes);
    };
    await prepareOverride(lock, '26.8.1', output, fetcher);
    await prepareOverride(lock, '26.8.1', output, fetcher);
    assert.equal(downloads, 1);
    assert.deepEqual(await readFile(join(output, 'guava.jar')), bytes);
    assert.equal(await readFile(join(output, 'upstream.sha256'), 'utf8'), lock.upstreamSha256 + '  lib/lib/main/com.google.guava.guava-33.6.0-jre.jar\n');
    assert.equal(await readFile(join(output, 'patched.sha256'), 'utf8'), lock.sha256 + '  lib/lib/main/com.google.guava.guava-33.6.0-jre.jar\n');
    await writeFile(join(output, 'guava.jar'), 'corrupted cache');
    await prepareOverride(lock, '26.8.1', output, fetcher);
    assert.equal(downloads, 2);
  } finally { await rm(output, { recursive: true, force: true }); }
});

test('unsafe locks, corrupt or failed downloads produce no usable replacement', async () => {
  const { prepareOverride } = await lib;
  const output = await mkdtemp(join(tmpdir(), 'keycloak-guava-'));
  try {
    await assert.rejects(prepareOverride(lock, '26.8.2', output, () => { throw Error('must not fetch'); }), /Invalid Guava/);
    await assert.rejects(prepareOverride(lock, '26.8.1', output, async () => new Response('wrong bytes')), /checksum mismatch/);
    await assert.rejects(prepareOverride(lock, '26.8.1', output, async () => new Response('', { status: 503 })), /download failed/);
    await assert.rejects(readFile(join(output, 'guava.jar')), { code: 'ENOENT' });
    await assert.rejects(readFile(join(output, 'patched.sha256')), { code: 'ENOENT' });
  } finally { await rm(output, { recursive: true, force: true }); }
});
