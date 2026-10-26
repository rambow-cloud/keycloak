import { readFile, writeFile, mkdtemp, unlink } from 'node:fs/promises';
import { writeFileSync, createReadStream } from 'node:fs';
import { resolve, join, basename, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { json, hash, profiles, validatePlan, isDigest } from './lib/releases.mjs';
import { publishImages } from './lib/quay-publish.mjs';
import { federatedQuayCredentials } from './lib/quay-auth.mjs';

function run(args, options = {}) {
  const r = spawnSync('skopeo', args, { encoding: 'utf8', maxBuffer: 5000000, timeout: 600000, ...options });
  if (r.error || r.status !== 0) throw new Error('Skopeo failed: ' + (r.error?.message ?? r.stderr?.slice(0, 4000)));
  return r.stdout;
}
async function archiveHash(path) {
  const digest = createHash('sha256');
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest('hex');
}
async function inspectSource(directory, prepared, image) {
  const path = resolve(directory, image.artifactName, 'keycloak.oci.tar');
  const checksum = await readFile(path + '.sha256', 'utf8');
  const match = /^([a-f0-9]{64})  keycloak\.oci\.tar\s*$/.exec(checksum);
  const actual = await archiveHash(path);
  if (!match || match[1] !== actual || (image.archiveSha256 && image.archiveSha256 !== actual)) throw new Error('OCI archive checksum mismatch.');
  const lock = await readFile(resolve(directory, image.artifactName, 'images.lock.json'), 'utf8');
  if (hash(lock) !== prepared.lockSha256) throw new Error('Artifact lock does not match the tagged source.');
  const info = JSON.parse(run(['inspect', 'oci-archive:' + path]));
  if (!isDigest(info.Digest) || info.Architecture !== 'amd64' || info.Os !== 'linux' ||
      info.Labels?.['org.opencontainers.image.revision'] !== prepared.sourceCommit ||
      info.Labels?.['org.opencontainers.image.version'] !== prepared.imageLock.keycloakVersion ||
      info.Labels?.['cloud.rambow.keycloak.profile'] !== image.profile || (image.digest && image.digest !== info.Digest)) throw new Error('OCI image identity/profile does not match the release.');
  return { path, digest: info.Digest, archiveSha256: actual };
}

export async function publishReleaseImages(plan, directory, output, { context, getIDToken, mask }) {
  validatePlan(plan);
  // Verify all downloaded inputs before requesting either transient token.
  const sources = {};
  for (const image of plan.images) sources[image.profile] = await inspectSource(directory, plan, image);
  const credentials = await federatedQuayCredentials({ username: process.env.QUAY_USERNAME, context, getIDToken, mask });
  const work = await mkdtemp(join(tmpdir(), 'rambow-quay-'));
  const auth = join(work, 'auth.json');
  try {
    run(['login', '--authfile', auth, '--username', credentials.username, '--password-stdin', 'quay.io'], { input: credentials.token });
    const adapter = {
      inspect: async reference => {
        const result = spawnSync('skopeo', ['inspect', '--authfile', auth, '--format', '{{.Digest}}', 'docker://' + reference], { encoding: 'utf8', timeout: 120000 });
        if (!result.error && result.status === 0) return result.stdout.trim();
        if (!result.error && /manifest unknown|name unknown|manifest not found|StatusCode: 404/i.test(result.stderr ?? '')) return null;
        throw new Error('Cannot establish destination state: ' + (result.error?.message ?? result.stderr?.slice(0, 2000)));
      },
      copy: async (image, reference) => {
        const digestFile = join(work, 'copied.digest');
        run(['copy', '--all', '--preserve-digests', '--authfile', auth, '--digestfile', digestFile,
          'oci-archive:' + sources[image.profile].path, 'docker://' + reference]);
        return (await readFile(digestFile, 'utf8')).trim();
      },
    };
    const record = await publishImages(plan, adapter, { runId: Number(process.env.GITHUB_RUN_ID),
      validationToolsCommit: process.env.VALIDATION_TOOLS_COMMIT,
      progress: state => writeFileSync(resolve(output, 'attempt.json'), json(state)) });
    await writeFile(resolve(output, 'record.json'), json(record));
    console.log('Changed profiles published with frozen digests and nonempty change history; catalog recording follows.');
  } finally {
    try { await unlink(auth); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

async function main() {
  const [mode, ...args] = process.argv.slice(2);
  if (mode === 'inspect-ci') {
    const directory = resolve(args[0] ?? 'dist');
    const profile = process.env.BUILD_PROFILE ?? 'core';
    if (!profiles.includes(profile)) throw new Error('Invalid profile');
    const lockBytes = await readFile(join(directory, 'images.lock.json'), 'utf8');
    const prepared = { sourceCommit: process.env.GITHUB_SHA, imageLock: JSON.parse(lockBytes), lockSha256: hash(lockBytes) };
    const image = { profile, artifactName: basename(directory) };
    const source = await inspectSource(dirname(directory), prepared, image);
    await writeFile(join(directory, 'release-evidence.json'), json({ schemaVersion: 1, profile, sourceCommit: prepared.sourceCommit,
      digest: source.digest, archiveSha256: source.archiveSha256, lockSha256: prepared.lockSha256 }));
    console.log('Verified the exported OCI archive contract for release publication.');
  } else if (mode === 'inspect') {
    const [preparedFile, directory, profile, evidenceFile, layout] = args;
    if (!profiles.includes(profile)) throw new Error('Invalid profile');
    const prepared = JSON.parse(await readFile(preparedFile, 'utf8'));
    const image = prepared.images.find(i => i.profile === profile);
    const source = await inspectSource(directory, prepared, image);
    run(['copy', '--all', '--preserve-digests', 'oci-archive:' + source.path, 'oci:' + resolve(layout)]);
    await writeFile(evidenceFile, json({ profile, sourceCommit: prepared.sourceCommit, sourceRunId: prepared.sourceRun.id,
      artifactId: image.artifactId, lockSha256: prepared.lockSha256, digest: source.digest, archiveSha256: source.archiveSha256 }));
  } else throw new Error('Usage: release-image.mjs inspect-ci [dist] | inspect <prepared> <artifacts> <profile> <evidence> <layout>');
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) await main();
