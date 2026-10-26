import { readFile, writeFile, mkdir, appendFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function validateCandidate(candidate) {
  const pinned = value => typeof value === 'string' && /^(registry\.access\.redhat\.com\/ubi10\/ubi(?:-micro)?|ghcr\.io\/bell-sw\/hardened-liberica-runtime-container|dhi\.io\/eclipse-temurin)(?::[\w.-]+)?@sha256:[a-f0-9]{64}$/.test(value);
  if (!pinned(candidate.runtime) || (candidate.runtimeBuilder && !pinned(candidate.runtimeBuilder)) ||
      !/^\/[\w./-]+\/java$/.test(candidate.javaPath) || candidate.javaPath.includes('..') ||
      !['debian', 'redhat', 'alpaquita'].includes(candidate.expectedOS)) throw new Error('Invalid pinned experimental runtime input');
}
function run(command, args) {
  const result = spawnSync(command, args, { encoding: 'utf8', maxBuffer: 2000000, timeout: 120000 });
  if (result.error || result.status !== 0) throw new Error(command + ' failed: ' + (result.error?.message ?? result.stderr?.slice(0, 2500)));
  return result.stdout;
}
function replaceOnce(source, old, next) {
  if (source.split(old).length !== 2) throw new Error('Unexpected production Containerfile structure');
  return source.replace(old, next);
}
export async function prepare(name, profile) {
  if (!['ubi10', 'bellsoft', 'dhi'].includes(name) || !['core', 'aws'].includes(profile)) throw new Error('Unknown runtime/profile');
  const directory = '.cache/runtime-comparison/' + name + '-' + profile;
  await mkdir(directory, { recursive: true });
  const lock = JSON.parse(await readFile('images.lock.json', 'utf8'));
  const config = JSON.parse(await readFile('experiments/images.lock.json', 'utf8'));
  const candidate = { ...config.candidates[name] };
  try {
    if (!candidate.runtime) {
      // Never consume implicit runner credentials. A public digest is frozen
      // before any build; a failed anonymous probe is a blocked experiment.
      if (name !== 'dhi' || candidate.publicProbe !== 'dhi.io/eclipse-temurin:25-debian13') throw new Error('Unexpected public probe');
      const authfile = resolve(directory, 'anonymous-auth.json');
      await writeFile(authfile, '{"auths":{}}\n');
      const metadata = JSON.parse(run('skopeo', ['inspect', '--authfile', authfile, '--override-os', 'linux', '--override-arch', 'amd64', 'docker://' + candidate.publicProbe]));
      if (!/^sha256:[a-f0-9]{64}$/.test(metadata.Digest ?? '') || metadata.Architecture !== 'amd64' || metadata.Os !== 'linux') throw new Error('Invalid public OCI identity');
      candidate.runtime = candidate.publicProbe + '@' + metadata.Digest;
      await writeFile(directory + '/resolved-image.json', JSON.stringify(metadata, null, 2) + '\n');
    }
    validateCandidate(candidate);
    let source = await readFile('Containerfile', 'utf8');
    source = replaceOnce(source, 'ARG RUNTIME_IMAGE', 'ARG RUNTIME_IMAGE\nARG EXPERIMENT_BUILD_IMAGE');
    const point = 'FROM ${BUILD_IMAGE} AS source';
    if (name === 'ubi10') {
      source = replaceOnce(source, point, 'FROM ${RUNTIME_IMAGE} AS micro\nFROM ${EXPERIMENT_BUILD_IMAGE} AS runtime-root\nUSER 0\nCOPY --from=micro / /opt/ubi-root/\nCOPY experiments/prepare-ubi10-runtime.sh /tmp/prepare-ubi-runtime.sh\nRUN bash /tmp/prepare-ubi-runtime.sh\n\n' + point);
      source = replaceOnce(source, 'FROM ${RUNTIME_IMAGE} AS runtime', 'FROM scratch AS runtime\nCOPY --from=runtime-root /opt/ubi-root/ /\nCOPY experiments/licenses/UBI-EULA.pdf /licenses/UBI-EULA.pdf\nENV LANG=en_US.UTF-8');
    } else {
      source = replaceOnce(source, point, 'FROM ${BUILD_IMAGE} AS java-link\nUSER 0\nRUN mkdir -p /java-link/usr/bin && ln -s ' + candidate.javaPath + ' /java-link/usr/bin/java\n\n' + point);
      source = replaceOnce(source, 'FROM ${RUNTIME_IMAGE} AS runtime', 'FROM ${RUNTIME_IMAGE} AS runtime\nCOPY --from=java-link /java-link/ /');
    }
    const file = '.cache/' + name + '-' + profile + '.Containerfile';
    await writeFile(file, source);
    await writeFile(directory + '/Containerfile', source);
    const input = { schemaVersion: 1, candidate: name, profile, candidateConfig: candidate, imageLock: { ...lock, runtime: candidate.runtime }, buildImage: candidate.runtimeBuilder ?? lock.builder,
      sourceCommit: process.env.GITHUB_SHA, headCommit: process.env.SCAN_HEAD_SHA, containerfile: file,
      productionLockSha256: hash(await readFile('images.lock.json')) };
    await writeFile(directory + '/inputs.json', JSON.stringify(input, null, 2) + '\n');
    await writeFile(directory + '/input-status.json', JSON.stringify({ status: 'ready', runtime: candidate.runtime }) + '\n');
    if (process.env.GITHUB_OUTPUT) await appendFile(process.env.GITHUB_OUTPUT, 'directory=' + directory + '\nexpected_os=' + candidate.expectedOS + '\n');
    console.log('Frozen experimental inputs: ' + candidate.runtime);
  } catch (error) {
    await writeFile(directory + '/input-status.json', JSON.stringify({ status: 'blocked', candidate: name, error: error.message }, null, 2) + '\n');
    throw error;
  }
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) await prepare(...process.argv.slice(2));
