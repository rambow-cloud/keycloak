import { readFile, writeFile, mkdir } from 'node:fs/promises';
const profile = process.argv[2];
if (!['core', 'aws'].includes(profile)) throw Error('Expected core or aws');
const directory = '.cache/ubi10/' + profile;
await mkdir(directory, { recursive: true });
const lock = JSON.parse(await readFile('docs/experiments/ubi10-grype/inputs.lock.json', 'utf8'));
for (const field of ['runtime', 'runtimeBuilder', 'officialJavaRuntime']) {
  if (!/^registry\.access\.redhat\.com\/ubi10\/[\w-]+@sha256:[a-f0-9]{64}$/.test(lock[field])) throw Error('Unpinned UBI input');
}
let source = await readFile('Containerfile', 'utf8');
const replace = (old, next) => {
  if (source.split(old).length !== 2) throw Error('Unexpected production Containerfile');
  source = source.replace(old, next);
};
replace('ARG RUNTIME_IMAGE', 'ARG RUNTIME_IMAGE\nARG EXPERIMENT_BUILD_IMAGE');
replace('FROM ${BUILD_IMAGE} AS source', `FROM \${RUNTIME_IMAGE} AS micro
FROM \${EXPERIMENT_BUILD_IMAGE} AS runtime-root
USER 0
COPY --from=micro / /opt/ubi-root/
COPY docs/experiments/ubi10-grype/prepare-ubi10-runtime.sh /tmp/prepare-runtime.sh
RUN bash /tmp/prepare-runtime.sh

FROM \${BUILD_IMAGE} AS source`);
replace('FROM ${RUNTIME_IMAGE} AS runtime', `FROM scratch AS runtime
COPY --from=runtime-root /opt/ubi-root/ /
COPY docs/experiments/ubi10-grype/licenses/UBI-EULA.pdf /licenses/UBI-EULA.pdf
ENV LANG=en_US.UTF-8`);
await writeFile(directory + '/Containerfile', source);
const ignore = await readFile('.containerignore', 'utf8');
await writeFile(directory + '/containerignore', ignore + '\n!docs\n!docs/experiments\n!docs/experiments/ubi10-grype\n!docs/experiments/ubi10-grype/prepare-ubi10-runtime.sh\n!docs/experiments/ubi10-grype/licenses\n!docs/experiments/ubi10-grype/licenses/UBI-EULA.pdf\n');
await writeFile(directory + '/inputs.json', JSON.stringify({ schemaVersion: 1, profile,
  sourceCommit: process.env.GITHUB_SHA, headCommit: process.env.SCAN_HEAD_SHA,
  images: JSON.parse(await readFile('images.lock.json', 'utf8')), experiment: lock,
  limitation: 'UBI OCI roots are pinned; the public RPM transaction rolls and is inventoried, not production-snapshotted.' }, null, 2) + '\n');
