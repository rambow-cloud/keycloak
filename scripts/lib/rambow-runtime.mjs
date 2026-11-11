import { readImageObject } from './oci.mjs';
import { assertBasePlatforms } from './platforms.mjs';
import { rambowJavaVersion, compareRuntimeVersions } from './runtime-family.mjs';
import { validateRuntimeInventory } from './runtime-sbom.mjs';
import { createHash } from 'node:crypto';

const upstream = { owner: 'rambow-cloud', repo: 'amazon-linux-distroless' };
const prefix = 'https://github.com/rambow-cloud/amazon-linux-distroless/releases/tag/';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const json = value => JSON.stringify(value, null, 2) + '\n';

export function chooseRuntimeRelease(current, releases) {
  const before = rambowJavaVersion(current);
  if (!before) throw Error('Expected the reviewed Rambow Java 25 runtime');
  return releases.filter(release => !release.draft && !release.prerelease)
    .map(release => {
      const match = /^java25-(25\.\d+\.\d+-r[1-9]\d*)$/.exec(release.tag_name ?? '');
      const version = match && rambowJavaVersion('ghcr.io/rambow-cloud/java:' + match[1] + '@sha256:' + '0'.repeat(64));
      return { release, version };
    }).filter(item => item.version && item.version[1] === before[1] && compareRuntimeVersions(item.version, before) > 0)
    .sort((a, b) => compareRuntimeVersions(b.version, a.version))[0]?.release ?? null;
}

async function assetBytes(github, release, name) {
  const assets = await github.paginate(github.rest.repos.listReleaseAssets, { ...upstream, release_id: release.id, per_page: 100 });
  const matches = assets.filter(asset => asset.name === name);
  if (matches.length !== 1 || matches[0].size > 2000000) throw Error('Missing, ambiguous or oversized runtime asset ' + name);
  const { data } = await github.rest.repos.getReleaseAsset({ ...upstream, asset_id: matches[0].id,
    headers: { accept: 'application/octet-stream' } });
  const bytes = Buffer.from(data);
  if (bytes.length > 2000000) throw Error('Runtime asset exceeds limit');
  return bytes;
}

export async function discoverRambowRuntime({ github, current, fetcher = fetch, readObject = readImageObject }) {
  if (!rambowJavaVersion(current)) return { runtime: current, files: {} };
  // Revision tags are immutable. Detect a moved source before selecting a later revision.
  const existing = await readObject(current.split('@')[0], fetcher);
  if (existing.reference !== current) throw Error('Published immutable runtime tag moved');
  const releases = await github.paginate(github.rest.repos.listReleases, { ...upstream, per_page: 100 });
  const release = chooseRuntimeRelease(current, releases);
  if (!release) return { runtime: current, files: {} };
  if (release.html_url !== prefix + release.tag_name) throw Error('Runtime release repository mismatch');
  const stable = JSON.parse(await assetBytes(github, release, 'stable.json'));
  const version = release.tag_name.slice('java25-'.length);
  if (stable.schemaVersion !== 1 || stable.runtime !== 'java25' || stable.version + '-r' + stable.revision !== version ||
      stable.releaseUrl !== release.html_url || !/^[a-f0-9]{40}$/.test(stable.sourceCommit ?? '') ||
      !/^ghcr\.io\/rambow-cloud\/amazon-linux-distroless\/java25@sha256:[a-f0-9]{64}$/.test(stable.reference ?? '') ||
      !/^java25-[a-f0-9]{12}-run[1-9]\d*$/.test(stable.previewRelease?.slice(prefix.length) ?? '') ||
      !stable.previewRelease.startsWith(prefix) || !stable.previewRelease.includes('java25-' + stable.sourceCommit.slice(0, 12) + '-run')) {
    throw Error('Invalid qualified stable Java runtime release');
  }
  const runtime = 'ghcr.io/rambow-cloud/java:' + version + '@' + stable.reference.split('@')[1];
  const index = await readObject(runtime, fetcher);
  assertBasePlatforms(index.value, ['amd64', 'arm64']);
  const { data: preview } = await github.rest.repos.getReleaseByTag({ ...upstream, tag: stable.previewRelease.slice(prefix.length) });
  if (preview.draft || preview.html_url !== stable.previewRelease) throw Error('Invalid runtime inventory release');
  const files = {};
  const metadata = { schemaVersion: 1, reference: runtime, sourceCommit: stable.sourceCommit,
    sourceRelease: release.html_url, architectures: {} };
  const directory = 'dependencies/runtime/' + index.digest.slice(7) + '/';
  for (const architecture of ['amd64', 'arm64']) {
    const children = index.value.manifests.filter(manifest => manifest.platform?.os === 'linux' && manifest.platform.architecture === architecture);
    if (children.length !== 1 || children[0].digest !== stable.leaves?.[architecture]) throw Error('Runtime index and stable child digests differ');
    const child = await readObject(runtime.split('@')[0] + '@' + children[0].digest, fetcher);
    const configDigest = child.value.config?.digest;
    const config = await readObject(runtime.split('@')[0] + '@' + configDigest, fetcher, 'blobs');
    if (config.value.os !== 'linux' || config.value.architecture !== architecture ||
        config.value.config?.User !== '65532:65532' ||
        config.value.config?.Labels?.['org.opencontainers.image.revision'] !== stable.sourceCommit ||
        !Array.isArray(config.value.rootfs?.diff_ids) || !config.value.rootfs.diff_ids.length) throw Error('Runtime config identity mismatch');
    const sbomBytes = await assetBytes(github, preview, architecture + '-sbom.cdx.json');
    const scanBytes = await assetBytes(github, release, 'scan-' + architecture + '.json');
    if ('sha256:' + hash(scanBytes) !== stable.scanHashes?.['scan-' + architecture + '.json']) throw Error('Runtime scan asset checksum mismatch');
    const scan = JSON.parse(scanBytes);
    metadata.architectures[architecture] = { manifest: child.digest, config: configDigest,
      diffIds: config.value.rootfs.diff_ids, sbomSha256: hash(sbomBytes) };
    const inventory = validateRuntimeInventory(runtime, architecture, metadata, sbomBytes);
    const purls = scan.Results?.flatMap(result => result.Packages ?? []).map(pkg => pkg.Identifier?.PURL).sort();
    if (scan.Metadata?.ImageID !== configDigest || scan.Metadata?.OS?.Family !== 'amazon' || scan.Metadata.OS.Name !== '2023' ||
        JSON.stringify(purls) !== JSON.stringify([...inventory.purls].sort())) throw Error('Runtime inventory differs from its stable scan');
    files[directory + architecture + '-sbom.cdx.json'] = sbomBytes.toString('utf8');
  }
  files[directory + 'base.json'] = json(metadata);
  return { runtime, files, release: release.html_url };
}
