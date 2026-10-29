import { readFile, writeFile, mkdir, readdir, copyFile, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { architectures } from './platforms.mjs';

export const indexType = 'application/vnd.oci.image.index.v1+json';
const manifestType = 'application/vnd.oci.image.manifest.v1+json';
const digest = bytes => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
export async function fileHash(path) {
  const hash = createHash('sha256');
  for await (const bytes of createReadStream(path)) hash.update(bytes);
  return hash.digest('hex');
}
function blobPath(layout, descriptor) {
  if (!/^sha256:[a-f0-9]{64}$/.test(descriptor?.digest) || !Number.isSafeInteger(descriptor.size) || descriptor.size < 1 || descriptor.size > 2000000000 || descriptor.urls) throw Error('Invalid OCI descriptor');
  return join(layout, 'blobs', 'sha256', descriptor.digest.slice(7));
}
async function readJSONBlob(layout, descriptor) {
  if (descriptor.size > 10000000) throw Error('OCI metadata exceeds limit');
  const bytes = await readFile(blobPath(layout, descriptor));
  if (bytes.length !== descriptor.size || digest(bytes) !== descriptor.digest) throw Error('OCI metadata digest/size mismatch');
  return JSON.parse(bytes);
}
export function validateChildren(children, expected = architectures) {
  if (!Array.isArray(children) || children.length !== expected.length || expected.some(architecture =>
    children.filter(c => c.architecture === architecture && /^sha256:[a-f0-9]{64}$/.test(c.digest)).length !== 1)) throw Error('Missing, duplicate or unexpected architecture child');
  return children;
}
export async function inspectLayout(layout, identity, expected = architectures) {
  const root = JSON.parse(await readFile(join(layout, 'index.json'), 'utf8'));
  if (root.schemaVersion !== 2 || root.manifests?.length !== 1) throw Error('OCI layout must select exactly one image/index');
  const descriptor = root.manifests[0];
  const manifest = await readJSONBlob(layout, descriptor);
  const entries = descriptor.mediaType === indexType ? manifest.manifests : [descriptor];
  if (manifest.schemaVersion !== 2 || !Array.isArray(entries)) throw Error('Invalid OCI index');
  const children = [];
  for (const entry of entries) {
    if (entry.mediaType !== manifestType) throw Error('Only OCI image manifests are accepted');
    const image = await readJSONBlob(layout, entry);
    if (image.schemaVersion !== 2 || image.mediaType !== manifestType || !Array.isArray(image.layers) || !image.layers.length) throw Error('Invalid OCI image manifest');
    const config = await readJSONBlob(layout, image.config);
    const labels = config.config?.Labels;
    if (config.os !== 'linux' || !expected.includes(config.architecture) ||
        (entry.platform && (entry.platform.os !== config.os || entry.platform.architecture !== config.architecture || (entry.platform.variant && entry.platform.variant !== 'v8'))) ||
        labels?.['org.opencontainers.image.revision'] !== identity.sourceCommit || labels?.['org.opencontainers.image.version'] !== identity.keycloakVersion ||
        labels?.['cloud.rambow.keycloak.profile'] !== identity.profile) throw Error('OCI config architecture/source/version/profile mismatch');
    for (const layer of image.layers) {
      const path = blobPath(layout, layer);
      if ((await stat(path)).size !== layer.size || 'sha256:' + await fileHash(path) !== layer.digest) throw Error('OCI layer checksum mismatch');
    }
    children.push({ architecture: config.architecture, digest: entry.digest });
  }
  validateChildren(children, expected);
  if (expected.length > 1 && descriptor.mediaType !== indexType) throw Error('Multi-architecture artifact requires an OCI index');
  return { digest: descriptor.digest, children: children.sort((a,b) => a.architecture.localeCompare(b.architecture)), descriptor };
}
export async function combineLayouts(inputs, destination, identity) {
  if (inputs.length !== architectures.length || new Set(inputs.map(i => i.architecture)).size !== architectures.length) throw Error('Both native architecture inputs are required');
  await mkdir(join(destination, 'blobs', 'sha256'), { recursive: true });
  const manifests = [];
  for (const architecture of architectures) {
    const input = inputs.find(i => i.architecture === architecture);
    if (!input) throw Error('Missing native architecture input');
    const inspected = await inspectLayout(input.path, identity, [architecture]);
    if (inspected.descriptor.mediaType !== manifestType) throw Error('Native input must be a single image');
    for (const name of await readdir(join(input.path, 'blobs', 'sha256'))) {
      if (!/^[a-f0-9]{64}$/.test(name)) throw Error('Invalid OCI blob path');
      await copyFile(join(input.path, 'blobs', 'sha256', name), join(destination, 'blobs', 'sha256', name));
    }
    manifests.push({ mediaType: manifestType, digest: inspected.digest, size: inspected.descriptor.size, platform: { os: 'linux', architecture } });
  }
  const bytes = JSON.stringify({ schemaVersion: 2, mediaType: indexType, manifests }) + '\n';
  const index = { mediaType: indexType, digest: digest(bytes), size: Buffer.byteLength(bytes), annotations: { 'org.opencontainers.image.ref.name': 'keycloak' } };
  await writeFile(blobPath(destination, index), bytes);
  await writeFile(join(destination, 'oci-layout'), JSON.stringify({ imageLayoutVersion: '1.0.0' }) + '\n');
  await writeFile(join(destination, 'index.json'), JSON.stringify({ schemaVersion: 2, manifests: [index] }) + '\n');
  return { digest: index.digest, children: manifests.map(m => ({ architecture: m.platform.architecture, digest: m.digest })) };
}
