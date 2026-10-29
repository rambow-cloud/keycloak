import { createHash } from 'node:crypto';
import { assertBasePlatforms } from './platforms.mjs';

export async function resolveImageDigest(reference, fetcher = fetch, requiredArchitectures = []) {
  if (!/^(quay\.io|gcr\.io|docker\.io)\/[\w./-]+:[\w.-]+(?:@sha256:[a-f0-9]{64})?$/.test(reference)) throw new Error('Invalid or unapproved OCI reference: ' + reference);
  const [tagged, pinned] = reference.split('@');
  const [host, ...parts] = tagged.split('/');
  const [repository, tag] = parts.join('/').split(':');
  const registry = host === 'docker.io' ? 'registry-1.docker.io' : host;
  const url = `https://${registry}/v2/${repository}/manifests/${pinned ?? tag}`;
  const headers = { Accept: 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' };
  let response = await fetcher(url, { headers, signal: AbortSignal.timeout(30000) });
  if (response.status === 401) {
    const values = Object.fromEntries([...(response.headers.get('www-authenticate') ?? '').matchAll(/(\w+)="([^"]*)"/g)].map(m => [m[1], m[2]]));
    if (!values.realm?.startsWith('https://')) throw new Error('Registry did not provide HTTPS token realm');
    const tokenUrl = new URL(values.realm);
    for (const key of ['service', 'scope']) if (values[key]) tokenUrl.searchParams.set(key, values[key]);
    const auth = await fetcher(tokenUrl, { signal: AbortSignal.timeout(30000) });
    if (!auth.ok) throw new Error('Registry token exchange failed: ' + auth.status);
    const token = await auth.json();
    if (!(token.token ?? token.access_token)) throw new Error('Registry token missing');
    headers.Authorization = `Bearer ${token.token ?? token.access_token}`;
    response = await fetcher(url, { headers, signal: AbortSignal.timeout(30000) });
  }
  if (!response.ok) throw new Error(`Resolve ${reference}: ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  const declared = response.headers.get('docker-content-digest');
  if (declared && declared !== digest) throw new Error('Registry digest mismatch: ' + reference);
  if (pinned && pinned !== digest) throw new Error('Pinned registry digest mismatch');
  const manifest = JSON.parse(bytes.toString('utf8'));
  if (manifest.schemaVersion !== 2 || (!manifest.manifests && !manifest.layers)) throw new Error('Invalid OCI manifest: ' + reference);
  if (requiredArchitectures.length) assertBasePlatforms(manifest, requiredArchitectures);
  return `${tagged}@${digest}`;
}
