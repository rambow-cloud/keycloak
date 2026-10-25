// Resolve immutable OCI index digests. Review and commit this file's output through an Issue/PR.
import { writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) throw new Error('Usage: node scripts/lock-images.mjs <x.y.z>');
// Latest LTS explicitly supported by Keycloak 26.8.1; verify official support before changing.
const javaVersion = 25;
const images = {
  keycloak: `quay.io/keycloak/keycloak:${version}`,
  builder: `docker.io/library/eclipse-temurin:${javaVersion}-jdk-noble`,
  runtime: `gcr.io/distroless/java${javaVersion}-debian13:nonroot`,
  postgres: 'docker.io/library/postgres:17-bookworm',
};
async function resolve(reference) {
  const [host, ...parts] = reference.split('/');
  const [repository, tag] = parts.join('/').split(':');
  const registry = host === 'docker.io' ? 'registry-1.docker.io' : host;
  const url = `https://${registry}/v2/${repository}/manifests/${tag}`;
  const headers = { Accept: 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json' };
  let response = await fetch(url, { headers, signal: AbortSignal.timeout(30000) });
  if (response.status === 401) {
    const challenge = response.headers.get('www-authenticate') ?? '';
    const values = Object.fromEntries([...challenge.matchAll(/(\w+)="([^"]*)"/g)].map(m => [m[1], m[2]]));
    if (!values.realm?.startsWith('https://')) throw new Error('Registry did not provide HTTPS token realm');
    const tokenUrl = new URL(values.realm);
    for (const key of ['service', 'scope']) if (values[key]) tokenUrl.searchParams.set(key, values[key]);
    const auth = await fetch(tokenUrl, { signal: AbortSignal.timeout(30000) });
    if (!auth.ok) throw new Error(`Token exchange failed: ${auth.status}`);
    const token = await auth.json();
    headers.Authorization = `Bearer ${token.token ?? token.access_token}`;
    response = await fetch(url, { headers, signal: AbortSignal.timeout(30000) });
  }
  if (!response.ok) throw new Error(`Resolve ${reference}: ${response.status}`);
  const bytes = Buffer.from(await response.arrayBuffer());
  const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  const declared = response.headers.get('docker-content-digest');
  if (declared && declared !== digest) throw new Error(`Digest mismatch: ${reference}`);
  return `${reference}@${digest}`;
}
const resolved = Object.fromEntries(await Promise.all(Object.entries(images).map(async ([key, ref]) => [key, await resolve(ref)])));
await writeFile(new URL('../images.lock.json', import.meta.url), JSON.stringify({ keycloakVersion: version, javaVersion, platform: 'linux/amd64', ...resolved }, null, 2) + '\n');
console.log('Updated images.lock.json; review digests and verify the resulting image before merging.');
