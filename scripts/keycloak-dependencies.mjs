import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
export function validateOverride(lock, keycloakVersion) {
  const keys = ['schemaVersion', 'keycloakVersion', 'upstreamVersion', 'upstreamSha256', 'version', 'sha256'];
  if (!lock || Object.keys(lock).length !== keys.length || Object.keys(lock).some(k => !keys.includes(k)) ||
      lock.schemaVersion !== 1 || !/^\d+\.\d+\.\d+$/.test(lock.keycloakVersion) || lock.keycloakVersion !== keycloakVersion ||
      !/^\d+\.\d+\.\d+-jre$/.test(lock.upstreamVersion) || !/^\d+\.\d+\.\d+-jre$/.test(lock.version) ||
      !/^[a-f0-9]{64}$/.test(lock.upstreamSha256) || !/^[a-f0-9]{64}$/.test(lock.sha256) ||
      lock.upstreamSha256 === lock.sha256 || lock.upstreamVersion === lock.version) {
    throw new Error('Invalid Guava override or Keycloak version changed; review/retire the override.');
  }
  return { path: 'lib/lib/main/com.google.guava.guava-' + lock.upstreamVersion + '.jar',
    url: 'https://repo.maven.apache.org/maven2/com/google/guava/guava/' + lock.version + '/guava-' + lock.version + '.jar' };
}

export async function prepareOverride(lock, keycloakVersion, output, fetcher = fetch) {
  const { path, url } = validateOverride(lock, keycloakVersion);
  const jar = resolve(output, 'guava.jar');
  let bytes;
  try { bytes = await readFile(jar); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  if (!bytes || digest(bytes) !== lock.sha256) {
    const response = await fetcher(url, { redirect: 'error', signal: AbortSignal.timeout(60000) });
    if (!response.ok) throw new Error('Guava download failed: ' + response.status);
    bytes = Buffer.from(await response.arrayBuffer());
    if (digest(bytes) !== lock.sha256) throw new Error('Guava checksum mismatch');
  }
  await mkdir(output, { recursive: true });
  await writeFile(jar, bytes);
  await writeFile(resolve(output, 'upstream.sha256'), lock.upstreamSha256 + '  ' + path + '\n');
  await writeFile(resolve(output, 'patched.sha256'), lock.sha256 + '  ' + path + '\n');
  await writeFile(resolve(output, 'version.txt'), lock.version + '\n');
  console.log('Verified Guava ' + lock.version + '; original distribution checksum is enforced before optimization.');
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const lock = JSON.parse(await readFile(resolve(root, 'dependencies/keycloak/overrides.lock.json'), 'utf8'));
  const images = JSON.parse(await readFile(resolve(root, 'images.lock.json'), 'utf8'));
  await prepareOverride(lock, images.keycloakVersion, resolve(root, '.cache/keycloak'));
}
