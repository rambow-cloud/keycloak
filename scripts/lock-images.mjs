// Refresh immutable digests within the reviewed image families, then submit an Issue/PR.
import { readFile, writeFile } from 'node:fs/promises';
import { resolveImageDigest } from './lib/oci.mjs';
import { lockArchitectures } from './lib/platforms.mjs';

const version = process.argv[2];
if (!/^\d+\.\d+\.\d+$/.test(version ?? '')) throw new Error('Usage: node scripts/lock-images.mjs <x.y.z>');
const path = new URL('../images.lock.json', import.meta.url);
const previous = JSON.parse(await readFile(path, 'utf8'));
const images = {
  keycloak: `quay.io/keycloak/keycloak:${version}`,
  ...Object.fromEntries(['builder', 'runtime', 'postgres'].map(key => [key, previous[key].split('@')[0]])),
};
const resolved = Object.fromEntries(await Promise.all(Object.entries(images).map(async ([key, ref]) => [key, await resolveImageDigest(ref, fetch, lockArchitectures(previous))])));
await writeFile(path, JSON.stringify({ ...previous, keycloakVersion: version, ...resolved }, null, 2) + '\n');
console.log('Updated images.lock.json; review compatibility and verify the resulting image before merging.');
