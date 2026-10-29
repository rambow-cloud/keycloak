import { readFile } from 'node:fs/promises';
import { nativeArchitecture, lockArchitectures } from './lib/platforms.mjs';
import { resolveImageDigest } from './lib/oci.mjs';
const lock = JSON.parse(await readFile(new URL('../images.lock.json', import.meta.url), 'utf8'));
if (process.argv[2] === 'native') console.log(nativeArchitecture());
else if (process.argv[2] === 'require') {
  if (!lockArchitectures(lock).includes(process.argv[3])) throw Error('Architecture is not in the image lock');
} else if (process.argv[2] === 'bases') {
  for (const key of ['keycloak','builder','runtime','postgres']) await resolveImageDigest(lock[key], fetch, lockArchitectures(lock));
  console.log('All pinned base indexes cover the locked Linux architectures.');
} else throw Error('Usage: platform.mjs native | require <architecture> | bases');
