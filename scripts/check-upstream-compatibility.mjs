import { readFile } from 'node:fs/promises';
import { inspectCompatibility } from './lib/upstream.mjs';

const lock = JSON.parse(await readFile(new URL('../images.lock.json', import.meta.url), 'utf8'));
const baseline = JSON.parse(await readFile(new URL('../config/upstream-compatibility.json', import.meta.url), 'utf8'));
const result = await inspectCompatibility(lock.keycloakVersion, lock.javaVersion, baseline);
if (result.warnings.length) throw new Error(result.warnings.join('\n'));
console.log('Keycloak startup source matches the reviewed baseline; Java ' + lock.javaVersion + ' remains the latest supported LTS.');
