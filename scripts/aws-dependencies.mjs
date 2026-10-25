// Normal builds fetch only checksum-locked JARs; Maven is used only to refresh the lock.
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir, readdir, unlink } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve, relative, sep } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('../', import.meta.url));
const lockPath = resolve(root, 'dependencies/aws/dependencies.lock.json');
const output = resolve(root, '.cache/aws/providers');
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const pom = await readFile(resolve(root, 'dependencies/aws/pom.xml'));
const imageLockPath = resolve(root, 'images.lock.json');
const imageLock = JSON.parse(await readFile(imageLockPath, 'utf8'));
const ca = imageLock.awsDependencies.rdsCa;
if (ca.url !== 'https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem') throw new Error('Unapproved RDS CA source');
const mode = process.argv[2];
if (!['fetch', 'lock'].includes(mode)) throw new Error('Usage: node scripts/aws-dependencies.mjs fetch|lock');
await mkdir(output, { recursive: true });

function validate(entry) {
  if (!/^[\w.-]+\.jar$/.test(entry.file) || !/^[a-f0-9]{64}$/.test(entry.sha256)) throw new Error('Invalid dependency lock entry');
  const prefix = 'https://repo.maven.apache.org/maven2/';
  if (!entry.url.startsWith(prefix) || new URL(entry.url).origin !== 'https://repo.maven.apache.org' || entry.url.includes('..')) throw new Error('Dependency must come from Maven Central');
  if (/\/org\/postgresql\/|\/io\/netty\/|\/netty-nio-client\/|\/slf4j-api\//.test(entry.url)) throw new Error('Dependency conflicts with Keycloak: ' + entry.file);
}

if (mode === 'lock') {
  // Clear only this task's generated JAR directory before resolving a fresh graph.
  for (const name of await readdir(output)) if (name.endsWith('.jar')) await unlink(resolve(output, name));
  const report = resolve(root, '.cache/aws/dependency-list.txt');
  const args = ['-B', '-q', '-f', resolve(root, 'dependencies/aws/pom.xml'), 'dependency:copy-dependencies',
    '-DincludeScope=runtime', '-Dmdep.useRepositoryLayout=true', '-DoutputDirectory=' + resolve(root, '.cache/aws/repository'),
    'dependency:list', '-DincludeScope=runtime', '-DoutputAbsoluteArtifactFilename=true', '-DoutputFile=' + report];
  const command = process.env.MAVEN_COMMAND || 'mvn';
  const result = spawnSync(command, args, { stdio: 'inherit', shell: process.platform === 'win32' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error('Maven dependency resolution failed');
  const entries = [];
  const listing = await readFile(report, 'utf8');
  for (const line of listing.split(/\r?\n/)) {
    const match = line.trim().match(/^([\w.-]+):([\w.-]+):jar:([^:]+):(compile|runtime):(.+?)(?: --.*)?$/);
    if (!match) continue;
    const [, group, artifact, version, , source] = match;
    const file = artifact + '-' + version + '.jar';
    const url = 'https://repo.maven.apache.org/maven2/' + group.replaceAll('.', '/') + '/' + artifact + '/' + version + '/' + file;
    const bytes = await readFile(source.trim());
    const entry = { file, url, sha256: digest(bytes) };
    validate(entry);
    entries.push(entry);
  }
  if (!entries.some(e => e.file.startsWith('aws-advanced-jdbc-wrapper-')) || !entries.some(e => /^rds-/.test(e.file))) throw new Error('Incomplete Maven dependency report');
  entries.sort((a, b) => a.file.localeCompare(b.file));
  await writeFile(lockPath, JSON.stringify({ pomSha256: digest(pom), artifacts: entries }, null, 2) + '\n');
  const response = await fetch(ca.url, { signal: AbortSignal.timeout(30000) });
  if (!response.ok) throw new Error('RDS CA download failed');
  ca.sha256 = digest(Buffer.from(await response.arrayBuffer()));
  await writeFile(imageLockPath, JSON.stringify(imageLock, null, 2) + '\n');
}

const lock = JSON.parse(await readFile(lockPath, 'utf8'));
if (lock.pomSha256 !== digest(pom)) throw new Error('POM changed; refresh and review the dependency lock');
if (!Array.isArray(lock.artifacts) || !lock.artifacts.length) throw new Error('Empty dependency lock');
const names = new Set();
if (!lock.artifacts.some(e => e.file === 'aws-advanced-jdbc-wrapper-' + imageLock.awsDependencies.wrapperVersion + '.jar') ||
    !lock.artifacts.some(e => e.file === 'rds-' + imageLock.awsDependencies.sdkVersion + '.jar')) throw new Error('Image and dependency version locks disagree');
for (const entry of lock.artifacts) {
  validate(entry);
  if (names.has(entry.file)) throw new Error('Duplicate artifact filename');
  names.add(entry.file);
}
for (const name of await readdir(output)) if (!names.has(name)) {
  const path = resolve(output, name);
  if (relative(output, path).startsWith('..' + sep)) throw new Error('Unsafe output path');
  await unlink(path);
}
await Promise.all(lock.artifacts.map(async entry => {
  const path = resolve(output, entry.file);
  try { if (digest(await readFile(path)) === entry.sha256) return; } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const response = await fetch(entry.url, { signal: AbortSignal.timeout(60000) });
  if (!response.ok) throw new Error('Dependency download failed: ' + entry.file + ' (' + response.status + ')');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (digest(bytes) !== entry.sha256) throw new Error('Dependency checksum mismatch: ' + entry.file);
  await writeFile(path, bytes);
}));
console.log('Verified ' + lock.artifacts.length + ' AWS runtime JARs against the committed lock.');
const caOutput = resolve(root, '.cache/aws/certs');
await mkdir(caOutput, { recursive: true });
if (!/^[a-f0-9]{64}$/.test(ca.sha256)) throw new Error('Invalid RDS CA checksum');
const caResponse = await fetch(ca.url, { signal: AbortSignal.timeout(30000) });
if (!caResponse.ok) throw new Error('RDS CA download failed');
const caBytes = Buffer.from(await caResponse.arrayBuffer());
if (digest(caBytes) !== ca.sha256) throw new Error('RDS CA changed; refresh the lock through a maintenance issue');
await writeFile(resolve(caOutput, 'rds-ca-bundle.pem'), caBytes);
console.log('Verified the public RDS CA bundle against its committed checksum.');
