import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFile, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { nativeArchitecture } from '../scripts/lib/platforms.mjs';
import { readRuntimeSbom } from '../scripts/lib/runtime-sbom.mjs';
import { validateTelemetryOverride } from '../scripts/opentelemetry-dependencies.mjs';

const architecture = process.env.PROBE_ARCH;
assert.equal(process.platform, 'linux');
assert.equal(nativeArchitecture(), architecture);
const output = resolve('.cache/grype-keycloak-sbom');
const work = await mkdtemp(join(tmpdir(), 'grype-keycloak-'));
await mkdir(output, { recursive: true });

const readJson = async path => JSON.parse(await readFile(path, 'utf8'));
const writeJson = (path, value) => writeFile(path, JSON.stringify(value, null, 2) + '\n');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const { plan } = await readJson('releases/records/v26.8.2-r2.json');
const guava = await readJson('dependencies/keycloak/overrides.lock.json');
const otel = await readJson('dependencies/keycloak/opentelemetry.lock.json');
const telemetryArtifacts = validateTelemetryOverride(otel, plan.keycloakVersion);
const inventory = await readRuntimeSbom(plan.imageLock.runtime, architecture);
const originalPath = join(output, 'runtime.cdx.json');
await copyFile(inventory.path, originalPath);
const original = await readJson(originalPath);
const os = original.components.find(component => component.type === 'operating-system');
const rpms = original.components.filter(component => inventory.purls.includes(component.purl));

function run(command, args, env = process.env) {
  const result = spawnSync(command, args, { env, encoding: 'utf8', maxBuffer: 48 * 1024 * 1024, timeout: 480000 });
  if (result.error) throw result.error;
  return result;
}

function checked(command, args, env) {
  const result = run(command, args, env);
  assert.equal(result.status, 0, result.stderr.slice(-6000));
  return result.stdout;
}

async function install(name, version, expectedHash) {
  const archive = name + '_' + version + '_linux_' + architecture + '.tar.gz';
  const url = 'https://github.com/anchore/' + name + '/releases/download/v' + version + '/' + archive;
  const response = await fetch(url, { signal: AbortSignal.timeout(120000) });
  assert.ok(response.ok, name + ' archive download failed with HTTP ' + response.status);
  const bytes = Buffer.from(await response.arrayBuffer());
  assert.equal(hash(bytes), expectedHash, name + ' archive checksum mismatch');
  const path = join(work, archive);
  await writeFile(path, bytes);
  checked('tar', ['-xzf', path, '-C', work, '--no-same-owner', name]);
  const binary = join(work, name);
  await writeFile(join(output, name + '-version.txt'), checked(binary, ['version']));
  return binary;
}

async function readBlob(layout, digest) {
  assert.match(digest, /^sha256:[a-f0-9]{64}$/);
  const bytes = await readFile(join(layout, 'blobs', 'sha256', digest.slice(7)));
  assert.equal('sha256:' + hash(bytes), digest);
  return JSON.parse(bytes);
}

function verifiedJavaInventory(java) {
  assert.equal(java.bomFormat, 'CycloneDX');
  const packages = java.components.filter(component => component.properties?.some(property =>
    property.name === 'syft:package:type' && property.value === 'java-archive'));
  assert.ok(packages.length, 'Syft found no Java archives');
  const corrections = [];
  for (const artifact of telemetryArtifacts) {
    // The optimized distribution keeps the original filenames after replacing the JAR bytes.
    const path = '/opt/keycloak/' + artifact.path;
    const file = java.components.find(component => component.type === 'file' && component.name === path);
    assert.ok(file?.hashes.some(entry => entry.alg === 'SHA-256' && entry.content === artifact.sha256),
      'Syft file hash does not confirm the reviewed OpenTelemetry JAR at ' + path);
    const index = packages.findIndex(component => component.name === artifact.artifactId &&
      component.properties.some(property => property.name === 'syft:location:0:path' && property.value === path));
    assert.ok(index >= 0, 'Missing Syft package for ' + path);
    const component = packages[index];
    const version = artifact.url.split('/').at(-2);
    const purl = 'pkg:maven/io.opentelemetry/' + artifact.artifactId + '@' + version;
    const originalRef = component['bom-ref'];
    assert.ok(originalRef.startsWith(component.purl));
    const ref = purl + originalRef.slice(component.purl.length);
    const { cpe, properties, ...data } = component;
    packages[index] = { ...data, 'bom-ref': ref, group: 'io.opentelemetry', version, purl,
      properties: properties.filter(property => property.name !== 'syft:cpe23') };
    corrections.push({ path, sha256: artifact.sha256, originalPurl: component.purl, purl, originalRef, ref });
  }
  return { packages, corrections };
}

function mergeSboms(java, packages, corrections, reference, digest) {
  const root = { type: 'container', name: reference, version: digest, 'bom-ref': reference };
  const components = [os, ...rpms, ...packages];
  const refs = new Set(components.map(component => component['bom-ref']));
  assert.ok(!refs.has(undefined) && !refs.has(reference) && refs.size === components.length,
    'Combined inventory has missing or duplicate component references');
  const javaRoot = java.metadata.component['bom-ref'];
  const replacements = new Map(corrections.map(({ originalRef, ref }) => [originalRef, ref]));
  const translate = ref => replacements.get(ref) ?? ref;
  return {
    ...java,
    metadata: { ...java.metadata, component: root },
    components,
    dependencies: [
      { ref: reference, dependsOn: [os['bom-ref'], ...packages.map(component => component['bom-ref'])] },
      { ref: os['bom-ref'], dependsOn: rpms.map(component => component['bom-ref']) },
      ...(java.dependencies ?? []).filter(edge => edge.ref !== javaRoot && refs.has(translate(edge.ref)))
        .map(edge => ({ ref: translate(edge.ref), dependsOn: (edge.dependsOn ?? []).map(translate).filter(ref => refs.has(ref)) })),
    ],
  };
}

const [syft, grype] = await Promise.all([
  install('syft', '1.57.0', process.env.SYFT_SHA256),
  install('grype', '0.121.2', process.env.GRYPE_SHA256),
]);
const grypeEnv = { ...process.env, GRYPE_DB_CACHE_DIR: join(work, 'grype-db'), GRYPE_DB_AUTO_UPDATE: 'false' };
checked(grype, ['db', 'update'], grypeEnv);
await writeFile(join(output, 'grype-db-status.txt'), checked(grype, ['db', 'status'], grypeEnv));
const results = [];
for (const profile of ['core', 'aws']) {
  const published = plan.images.find(image => image.profile === profile);
  const { digest } = published.children.find(child => child.architecture === architecture);
  const reference = plan.registry + '@' + digest;
  const layout = join(work, profile);
  const directory = join(output, profile);
  await mkdir(directory);
  console.log('Scanning ' + profile + ' linux/' + architecture + ' ' + reference);
  checked('skopeo', ['copy', '--preserve-digests', 'docker://' + reference, 'oci:' + layout + ':scan']);
  const { manifests } = await readJson(join(layout, 'index.json'));
  assert.deepEqual(manifests.map(manifest => manifest.digest), [digest]);
  const manifest = await readBlob(layout, digest);
  const config = await readBlob(layout, manifest.config.digest);
  assert.equal(config.architecture, architecture);
  assert.equal(config.os, 'linux');
  assert.deepEqual(config.rootfs.diff_ids.slice(0, inventory.base.diffIds.length), inventory.base.diffIds,
    'Published child does not inherit the verified base layers');
  await writeJson(join(directory, 'target.json'), {
    architecture, profile, reference, digest, configDigest: manifest.config.digest, tag: published.tag,
    base: inventory.base, runtime: inventory.reference, sourceCommit: plan.sourceCommit,
  });

  const javaPath = join(directory, 'java.cdx.json');
  checked(syft, ['scan', 'oci-dir:' + layout, '--select-catalogers', 'java',
    '-o', 'cyclonedx-json=' + javaPath, '-o', 'syft-json=' + join(directory, 'java.syft.json')]);
  await rm(layout, { recursive: true });
  const java = await readJson(javaPath);
  const { packages, corrections } = verifiedJavaInventory(java);
  await writeJson(join(directory, 'java-corrections.json'), corrections);
  const maven = packages.filter(component => component.purl?.startsWith('pkg:maven/'));
  const hasMaven = (name, version) => maven.some(component => component.purl.split('?')[0] ===
    'pkg:maven/' + name + '@' + version);
  const expected = [
    ['org.keycloak/keycloak-core', plan.keycloakVersion],
    ['com.google.guava/guava', guava.version],
    ['io.opentelemetry/opentelemetry-api', otel.version],
  ];
  for (const [name, version] of expected) {
    assert.ok(hasMaven(name, version), 'Syft did not find ' + name + '@' + version);
  }
  assert.equal(hasMaven('software.amazon.jdbc/aws-advanced-jdbc-wrapper', plan.imageLock.awsDependencies.wrapperVersion),
    profile === 'aws', 'Unexpected AWS JDBC wrapper coverage');

  const mergedPath = join(directory, 'combined.cdx.json');
  await writeJson(mergedPath, mergeSboms(java, packages, corrections, reference, digest));
  const result = run(grype, ['sbom:' + mergedPath, '--distro', 'amzn:2023', '-vv', '-o', 'json'], grypeEnv);
  await writeFile(join(directory, 'grype.log'), result.stderr);
  await writeFile(join(directory, 'grype.json'), result.stdout);
  assert.equal(result.status, 0, result.stderr.slice(-6000));
  const report = JSON.parse(result.stdout);
  assert.equal(report.distro.name, 'amazonlinux');
  assert.equal(report.distro.version, '2023');
  const imported = new Set([...result.stderr.matchAll(/id="(pkg:[^"\s]+)"/g)].map(match => match[1]));
  assert.deepEqual([...imported].filter(purl => purl.startsWith('pkg:rpm/')).sort(), [...inventory.purls].sort(),
    'Grype did not read the original RPM identities');
  // Grype does not log every package identity at debug level. Use its catalog count.
  const gatheredPackages = Number(/gathered packages packages=(\d+)\b/.exec(result.stderr)?.[1]);
  assert.equal(gatheredPackages, rpms.length + packages.length, 'Grype package count differs from the combined inventory');
  const summary = {
    architecture, profile, digest, rpmCount: rpms.length, javaComponents: packages.length,
    verifiedTelemetryJars: corrections.length,
    mavenIdentities: new Set(maven.map(component => component.purl)).size,
    gatheredPackages,
    matches: report.matches.length,
    rpmMatches: report.matches.filter(match => match.artifact.type === 'rpm').length,
    ignoredMatches: report.ignoredMatches?.length ?? 0,
    database: report.descriptor.db,
  };
  await writeJson(join(directory, 'summary.json'), summary);
  results.push(summary);
  console.log(JSON.stringify(summary));
}

assert.deepEqual(results[0].database, results[1].database, 'Grype database changed between profiles');
await appendFile(process.env.GITHUB_STEP_SUMMARY, '## Keycloak Grype SBOM experiment (' + architecture + ')\n\n' +
  '| Profile | RPMs | Syft Java components | Packages loaded by Grype | RPM matches | All matches |\n' +
  '| --- | ---: | ---: | ---: | ---: | ---: |\n' +
  results.map(result => '| ' + [result.profile, result.rpmCount, result.javaComponents, result.gatheredPackages,
    result.rpmMatches, result.matches].join(' | ') + ' |\n').join(''));
