import { readFile, writeFile, mkdir, stat, readdir } from 'node:fs/promises';
import { openSync, closeSync, createReadStream } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const directory = 'docs/experiments/ubi10-grype';
const output = '.cache/ubi10-grype-report';
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
async function hashFile(path) {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest('hex');
}
function run(command, args, file) {
  const fd = file ? openSync(file, 'w') : null;
  try {
    const result = spawnSync(command, args, { encoding: 'utf8', timeout: 900000, maxBuffer: 5000000,
      stdio: file ? ['ignore', fd, 'inherit'] : ['ignore', 'pipe', 'inherit'] });
    if (result.error || result.status !== 0) throw Error(command + ' failed: ' + (result.error?.message ?? result.status));
    return result.stdout;
  } finally { if (fd !== null) closeSync(fd); }
}
export function isGuavaFinding(match) {
  return [match.vulnerability, ...(match.relatedVulnerabilities ?? []), ...(match.vulnerability?.relatedVulnerabilities ?? [])]
    .some(v => ['CVE-2026-102554', 'GHSA-xxph-c9ww-hj94'].includes(v?.id));
}
export function summarize(report, inventory, runtime) {
  const errors = [];
  const database = report.descriptor?.db?.status;
  const family = runtime === 'ubi10' ? /rhel|redhat|red hat/i : /debian/i;
  const major = runtime === 'ubi10' ? /^10(?:\.|$)/ : /^13(?:\.|$)/;
  const distro = inventory.distro ?? {};
  if (!family.test(distro.id ?? distro.name ?? '') || !major.test(distro.versionID ?? distro.version ?? '')) errors.push('Unexpected inventory OS');
  if (!family.test(report.distro?.name ?? '') || !major.test(report.distro?.version ?? '')) errors.push('Unexpected Grype OS');
  if (report.descriptor?.name !== 'grype' || report.descriptor?.version !== '0.121.0' ||
      database?.valid !== true || !/^v?6\./.test(database?.schemaVersion ?? '') ||
      !Number.isFinite(Date.parse(database?.built ?? '')) || database?.error) errors.push('Scanner/database identity or status invalid');
  if (!Array.isArray(report.matches) || !Array.isArray(inventory.artifacts)) throw Error('Incomplete scan/inventory JSON');
  const osType = runtime === 'ubi10' ? 'rpm' : 'deb';
  const os = inventory.artifacts.filter(p => p.type === osType);
  const jars = inventory.artifacts.filter(p => p.type === 'java-archive');
  const application = jars.filter(p => p.locations?.some(l => (l.path ?? l.accessPath ?? '').includes('/opt/keycloak/')));
  if (!os.length || !application.length) errors.push('Missing OS or Keycloak Java package inventory');
  if (!application.some(p => /guava/i.test(p.name) && p.version === '33.7.2-jre')) errors.push('Patched Guava missing');
  const counts = Object.fromEntries(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN'].map(s => [s, { total: 0, fixable: 0 }]));
  let blocking = 0;
  const namespaces = new Set();
  const matches = report.matches.map(m => {
    const v = m.vulnerability;
    if (!v?.id || !m.artifact?.name || !m.artifact?.type) throw Error('Malformed vulnerability match');
    const severity = String(v.severity ?? 'UNKNOWN').toUpperCase();
    const level = Object.hasOwn(counts, severity) ? severity : 'UNKNOWN';
    const fixable = Array.isArray(v.fix?.versions) && v.fix.versions.length > 0;
    counts[level].total++; if (fixable) counts[level].fixable++;
    if (fixable && ['HIGH', 'CRITICAL'].includes(level)) blocking++;
    if (v.namespace) namespaces.add(v.namespace);
    return { id: v.id, severity: level, package: m.artifact.name, version: m.artifact.version,
      type: m.artifact.type, fixes: v.fix?.versions ?? [], fixState: v.fix?.state,
      namespace: v.namespace, matchTypes: m.matchDetails?.map(d => d.type) ?? [], url: v.dataSource };
  });
  if (report.matches.some(isGuavaFinding)) errors.push('Guava defect still detected');
  const jvmPackages = inventory.artifacts.filter(p => p.type === 'java-jvm' ||
    (p.type === osType && /java-\d+-openjdk|temurin|openjdk|jre/i.test(p.name)));
  const summarizePackage = p => ({ name: p.name, version: p.version, type: p.type, purl: p.purl, cpes: p.cpes, metadata: p.metadata });
  return { status: errors.length ? 'coverage-failed' : 'complete', errors, distro: report.distro,
    database: database ? { ...database, providers: report.descriptor.db.providers } : undefined, counts, total: report.matches.length,
    uniqueAdvisories: new Set(matches.map(m => m.id)).size, blocking, namespaces: [...namespaces].sort(),
    inventory: { os: os.length, jars: jars.length, applicationJars: application.length, jvm: jvmPackages.map(summarizePackage) },
    applicationPackages: application.map(p => ({ name: p.name, version: p.version, purl: p.purl })).sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    jvmMatches: matches.filter(m => m.type === 'java-jvm' || /java-\d+-openjdk|temurin|openjdk|jre/i.test(m.package)), matches };
}

async function downloadTools(lock) {
  const destination = resolve(output, 'tools');
  await mkdir(destination, { recursive: true });
  for (const name of ['grype', 'syft']) {
    const pin = lock[name];
    if (!/^\d+\.\d+\.\d+$/.test(pin.version) || !/^[a-f0-9]{64}$/.test(pin.sha256)) throw Error('Invalid tool lock');
    const url = 'https://github.com/anchore/' + name + '/releases/download/v' + pin.version + '/' + name + '_' + pin.version + '_linux_amd64.tar.gz';
    const response = await fetch(url, { signal: AbortSignal.timeout(120000) });
    if (!response.ok) throw Error('Tool download HTTP ' + response.status);
    const bytes = Buffer.from(await response.arrayBuffer());
    if (digest(bytes) !== pin.sha256) throw Error(name + ' checksum mismatch');
    const archive = resolve(destination, name + '.tar.gz');
    await writeFile(archive, bytes);
    run('tar', ['-xzf', archive, '-C', destination, name]);
  }
  return { grype: resolve(destination, 'grype'), syft: resolve(destination, 'syft') };
}
async function controls(grype) {
  const lock = JSON.parse(await readFile('dependencies/keycloak/overrides.lock.json', 'utf8'));
  const states = [];
  for (const [label, version, expected] of [['vulnerable', lock.upstreamVersion, lock.upstreamSha256], ['fixed', lock.version, lock.sha256]]) {
    const dir = resolve(output, 'control-' + label);
    await mkdir(dir, { recursive: true });
    const response = await fetch('https://repo.maven.apache.org/maven2/com/google/guava/guava/' + version + '/guava-' + version + '.jar');
    if (!response.ok) throw Error('Control download failed');
    const bytes = Buffer.from(await response.arrayBuffer());
    if (digest(bytes) !== expected) throw Error('Control checksum mismatch');
    await writeFile(resolve(dir, 'guava-' + version + '.jar'), bytes);
    const file = resolve(output, 'control-' + label + '.json');
    run(grype, ['dir:' + dir, '-o', 'json'], file);
    const report = JSON.parse(await readFile(file, 'utf8'));
    states.push({ label, version, matched: report.matches.some(isGuavaFinding), database: report.descriptor.db.status });
  }
  if (!states[0].matched || states[1].matched) throw Error('Vulnerable/fixed Guava controls failed');
  await writeFile(resolve(output, 'controls.json'), JSON.stringify(states, null, 2) + '\n');
  return states;
}
export function render(rows) {
  let md = '# UBI 10 and distroless comparison\n\n' +
    'Same application/provider inputs; one frozen Grype DB. Raw counts reflect different vendor feeds and package inventories, not exploitability ratios.\n\n' +
    '| Runtime | Profile | Actual Java | Vendor | OS packages / app JARs | Findings / unique advisories | Fixable HIGH/CRITICAL | Coverage |\n| --- | --- | --- | --- | --- | --- | --- | --- |\n';
  for (const r of rows) {
    const safe = v => String(v ?? 'unknown').replaceAll('|', '&#124;').replaceAll('\n', ' ');
    md += '| ' + [r.runtime, r.profile, r.java?.['java.runtime.version'], r.java?.['java.vendor'],
      r.inventory ? r.inventory.os + ' / ' + r.inventory.applicationJars : 'unknown',
      r.total === undefined ? 'unknown' : r.total + ' / ' + r.uniqueAdvisories, r.blocking, r.status].map(safe).join(' | ') + ' |\n';
  }
  return md + '\nComplete machine reports include image digests, size/media types, RPM inventory, JVM/trust-store identity, match namespaces/methods and coverage limitations. No production adoption or experimental registry publication occurred.\n';
}
async function main() {
  await mkdir(output, { recursive: true });
  const lock = JSON.parse(await readFile(directory + '/inputs.lock.json', 'utf8'));
  const tools = await downloadTools(lock);
  process.env.GRYPE_DB_CACHE_DIR = resolve('.cache/ubi10-grype-db');
  process.env.GRYPE_DB_AUTO_UPDATE = 'false';
  process.env.GRYPE_CHECK_FOR_APP_UPDATE = 'false';
  process.env.SYFT_CHECK_FOR_APP_UPDATE = 'false';
  process.env.SYFT_JAVA_USE_NETWORK = 'false';
  run(tools.grype, ['version'], resolve(output, 'grype-version.txt'));
  run(tools.syft, ['version'], resolve(output, 'syft-version.txt'));
  run(tools.grype, ['db', 'update']);
  run(tools.grype, ['db', 'status'], resolve(output, 'database-status.txt'));
  run(tools.grype, ['db', 'status', '-o', 'json'], resolve(output, 'database-status.json'));
  const databaseStatus = JSON.parse(await readFile(resolve(output, 'database-status.json'), 'utf8'));
  if (databaseStatus.valid !== true || !databaseStatus.path) throw Error('Native Grype DB validation failed');
  let databaseFile = databaseStatus.path;
  if ((await stat(databaseFile)).isDirectory()) {
    const files = (await readdir(databaseFile)).filter(name => name.endsWith('.db'));
    if (files.length !== 1) throw Error('Cannot identify the frozen database');
    databaseFile = resolve(databaseFile, files[0]);
  }
  const databaseSha256 = await hashFile(databaseFile);
  const control = await controls(tools.grype);
  const images = JSON.parse(await readFile('images.lock.json', 'utf8'));
  const probe = resolve(output, 'probe');
  await mkdir(probe, { recursive: true });
  run('podman', ['run', '--rm', '--network=none', '-v', resolve(directory) + ':/source:ro', '-v', probe + ':/out:rw',
    '--entrypoint', 'javac', images.builder, '--release', '25', '-d', '/out', '/source/JavaRuntimeInfo.java']);
  run('skopeo', ['inspect', '--config', '--override-os', 'linux', '--override-arch', 'amd64', 'docker://' + lock.officialJavaRuntime], resolve(output, 'official-ubi-java-image-config.json'));
  const rows = [];
  const artifactSource = process.env.ARTIFACT_SOURCE_SHA || process.env.GITHUB_SHA;
  for (const runtime of ['distroless', 'ubi10']) for (const profile of ['core', 'aws']) {
    const key = runtime + '-' + profile;
    const dir = resolve(output, key);
    await mkdir(dir, { recursive: true });
    try {
      const input = resolve('.cache/comparison-inputs', (runtime === 'ubi10' ? 'ubi10' : 'keycloak') + '-oci-' + profile + '-amd64-' + artifactSource);
      const archive = resolve(input, 'keycloak.oci.tar');
      const hash = await hashFile(archive);
      if (!(await readFile(archive + '.sha256', 'utf8')).startsWith(hash + '  keycloak.oci.tar')) throw Error('Archive checksum mismatch');
      const info = JSON.parse(run('skopeo', ['inspect', 'oci-archive:' + archive]));
      if (info.Architecture !== 'amd64' || info.Os !== 'linux' || info.Labels?.['org.opencontainers.image.revision'] !== artifactSource ||
          info.Labels?.['cloud.rambow.keycloak.profile'] !== profile) throw Error('Image provenance/profile mismatch');
      const manifest = JSON.parse(run('skopeo', ['inspect', '--raw', 'oci-archive:' + archive]));
      const local = 'localhost/grype-comparison:' + key;
      const imageID = run('podman', ['pull', '--quiet', '--retry=0', 'oci-archive:' + archive]).trim().split('\n').at(-1);
      if (!/^(?:sha256:)?[a-f0-9]{64}$/.test(imageID)) throw Error('Unexpected local OCI image identity');
      run('podman', ['tag', imageID, local]);
      const size = JSON.parse(run('podman', ['image', 'inspect', local]))[0].Size;
      run('podman', ['run', '--rm', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--memory=256m',
        '-v', probe + ':/probe:ro', '--entrypoint', '/usr/bin/java', local, '-Xmx128m', '-cp', '/probe', 'JavaRuntimeInfo'], resolve(dir, 'java.json'));
      const java = JSON.parse(await readFile(resolve(dir, 'java.json'), 'utf8'));
      const sbom = resolve(dir, 'inventory.json');
      run(tools.syft, ['oci-archive:' + archive, '-o', 'syft-json=' + sbom]);
      run(tools.grype, ['sbom:' + sbom, '-o', 'json'], resolve(dir, 'grype.json'));
      const scan = JSON.parse(await readFile(resolve(dir, 'grype.json'), 'utf8'));
      const inventory = JSON.parse(await readFile(sbom, 'utf8'));
      const summary = summarize(scan, inventory, runtime);
      const runtimeStatus = runtime === 'ubi10' ? JSON.parse(await readFile(resolve(input, 'runtime-status.json'), 'utf8')).status : process.env.BASELINE_RESULT;
      const row = { runtime, profile, ...summary, java, runtimeStatus, imageDigest: info.Digest, archiveSha256: hash,
        layerBytes: manifest.layers.reduce((sum, l) => sum + l.size, 0), layerMediaTypes: [...new Set(manifest.layers.map(l => l.mediaType))], uncompressedBytes: size,
        inventorySha256: await hashFile(sbom),
        jvmCoverageLimit: 'JVM package identification and matches are reported separately; this does not certify exhaustive JVM advisory coverage.' };
      if (runtime === 'ubi10') await writeFile(resolve(dir, 'ubi-runtime-packages.tsv'), await readFile(resolve(input, 'ubi-runtime-packages.tsv')));
      if (!['passed', 'success'].includes(runtimeStatus)) row.errors.push('Runtime verification did not pass');
      if (java.emSignECCG3Present || java.aaaCertificateServicesPresent) row.errors.push('A previously distrusted incident root remains trusted');
      rows.push(row);
      await writeFile(resolve(dir, 'summary.json'), JSON.stringify(row, null, 2) + '\n');
    } catch (error) {
      rows.push({ runtime, profile, status: 'failed', errors: [error.message] });
      await writeFile(resolve(dir, 'failure.json'), JSON.stringify({ error: error.message }) + '\n');
    }
  }
  const databases = rows.filter(r => r.database).map(r => JSON.stringify([r.database.built, r.database.schemaVersion, r.database.from]));
  const issues = [];
  if (databases.length !== 4 || new Set([...databases, ...control.map(c => JSON.stringify([c.database.built, c.database.schemaVersion, c.database.from]))]).size !== 1 ||
      await hashFile(databaseFile) !== databaseSha256) issues.push('Database identity differs or an image scan is missing');
  for (const profile of ['core', 'aws']) {
    const candidates = rows.filter(r => r.profile === profile);
    if (candidates.some(r => !r.applicationPackages) || JSON.stringify(candidates[0].applicationPackages) !== JSON.stringify(candidates[1].applicationPackages)) issues.push('Application Java inputs differ for ' + profile);
  }
  const result = { schemaVersion: 1, branch: process.env.GITHUB_HEAD_REF || process.env.GITHUB_REF_NAME,
    sourceCommit: artifactSource, reportCodeCommit: process.env.GITHUB_SHA, headCommit: process.env.SCAN_HEAD_SHA,
    artifactSourceRun: Number(process.env.ARTIFACT_SOURCE_RUN || process.env.GITHUB_RUN_ID),
    runId: Number(process.env.GITHUB_RUN_ID), runUrl: 'https://github.com/rambow-cloud/keycloak/actions/runs/' + process.env.GITHUB_RUN_ID,
    createdAt: new Date().toISOString(), tools: lock, database: { ...databaseStatus, sha256: databaseSha256 }, control, issues, rows };
  await writeFile(resolve(output, 'comparison.json'), JSON.stringify(result, null, 2) + '\n');
  await writeFile(resolve(output, 'README.md'), render(rows));
  if (issues.length || rows.some(r => r.status !== 'complete' || r.errors.length || r.blocking)) throw Error('Comparison reported coverage, runtime, trust or vulnerability gate failures; inspect preserved evidence.');
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  try { await main(); } catch (error) {
    await mkdir(output, { recursive: true });
    await writeFile(resolve(output, 'fatal.json'), JSON.stringify({ error: error.message }, null, 2) + '\n');
    throw error;
  }
}
