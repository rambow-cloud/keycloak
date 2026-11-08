import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { appendFile, copyFile, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { readRuntimeSbom } from '../scripts/lib/runtime-sbom.mjs';
import { downloadScannerArchive } from '../scripts/lib/trivy.mjs';
import { nativeArchitecture } from '../scripts/lib/platforms.mjs';

const architecture = process.env.PROBE_ARCH;
assert.equal(nativeArchitecture(), architecture);
assert.equal(process.platform, 'linux');
const output = resolve('.cache/al2023-sbom-comparison');
const work = await mkdtemp(join(tmpdir(), 'al2023-sbom-'));
await mkdir(output, { recursive: true });
const readJson = async path => JSON.parse(await readFile(path, 'utf8'));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const imageLock = await readJson('images.lock.json');
const policy = await readJson('config/trivy.json');
const inventory = await readRuntimeSbom(imageLock.runtime, architecture);
const originalPath = join(output, 'original.cdx.json');
const controlPath = join(output, 'glibc-control.cdx.json');
await copyFile(inventory.path, originalPath);
assert.equal(sha256(await readFile(originalPath)), inventory.base.sbomSha256);

const original = await readJson(originalPath);
const os = original.components.find(component => component.type === 'operating-system');
const glibc = structuredClone(original.components.find(component => component.name === 'glibc'));
const vulnerableVersion = '2.34-52.amzn2023.0.3';
glibc.purl = glibc.purl.replace('@' + glibc.version + '?', '@' + vulnerableVersion + '?');
glibc.version = vulnerableVersion;
glibc['bom-ref'] = glibc.purl;
glibc.properties = glibc.properties.filter(property => property.name.startsWith('aquasecurity:trivy:'));
glibc.properties.find(property => property.name === 'aquasecurity:trivy:SrcRelease').value = '52.amzn2023.0.3';
const control = {
  bomFormat: original.bomFormat, specVersion: original.specVersion, version: 1,
  metadata: { component: { type: 'container', name: 'Synthetic ALAS glibc control', 'bom-ref': 'control' } },
  components: [os, glibc],
  dependencies: [{ ref: 'control', dependsOn: [os['bom-ref']] }, { ref: os['bom-ref'], dependsOn: [glibc.purl] }],
};
await writeFile(controlPath, JSON.stringify(control, null, 2) + '\n');

const grypeVersion = '0.121.2';
const grypeName = `grype_${grypeVersion}_linux_${architecture}.tar.gz`;
const grypeUrl = `https://github.com/anchore/grype/releases/download/v${grypeVersion}/${grypeName}`;
const [trivyArchive, response] = await Promise.all([
  downloadScannerArchive(policy, architecture), fetch(grypeUrl, { signal: AbortSignal.timeout(120000) }),
]);
assert.ok(response.ok, 'Grype archive download failed with HTTP ' + response.status);
const grypeArchive = Buffer.from(await response.arrayBuffer());
assert.equal(sha256(grypeArchive), process.env.GRYPE_SHA256);

function run(executable, args, env = process.env) {
  const result = spawnSync(executable, args, { env, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, timeout: 480000 });
  if (result.error) throw result.error;
  return result;
}

for (const [name, bytes] of [['trivy', trivyArchive], ['grype', grypeArchive]]) {
  const archive = join(work, name + '.tar.gz');
  await writeFile(archive, bytes);
  const extract = run('tar', ['-xzf', archive, '-C', work, '--no-same-owner', name]);
  assert.equal(extract.status, 0, extract.stderr);
  const version = run(join(work, name), ['version']);
  assert.equal(version.status, 0, version.stderr);
  await writeFile(join(output, name + '-version.txt'), version.stdout);
}

const trivyCache = join(work, 'trivy-cache');
const grypeEnv = { ...process.env, GRYPE_DB_CACHE_DIR: join(work, 'grype-cache') };
for (const [kind, path] of [['original', originalPath], ['control', controlPath]]) {
  const grype = run(join(work, 'grype'), [`sbom:${path}`, '--distro', 'amzn:2023', '-vv', '-o', 'json'],
    { ...grypeEnv, GRYPE_DB_AUTO_UPDATE: String(kind === 'original') });
  await writeFile(join(output, `grype-${kind}.log`), grype.stderr);
  await writeFile(join(output, `grype-${kind}.json`), grype.stdout);
  assert.equal(grype.status, 0, grype.stderr.slice(-4000));

  const trivy = run(join(work, 'trivy'), ['sbom', '--config', '', '--ignorefile', '', '--scanners', 'vuln',
    '--pkg-types', 'os', '--list-all-pkgs', '--ignore-unfixed=false', '--format', 'json', '--cache-dir', trivyCache,
    '--no-progress', '--skip-version-check', '--skip-java-db-update', ...(kind === 'control' ? ['--skip-db-update'] : []), path]);
  await writeFile(join(output, `trivy-${kind}.log`), trivy.stderr);
  await writeFile(join(output, `trivy-${kind}.json`), trivy.stdout);
  assert.equal(trivy.status, 0, trivy.stderr.slice(-4000));
}
await copyFile(join(trivyCache, 'db', 'metadata.json'), join(output, 'trivy-db-metadata.json'));

function grypeRows(report) {
  return report.matches.flatMap(match => {
    const ids = [match.vulnerability.id, ...(match.relatedVulnerabilities ?? []).map(v => v.id)];
    const cves = [...new Set(ids.filter(id => /^CVE-/.test(id)))];
    return (cves.length ? cves : [ids[0]]).map(id => ({ id, package: match.artifact.name,
      version: match.artifact.version, advisory: match.vulnerability.id, severity: match.vulnerability.severity,
      fixed: match.vulnerability.fix?.versions ?? [], namespace: match.vulnerability.namespace,
      source: match.vulnerability.dataSource }));
  });
}

function trivyRows(report) {
  return report.Results.flatMap(result => (result.Vulnerabilities ?? []).map(v => ({
    id: v.VulnerabilityID, package: v.PkgName, version: v.InstalledVersion, severity: v.Severity,
    fixed: v.FixedVersion, source: v.DataSource?.URL, sourceId: v.DataSource?.ID,
  })));
}

const results = {};
for (const kind of ['original', 'control']) {
  const grype = await readJson(join(output, `grype-${kind}.json`));
  const log = await readFile(join(output, `grype-${kind}.log`), 'utf8');
  const trivy = await readJson(join(output, `trivy-${kind}.json`));
  const expected = kind === 'original' ? inventory.purls : [glibc.purl];
  const grypePurls = [...new Set([...log.matchAll(/id="(pkg:rpm\/[^"\s]+)"/g)].map(match => match[1]))];
  const trivyPurls = trivy.Results.filter(result => result.Type === 'amazon' && result.Class === 'os-pkgs')
    .flatMap(result => result.Packages.map(pkg => pkg.Identifier.PURL));
  assert.deepEqual(grypePurls.sort(), [...expected].sort(), 'Grype did not enumerate the exact RPM identities');
  assert.deepEqual(trivyPurls.sort(), [...expected].sort(), 'Trivy did not enumerate the exact RPM identities');
  assert.match(log, /using distro: amzn 2023/);
  assert.equal(trivy.Metadata.OS.Family, 'amazon');
  assert.equal(trivy.Metadata.OS.Name, '2023');

  const g = grypeRows(grype);
  const t = trivyRows(trivy);
  const keys = rows => [...new Set(rows.map(row => `${row.package}/${row.id}`))].sort();
  const gKeys = keys(g);
  const tKeys = keys(t);
  results[kind] = { rpmCount: expected.length, grypeDistribution: grype.distro, trivyDistribution: trivy.Metadata.OS,
    grypeDatabase: grype.descriptor?.db, grypeIgnored: grype.ignoredMatches?.length ?? 0,
    grype: g, trivy: t, shared: gKeys.filter(key => tKeys.includes(key)),
    grypeOnly: gKeys.filter(key => !tKeys.includes(key)), trivyOnly: tKeys.filter(key => !gKeys.includes(key)) };
}

const advisory = 'ALAS2023-2023-359';
const controlCves = ['CVE-2023-4527', 'CVE-2023-4806', 'CVE-2023-4813', 'CVE-2023-4911'];
const isAmazon = row => /amazon|alas/i.test([row.namespace, row.source, row.sourceId, row.advisory].join(' '));
const controlCoverage = Object.fromEntries(['grype', 'trivy'].map(tool => [tool, controlCves.map(id => ({
  id, matched: results.control[tool].some(row => row.id === id && row.package === 'glibc' && isAmazon(row)),
}))]));
const report = { architecture, runtime: inventory.reference, sbomSha256: inventory.base.sbomSha256,
  baseManifest: inventory.base.manifest, sourceCommit: process.env.GITHUB_SHA, runId: process.env.GITHUB_RUN_ID,
  controlAdvisory: advisory, vulnerableVersion, expectedFixedVersion: '2.34-52.amzn2023.0.6', controlCoverage, results };
await writeFile(join(output, 'comparison.json'), JSON.stringify(report, null, 2) + '\n');
await appendFile(process.env.GITHUB_STEP_SUMMARY, `## AL2023 CycloneDX comparison (${architecture})\n\n` +
  `Original RPMs: ${results.original.rpmCount}. Grype-only pairs: ${results.original.grypeOnly.length}. ` +
  `Trivy-only pairs: ${results.original.trivyOnly.length}. Shared pairs: ${results.original.shared.length}.\n\n` +
  `Control: [${advisory}](https://alas.aws.amazon.com/AL2023/${advisory}.html) with glibc ${vulnerableVersion}.\n\n` +
  '| Scanner | Known advisory CVEs matched |\n| --- | --- |\n' +
  Object.entries(controlCoverage).map(([tool, rows]) => `| ${tool} | ${rows.filter(row => row.matched).length}/${rows.length} |`).join('\n') + '\n');
console.log(JSON.stringify({ architecture, original: results.original, controlCoverage }, null, 2));
assert.ok(Object.values(controlCoverage).every(rows => rows.every(row => row.matched)), 'Known ALAS CVE control did not match in both scanners');
