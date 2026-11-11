const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { createHash } = require('node:crypto');
const { join } = require('node:path');
const currentRecord = JSON.parse(readFileSync(join(__dirname, '../releases/records/v26.8.2-r2.json'), 'utf8'));
const digest = character => 'sha256:' + character.repeat(64);
const checksum = bytes => createHash('sha256').update(bytes).digest('hex');
const ref = version => 'ghcr.io/rambow-cloud/java:' + version + '@' + digest('f');
const prefix = 'https://github.com/rambow-cloud/amazon-linux-distroless/releases/tag/';

test('runtime discovery orders stable revisions numerically and keeps the reviewed Java family', async () => {
  const { chooseRuntimeRelease } = await import('../scripts/lib/rambow-runtime.mjs');
  const current = currentRecord.plan.imageLock.runtime;
  const releases = ['java25-25.0.5-r1', 'java21-21.0.99-r99', 'java25-25.1.0-r1', 'java25-25.0.5-r9', 'java25-25.0.5-r10']
    .map(tag_name => ({ tag_name }));
  releases.push({ tag_name: 'java25-25.0.6-r1', prerelease: true }, { tag_name: 'java25-25.0.7-r1', draft: true });
  assert.equal(chooseRuntimeRelease(current, releases).tag_name, 'java25-25.0.5-r10');
  assert.equal(chooseRuntimeRelease(ref('25.0.5-r10'), releases), null);
  assert.equal(chooseRuntimeRelease(current, [{ tag_name: 'java25-25.0.6-r1' }]).tag_name, 'java25-25.0.6-r1');
});

function importFixture() {
  const release = { id: 1, tag_name: 'java25-25.0.5-r3', html_url: prefix + 'java25-25.0.5-r3' };
  const preview = { id: 2, tag_name: 'java25-' + 'a'.repeat(12) + '-run123', prerelease: true };
  preview.html_url = prefix + preview.tag_name;
  const stable = { schemaVersion: 1, runtime: 'java25', version: '25.0.5', revision: 3, sourceCommit: 'a'.repeat(40),
    reference: 'ghcr.io/rambow-cloud/amazon-linux-distroless/java25@' + digest('b'),
    previewRelease: preview.html_url, releaseUrl: release.html_url, leaves: {}, scanHashes: {} };
  const assets = {};
  const index = { schemaVersion: 2, manifests: [] };
  for (const [architecture, character] of [['amd64', 'c'], ['arm64', 'd']]) {
    const child = digest(character);
    stable.leaves[architecture] = child;
    index.manifests.push({ digest: child, platform: { os: 'linux', architecture } });
    const sbom = JSON.parse(readFileSync(join(__dirname, '../dependencies/runtime/c5ab8cec00b8a1d999e5663b26a5f11646183a1b99ea82676f1fed4a02eee51f/' + architecture + '-sbom.cdx.json'), 'utf8'));
    sbom.metadata.component.properties.find(p => p.name === 'aquasecurity:trivy:ImageID').value = digest('e');
    assets['2/' + architecture + '-sbom.cdx.json'] = Buffer.from(JSON.stringify(sbom));
    const scan = { Metadata: { OS: { Family: 'amazon', Name: '2023' }, ImageID: digest('e') },
      Results: [{ Packages: sbom.components.filter(c => c.purl).map(c => ({ Identifier: { PURL: c.purl } })) }] };
    const bytes = Buffer.from(JSON.stringify(scan));
    assets['1/scan-' + architecture + '.json'] = bytes;
    stable.scanHashes['scan-' + architecture + '.json'] = 'sha256:' + checksum(bytes);
  }
  const config = architecture => ({ os: 'linux', architecture, rootfs: { diff_ids: [digest('1')] },
    config: { User: '65532:65532', Labels: { 'org.opencontainers.image.revision': stable.sourceCommit } } });
  const github = { rest: { repos: {
    listReleases: 'releases', listReleaseAssets: 'assets',
    getReleaseByTag: async () => ({ data: preview }),
    getReleaseAsset: async ({ asset_id }) => ({ data: asset_id === 'stable' ? Buffer.from(JSON.stringify(stable)) : assets[asset_id] }),
  } }, paginate: async (method, args) => method === 'releases' ? [release] :
    [{ name: 'stable.json', id: 'stable', size: 1000 }, ...Object.keys(assets).filter(key => key.startsWith(args.release_id + '/'))
      .map(key => ({ name: key.split('/')[1], id: key, size: assets[key].length }))] };
  const readObject = async (reference, _fetcher, kind) => {
    if (!reference.includes('@')) return { reference: currentRecord.plan.imageLock.runtime };
    const sha = reference.split('@')[1];
    if (kind === 'blobs') {
      const architecture = readObject.lastArchitecture;
      return { digest: sha, value: config(architecture) };
    }
    if (sha === digest('b')) return { digest: sha, value: index };
    readObject.lastArchitecture = sha === digest('c') ? 'amd64' : 'arm64';
    return { digest: sha, value: { config: { digest: digest('e') } } };
  };
  return { github, current: currentRecord.plan.imageLock.runtime, readObject, assets, stable, index, release };
}

test('runtime candidate imports both original SBOMs with exact index, config and scan identities', async () => {
  const { discoverRambowRuntime } = await import('../scripts/lib/rambow-runtime.mjs');
  const f = importFixture();
  const result = await discoverRambowRuntime(f);
  assert.equal(result.runtime, 'ghcr.io/rambow-cloud/java:25.0.5-r3@' + digest('b'));
  assert.equal(Object.keys(result.files).length, 3);
  const metadata = JSON.parse(result.files['dependencies/runtime/' + 'b'.repeat(64) + '/base.json']);
  assert.equal(metadata.architectures.arm64.config, digest('e'));
  assert.equal(metadata.architectures.amd64.manifest, digest('c'));
  assert.equal(metadata.architectures.amd64.sbomSha256, checksum(f.assets['2/amd64-sbom.cdx.json']));
  for (const mutate of [
    fixture => { fixture.index.manifests.pop(); },
    fixture => { fixture.stable.leaves.arm64 = digest('9'); },
    fixture => { fixture.assets['2/arm64-sbom.cdx.json'] = Buffer.from('{}'); },
    fixture => { fixture.stable.scanHashes['scan-amd64.json'] = digest('0'); },
    fixture => { fixture.stable.previewRelease = 'https://evil.example/release'; },
    fixture => { fixture.readObject = async () => ({ reference: 'moved' }); },
  ]) {
    const invalid = importFixture();
    mutate(invalid);
    await assert.rejects(discoverRambowRuntime(invalid));
  }
});

test('same-family revision automation permits forward updates and rejects immutable-tag drift', async () => {
  const { sameRuntimeFamily } = await import('../scripts/lib/runtime-family.mjs');
  const { autoMergeEligible } = await import('../scripts/lib/upstream.mjs');
  const { runtimeIntent, validateRequest } = await import('../scripts/lib/runtime-update.mjs');
  const current = currentRecord.plan.imageLock;
  const next = { ...current, runtime: ref('25.0.5-r3') };
  assert.ok(sameRuntimeFamily(current.runtime, next.runtime));
  assert.ok(autoMergeEligible(current, next, []));
  assert.equal(autoMergeEligible(current, next, ['launcher changed']), false);
  assert.equal(sameRuntimeFamily(next.runtime, current.runtime), false);
  assert.equal(sameRuntimeFamily(current.runtime, current.runtime.split('@')[0] + '@' + digest('0')), false);
  assert.equal(sameRuntimeFamily(current.runtime, ref('25.1.0-r1')), false);
  const intent = runtimeIntent([currentRecord], next);
  assert.equal(validateRequest({ schemaVersion: 1, ...intent, issue: 146, fragment: 'changes/146-distroless.json' }).to, next.runtime);
});

test('supported OS fixes are selected independently while Java CVEs remain tracked', async () => {
  const { supportedRemediationIntent } = await import('../scripts/lib/cve-monitor.mjs');
  const current = currentRecord.plan.imageLock;
  const intent = { affected: [{ profile: 'core', cves: ['CVE-2026-86805', 'CVE-2026-119210'], targets: [] }] };
  const result = { target: { profile: 'core' }, cveClasses: { 'CVE-2026-86805': ['os-pkgs'], 'CVE-2026-119210': ['lang-pkgs'] } };
  const selected = supportedRemediationIntent(intent, [result], [{ profile: 'core', lock: current }], { ...current, runtime: ref('25.0.5-r3') });
  assert.deepEqual(selected.affected[0].cves, ['CVE-2026-86805']);
  assert.deepEqual(intent.affected[0].cves, ['CVE-2026-86805', 'CVE-2026-119210']);
  result.cveClasses['CVE-2026-86805'].push('lang-pkgs');
  assert.equal(supportedRemediationIntent(intent, [result], [{ profile: 'core', lock: current }], { ...current, runtime: ref('25.0.5-r3') }).affected.length, 0);
});

test('AL2023 paired reports use their distinct runtime inventories after compaction', async () => {
  const { compactReport, compareReports, aggregatePairs, runtimeIntent, validateRequest } = await import('../scripts/lib/runtime-update.mjs');
  const policy = JSON.parse(readFileSync(join(__dirname, '../config/trivy.json'), 'utf8'));
  const context = { monitorCommit: 'a'.repeat(40), runId: 12, runAttempt: 1 };
  const next = { ...currentRecord.plan.imageLock, runtime: ref('25.0.5-r3') };
  const request = validateRequest({ schemaVersion: 1, ...runtimeIntent([currentRecord], next), issue: 146, fragment: 'changes/146-distroless.json' });
  const report = (runtime, architecture, vulnerable) => ({
    SchemaVersion: 2, ArtifactType: 'container_image', Metadata: { OS: { Family: 'amazon', Name: '2023' },
      ImageID: digest('a'), ImageConfig: { os: 'linux', architecture, rootfs: { diff_ids: [digest('1')] } } },
    RuntimeSbom: { reference: runtime, architecture, sha256: '1'.repeat(64) },
    Results: [{ Class: 'os-pkgs', Type: 'amazon', Target: 'AL2023', Packages: [{ Name: 'glibc', Version: '2.34',
      Identifier: { PURL: 'pkg:rpm/amazon/glibc@2.34' } }],
      Vulnerabilities: vulnerable ? [{ VulnerabilityID: 'CVE-2026-86805', PkgName: 'glibc', InstalledVersion: 'old', FixedVersion: 'new', Severity: 'HIGH' }] : [] },
    { Class: 'lang-pkgs', Type: 'jar', Target: 'Java', Packages: [{ Name: 'org.keycloak:keycloak-core', Version: '26.8.2' }] }],
  });
  const pairs = request.baselines.map(target => ({
    schemaVersion: 1, requestId: request.id, ...context, sourceCommit: context.monitorCommit, profile: target.profile,
    architecture: target.architecture, target, candidateDigest: digest('b'), candidateConfig: digest('a'), baselineConfig: digest('a'),
    scannerVersion: policy.version, scannerSha256: target.architecture === 'amd64' ? policy.linuxAmd64Sha256 : policy.linuxArm64Sha256,
    database: { vulnerability: '1'.repeat(64), java: '2'.repeat(64) }, databaseAfter: { vulnerability: '1'.repeat(64), java: '2'.repeat(64) },
    before: compactReport(report(request.from[target.profile], target.architecture, true)),
    after: compactReport(report(request.to, target.architecture, false)),
  }));
  const images = aggregatePairs(request, pairs, context, policy);
  assert.ok(images.every(image => image.resolved.includes('CVE-2026-86805')));
  assert.equal(pairs[0].after.Results[0].Packages[0].Identifier.PURL, 'pkg:rpm/amazon/glibc@2.34');
  assert.deepEqual(compareReports(pairs[0].before, pairs[0].after, pairs[0].target, context, policy, request.to).resolved, ['CVE-2026-86805']);
  pairs[0].after.RuntimeSbom.reference = request.from.core;
  assert.throws(() => aggregatePairs(request, pairs, context, policy), /coverage/);
});
