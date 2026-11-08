'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');

test('AL2023 scans require the exact architecture inventory and inherited base layers', async () => {
  const { readRuntimeSbom, combineRuntimeScans } = await import('../scripts/lib/runtime-sbom.mjs');
  const { hasScanCoverage } = await import('../scripts/lib/trivy.mjs');
  const runtime = 'ghcr.io/rambow-cloud/java:25.0.5-r2@sha256:c5ab8cec00b8a1d999e5663b26a5f11646183a1b99ea82676f1fed4a02eee51f';
  for (const architecture of ['amd64', 'arm64']) {
    const inventory = await readRuntimeSbom(runtime, architecture);
    const image = {
      SchemaVersion: 2, ArtifactType: 'container_image',
      Metadata: { ImageID: 'sha256:' + 'f'.repeat(64), ImageConfig: { os: 'linux', architecture, rootfs: { diff_ids: inventory.base.diffIds } } },
      Results: [{ Class: 'lang-pkgs', Type: 'jar', Packages: [{ Name: 'org.keycloak:keycloak-core' }] }],
    };
    const os = {
      SchemaVersion: 2, ArtifactType: 'cyclonedx',
      Metadata: { OS: { Family: 'amazon', Name: '2023' }, ImageID: inventory.base.config },
      Results: [{ Class: 'os-pkgs', Type: 'amazon', Packages: inventory.purls.map(PURL => ({ Identifier: { PURL } })) }],
    };
    assert.equal(hasScanCoverage(image, runtime, true), false);
    assert.equal(hasScanCoverage(combineRuntimeScans(image, os, inventory), runtime, true), true);
    const partial = structuredClone(os);
    partial.Results[0].Packages.pop();
    assert.throws(() => combineRuntimeScans(image, partial, inventory), /complete pinned AL2023/);
    const differentImage = structuredClone(image);
    differentImage.Metadata.ImageConfig.rootfs.diff_ids[0] = 'sha256:' + '0'.repeat(64);
    assert.throws(() => combineRuntimeScans(differentImage, os, inventory), /inherit/);
  }
});
