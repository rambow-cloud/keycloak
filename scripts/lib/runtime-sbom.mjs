import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

const digestPattern = /^sha256:[a-f0-9]{64}$/;
const referencePattern = /^ghcr\.io\/rambow-cloud\/java:25\.\d+\.\d+-r[1-9]\d*@sha256:([a-f0-9]{64})$/;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const isRambowRuntime = reference => referencePattern.test(reference ?? '');

export function validateRuntimeInventory(reference, architecture, metadata, bytes) {
  const match = referencePattern.exec(reference);
  if (!match || !['amd64', 'arm64'].includes(architecture)) throw Error('Expected a reviewed Rambow Java 25 runtime and architecture');
  const base = metadata.architectures?.[architecture];
  if (metadata.schemaVersion !== 1 || metadata.reference !== reference || !digestPattern.test(base?.manifest) ||
      !digestPattern.test(base.config) || !Array.isArray(base.diffIds) || !base.diffIds.length ||
      !base.diffIds.every(value => digestPattern.test(value)) || hash(bytes) !== base.sbomSha256) {
    throw Error('Runtime SBOM checksum or base identity mismatch');
  }
  const sbom = JSON.parse(bytes);
  const purls = sbom.components?.filter(component => component.purl?.startsWith('pkg:rpm/amazon/')).map(component => component.purl);
  const imageId = sbom.metadata?.component?.properties?.find(property => property.name === 'aquasecurity:trivy:ImageID')?.value;
  if (sbom.bomFormat !== 'CycloneDX' || imageId !== base.config || !purls?.length || new Set(purls).size !== purls.length ||
      !sbom.components.some(component => component.type === 'operating-system' && component.name === 'amazon' && component.version === '2023')) {
    throw Error('Invalid AL2023 base SBOM inventory');
  }
  return { reference, architecture, base, purls };
}

export async function readRuntimeSbom(reference, architecture) {
  const match = referencePattern.exec(reference);
  if (!match || !['amd64', 'arm64'].includes(architecture)) throw Error('Expected a reviewed Rambow Java 25 runtime and architecture');
  const directory = new URL('../../dependencies/runtime/' + match[1] + '/', import.meta.url);
  const metadata = JSON.parse(await readFile(new URL('base.json', directory), 'utf8'));
  const path = new URL(architecture + '-sbom.cdx.json', directory);
  return { ...validateRuntimeInventory(reference, architecture, metadata, await readFile(path)), path };
}

export function combineRuntimeScans(imageReport, runtimeReport, inventory) {
  const { reference, architecture, base, purls } = inventory;
  const config = imageReport.Metadata?.ImageConfig;
  if (imageReport.SchemaVersion !== 2 || imageReport.ArtifactType !== 'container_image' ||
      config?.architecture !== architecture || config.os !== 'linux' || !digestPattern.test(imageReport.Metadata?.ImageID) ||
      !Array.isArray(config.rootfs?.diff_ids) || !base.diffIds.every((id, index) => config.rootfs.diff_ids[index] === id)) {
    throw Error('Final image does not inherit the reviewed runtime layers for this architecture');
  }
  if (!Array.isArray(imageReport.Results) || imageReport.Results.some(result => result.Class === 'os-pkgs' &&
      (result.Packages?.length || result.Vulnerabilities?.length))) {
    throw Error('Unexpected native OS inventory alongside the reviewed runtime SBOM');
  }
  const os = runtimeReport.Metadata?.OS;
  const result = runtimeReport.Results?.[0];
  if (runtimeReport.SchemaVersion !== 2 || runtimeReport.ArtifactType !== 'cyclonedx' ||
      runtimeReport.Metadata.ImageID !== base.config || os?.Family !== 'amazon' || os.Name !== '2023' ||
      runtimeReport.Results.length !== 1 || result.Class !== 'os-pkgs' || result.Type !== 'amazon' ||
      !Array.isArray(result.Packages) || result.Packages.length !== purls.length ||
      new Set(result.Packages.map(pkg => pkg.Identifier?.PURL)).size !== purls.length ||
      !result.Packages.every(pkg => purls.includes(pkg.Identifier?.PURL))) {
    throw Error('Trivy did not scan the complete pinned AL2023 RPM inventory');
  }
  return {
    ...imageReport,
    Metadata: { ...imageReport.Metadata, OS: os },
    Results: [...imageReport.Results.filter(entry => entry.Class !== 'os-pkgs'), result],
    RuntimeSbom: { reference, architecture, baseManifest: base.manifest, baseConfig: base.config, sha256: base.sbomSha256 },
  };
}
