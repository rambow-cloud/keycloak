import { createHash } from 'node:crypto';

const sha256 = value => createHash('sha256').update(value).digest('hex');
export const sbomBytes = value => JSON.stringify(value, null, 2) + '\n';
export const sbomHash = value => sha256(sbomBytes(value));
const digestPattern = /^sha256:[a-f0-9]{64}$/;

export function inventoryPurls(report) {
  const packages = report.Results?.flatMap(result => result.Packages ?? []);
  if (report.SchemaVersion !== 2 || !packages?.length ||
      packages.some(pkg => !/^pkg:[a-z0-9]+\/\S+$/.test(pkg.Identifier?.PURL ?? ''))) {
    throw Error('SBOM requires the complete identified package inventory');
  }
  return [...new Set(packages.map(pkg => pkg.Identifier.PURL))].sort();
}

export function validateSbom(sbom, { digest, profile, architecture, purls }) {
  const reference = 'quay.io/rambow-cloud/keycloak@' + digest;
  const properties = sbom.metadata?.component?.properties ?? [];
  const components = sbom.components;
  if (!digestPattern.test(digest) || !['core', 'aws'].includes(profile) ||
      !['amd64', 'arm64'].includes(architecture) || sbom.bomFormat !== 'CycloneDX' || sbom.specVersion !== '1.6' ||
      sbom.version !== 1 || sbom.metadata?.component?.name !== reference ||
      sbom.metadata.component['bom-ref'] !== reference ||
      !properties.some(p => p.name === 'rambow:profile' && p.value === profile) ||
      !properties.some(p => p.name === 'rambow:architecture' && p.value === architecture) ||
      !Array.isArray(components) || !components.length) throw Error('SBOM image identity mismatch');
  const identities = components.filter(component => component.purl).map(component => component.purl).sort();
  if (new Set(identities).size !== identities.length ||
      purls && JSON.stringify(identities) !== JSON.stringify([...purls].sort())) throw Error('SBOM package coverage mismatch');
  const refs = new Set([reference, ...components.map(component => component['bom-ref'])]);
  if (refs.has(undefined) || refs.size !== components.length + 1 ||
      !Array.isArray(sbom.dependencies) || sbom.dependencies.some(edge =>
        !refs.has(edge.ref) || !Array.isArray(edge.dependsOn) || edge.dependsOn.some(ref => !refs.has(ref)))) {
    throw Error('SBOM dependency references are invalid');
  }
  return sbom;
}

export function createSbom(report, { digest, profile, architecture, scannerVersion, runtimeSbom }) {
  const purls = inventoryPurls(report);
  if (report.Metadata?.ImageConfig?.architecture !== architecture) throw Error('SBOM architecture differs from the scan');
  const byPurl = new Map();
  for (const result of report.Results) for (const pkg of result.Packages ?? []) {
    const purl = pkg.Identifier.PURL;
    let component = byPurl.get(purl);
    if (!component) {
      const [group, name] = pkg.Name.includes(':') ? [pkg.Name.slice(0, pkg.Name.lastIndexOf(':')), pkg.Name.split(':').at(-1)] : [null, pkg.Name];
      component = { type: 'library', 'bom-ref': purl, ...(group ? { group } : {}), name, version: pkg.Version, purl, properties: [] };
      byPurl.set(purl, component);
    }
    if (pkg.FilePath && !component.properties.some(p => p.value === pkg.FilePath)) {
      component.properties.push({ name: 'rambow:location', value: pkg.FilePath });
    }
  }
  let operatingSystem;
  if (runtimeSbom) {
    const originals = runtimeSbom.components.filter(component => component.purl?.startsWith('pkg:rpm/amazon/'));
    const imported = [...byPurl.keys()].filter(purl => purl.startsWith('pkg:rpm/amazon/')).sort();
    if (JSON.stringify(imported) !== JSON.stringify(originals.map(component => component.purl).sort())) {
      throw Error('SBOM runtime RPM coverage differs from the reviewed inventory');
    }
    for (const component of originals) byPurl.set(component.purl, structuredClone(component));
    operatingSystem = runtimeSbom.components.find(component => component.type === 'operating-system');
    if (!operatingSystem) throw Error('Runtime SBOM operating system is missing');
  }
  const reference = 'quay.io/rambow-cloud/keycloak@' + digest;
  const components = [...byPurl.values()].sort((a, b) => a.purl.localeCompare(b.purl));
  const rpmRefs = components.filter(component => component.purl.startsWith('pkg:rpm/')).map(component => component['bom-ref']);
  const sbom = {
    bomFormat: 'CycloneDX', specVersion: '1.6', version: 1,
    metadata: {
      tools: { components: [{ type: 'application', name: 'Trivy', version: scannerVersion }] },
      component: { type: 'container', 'bom-ref': reference, name: reference, version: digest,
        properties: [{ name: 'rambow:profile', value: profile }, { name: 'rambow:architecture', value: architecture }] },
    },
    components: [...(operatingSystem ? [structuredClone(operatingSystem)] : []), ...components],
    dependencies: [
      { ref: reference, dependsOn: [
        ...(operatingSystem ? [operatingSystem['bom-ref']] : []),
        ...components.filter(component => !operatingSystem || !rpmRefs.includes(component['bom-ref'])).map(component => component['bom-ref']),
      ] },
      ...(operatingSystem ? [{ ref: operatingSystem['bom-ref'], dependsOn: rpmRefs }] : []),
    ],
  };
  return validateSbom(sbom, { digest, profile, architecture, purls });
}
