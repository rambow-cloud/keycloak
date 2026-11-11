import { createHash } from 'node:crypto';
import { validateSbom } from './sbom.mjs';

export const signingIssuer = 'https://token.actions.githubusercontent.com';
const workflow = 'https://github.com/rambow-cloud/keycloak/.github/workflows/release.yml';
const digestPattern = /^sha256:[a-f0-9]{64}$/;
const checksumPattern = /^[a-f0-9]{64}$/;
const canonical = value => JSON.stringify(value, (_key, item) => item && typeof item === 'object' && !Array.isArray(item)
  ? Object.fromEntries(Object.entries(item).sort(([a], [b]) => a.localeCompare(b))) : item);
export const canonicalHash = value => createHash('sha256').update(canonical(value)).digest('hex');

export function signingIdentities(plan) {
  if (!/^v\d+\.\d+\.\d+-r[1-9]\d*$/.test(plan.tag)) throw Error('Signing requires a formal release');
  return [workflow + '@refs/heads/main', workflow + '@refs/tags/' + plan.tag];
}

export function signingIdentityPattern(plan) {
  return '^(' + signingIdentities(plan).map(value => value.replace(/[.*+?^$()|[\]{}\\]/g, '\\$&')).join('|') + ')$';
}

export function signatureTargets(plan) {
  return plan.images.flatMap(image => [
    { profile: image.profile, digest: image.digest },
    ...(image.children ?? []).map(child => ({ profile: image.profile, ...child })),
  ]);
}

export function validateSupplyChain(plan) {
  const contract = plan.supplyChain;
  if (!contract) return;
  const expected = signatureTargets(plan).filter(target => target.architecture);
  if (contract.schemaVersion !== 1 || !/^\d+\.\d+\.\d+$/.test(contract.cosign?.version ?? '') ||
      !checksumPattern.test(contract.cosign?.linuxAmd64Sha256 ?? '') || !expected.length ||
      !Array.isArray(contract.sboms) || contract.sboms.length !== expected.length) {
    throw Error('Invalid frozen signing and SBOM contract');
  }
  for (const target of expected) {
    const matches = contract.sboms.filter(sbom => sbom.profile === target.profile && sbom.architecture === target.architecture);
    const sbom = matches[0];
    if (matches.length !== 1 || sbom.digest !== target.digest || !digestPattern.test(sbom.digest) ||
        sbom.asset !== 'sbom-' + target.profile + '-' + target.architecture + '.cdx.json' || !checksumPattern.test(sbom.sha256 ?? '')) {
      throw Error('Frozen SBOM does not match its published child');
    }
  }
}

export function verifyAttestationPayload(output, expectedSbom, target) {
  let envelopes;
  try { envelopes = JSON.parse(output); }
  catch { envelopes = output.trim().split(/\r?\n/).map(line => JSON.parse(line)); }
  if (!Array.isArray(envelopes)) envelopes = [envelopes];
  const statements = envelopes.map(envelope => JSON.parse(Buffer.from(envelope.payload, 'base64').toString('utf8')));
  const found = statements.some(statement => statement.predicateType === 'https://cyclonedx.org/bom' &&
    statement.subject?.some(subject => subject.digest?.sha256 === target.digest.slice(7)) &&
    canonicalHash(statement.predicate) === canonicalHash(expectedSbom));
  if (!found) throw Error('Verified attestation differs from the frozen SBOM or image subject');
  validateSbom(expectedSbom, target);
}

export function validateSupplyChainRecord(record) {
  validateSupplyChain(record.plan);
  if (!record.plan.supplyChain) {
    if (record.supplyChain !== undefined) throw Error('Signing evidence has no frozen contract');
    return;
  }
  const evidence = record.supplyChain;
  const targets = signatureTargets(record.plan);
  if (evidence?.schemaVersion !== 1 || evidence.status !== 'verified' || evidence.issuer !== signingIssuer ||
      canonicalHash(evidence.identities) !== canonicalHash(signingIdentities(record.plan)) ||
      evidence.contractSha256 !== canonicalHash(record.plan.supplyChain) ||
      !Array.isArray(evidence.targets) || evidence.targets.length !== targets.length) throw Error('Verified signing evidence is required');
  for (const target of targets) {
    const matches = evidence.targets.filter(item => item.profile === target.profile && item.digest === target.digest &&
      item.architecture === target.architecture);
    if (matches.length !== 1 || matches[0].signatureVerified !== true) throw Error('Missing exact-digest signature verification');
    if (target.architecture) {
      const sbom = record.plan.supplyChain.sboms.find(item => item.profile === target.profile && item.architecture === target.architecture);
      if (matches[0].sbomSha256 !== sbom.sha256 || matches[0].attestationVerified !== true) throw Error('Missing frozen SBOM attestation verification');
    }
  }
}
