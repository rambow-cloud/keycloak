import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { sbomHash, validateSbom } from './lib/sbom.mjs';
import { signingIssuer, signingIdentities, signingIdentityPattern, signatureTargets, canonicalHash,
  verifyAttestationPayload, validateSupplyChainRecord } from './lib/supply-chain.mjs';
import { readAsset } from './quay-release.mjs';

export async function prepareSigning(plan, { github, context, work, output, getIDToken, mask, fetchImpl = fetch, runCosign = spawnSync }) {
  if (!plan.supplyChain) return undefined;
  if (!signingIdentities(plan).includes('https://github.com/' + process.env.GITHUB_WORKFLOW_REF)) {
    throw Error('Signing is restricted to the reviewed main/formal-release workflow');
  }
  const { data: release } = await github.rest.repos.getReleaseByTag({ ...context.repo, tag: plan.tag });
  if (release.id !== plan.releaseId || release.draft || release.prerelease) throw Error('Signing release identity changed');
  const sboms = new Map();
  for (const descriptor of plan.supplyChain.sboms) {
    const sbom = await readAsset(github, context.repo, release, descriptor.asset, 10000000);
    if (!sbom || sbomHash(sbom) !== descriptor.sha256) throw Error('Frozen SBOM asset is missing or changed');
    validateSbom(sbom, descriptor);
    const path = join(work, descriptor.asset);
    await writeFile(path, JSON.stringify(sbom, null, 2) + '\n');
    sboms.set(descriptor.profile + '/' + descriptor.architecture, { descriptor, sbom, path });
  }
  const policy = plan.supplyChain.cosign;
  const url = 'https://github.com/sigstore/cosign/releases/download/v' + policy.version + '/cosign-linux-amd64';
  const response = await fetchImpl(url, { signal: AbortSignal.timeout(120000) });
  if (!response.ok) throw Error('Cannot download pinned Cosign (HTTP ' + response.status + ')');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (createHash('sha256').update(bytes).digest('hex') !== policy.linuxAmd64Sha256) throw Error('Cosign checksum mismatch');
  const binary = join(work, 'cosign');
  await writeFile(binary, bytes, { mode: 0o755 });
  const anonymous = join(work, 'anonymous');
  await mkdir(anonymous);
  await writeFile(join(anonymous, 'config.json'), '{"auths":{}}\n');
  await writeFile(join(anonymous, 'auth.json'), '{"auths":{}}\n');
  const evidenceDirectory = join(output, 'signatures');
  await mkdir(evidenceDirectory, { recursive: true });
  const verificationFlags = ['--certificate-oidc-issuer', signingIssuer, '--certificate-identity-regexp', signingIdentityPattern(plan)];

  function command(args, configDirectory) {
    const result = runCosign(binary, args, { encoding: 'utf8', maxBuffer: 24000000, timeout: 240000,
      env: { ...process.env, DOCKER_CONFIG: configDirectory, REGISTRY_AUTH_FILE: join(configDirectory, 'auth.json') } });
    // Do not expose command arguments or signer output, which may include transient tokens.
    if (result.error) throw Error('Cosign execution failed');
    return result;
  }

  async function sign(args, authDirectory) {
    const token = await getIDToken('sigstore');
    mask(token);
    const result = command([...args, '--yes', '--identity-token', token], authDirectory);
    if (result.status !== 0) throw Error('Cosign signing failed; recover the frozen release after inspecting service availability');
  }

  return async authDirectory => {
    const evidence = { schemaVersion: 1, status: 'partial', issuer: signingIssuer, identities: signingIdentities(plan),
      contractSha256: canonicalHash(plan.supplyChain), targets: [] };
    const save = () => writeFile(join(output, 'supply-chain-verification.json'), JSON.stringify(evidence, null, 2) + '\n');
    await save();
    for (const target of signatureTargets(plan)) {
      const reference = plan.registry + '@' + target.digest;
      const prefix = join(evidenceDirectory, target.profile + '-' + (target.architecture ?? 'index'));
      const signatureArgs = ['verify', ...verificationFlags, reference];
      let signature = command(signatureArgs, anonymous);
      if (signature.status !== 0) {
        await sign(['sign', reference], authDirectory);
        signature = command(signatureArgs, anonymous);
      }
      if (signature.status !== 0) throw Error('Anonymous exact-identity signature verification failed for ' + target.profile);
      const claims = JSON.parse(signature.stdout);
      if (!Array.isArray(claims) || !claims.some(claim => claim.critical?.image?.['docker-manifest-digest'] === target.digest)) {
        throw Error('Verified signature has a different image digest');
      }
      await writeFile(prefix + '-signature.json', signature.stdout);
      const verified = { ...target, signatureVerified: true };
      if (target.architecture) {
        const { descriptor, sbom, path } = sboms.get(target.profile + '/' + target.architecture);
        const args = ['verify-attestation', '--type', 'cyclonedx', ...verificationFlags, reference];
        let attestation = command(args, anonymous);
        let matches = false;
        if (attestation.status === 0) {
          try { verifyAttestationPayload(attestation.stdout, sbom, target); matches = true; }
          catch { /* An older attestation may coexist with the reviewed frozen inventory. */ }
        }
        if (!matches) {
          await sign(['attest', '--type', 'cyclonedx', '--predicate', path, reference], authDirectory);
          attestation = command(args, anonymous);
          if (attestation.status !== 0) throw Error('Anonymous SBOM attestation verification failed');
          verifyAttestationPayload(attestation.stdout, sbom, target);
        }
        await writeFile(prefix + '-attestation.json', attestation.stdout);
        Object.assign(verified, { attestationVerified: true, sbomSha256: descriptor.sha256 });
      }
      evidence.targets.push(verified);
      await save();
    }
    evidence.status = 'verified';
    validateSupplyChainRecord({ plan, supplyChain: evidence });
    await save();
    return evidence;
  };
}
