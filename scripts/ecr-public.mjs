import { mkdir, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { json, hash, equal, repository, parseRelease, validateRecord, destinationAction } from './lib/releases.mjs';
import { activeReleaseRecords } from './lib/release-events.mjs';
import { readCatalog, readAsset, putImmutableAsset, assertTagSource, completionAsset } from './quay-release.mjs';
import { signingIssuer, signingIdentityPattern, signingIdentities, signatureTargets, canonicalHash,
  verifyAttestationPayload, validateSupplyChainRecord } from './lib/supply-chain.mjs';
import { sbomHash, validateSbom } from './lib/sbom.mjs';

const asset = name => 'ecr-public-mirror-' + name + '.json';
const prefix = 'repo:rambow-cloud@333554680/keycloak@1433566126';
export function validateConfig(c) {
  if (c.schemaVersion !== 1 || typeof c.enabled !== 'boolean' || c.accountId !== '060065238923' ||
      c.region !== 'us-east-1' || c.repository !== 'public.ecr.aws/j2a6d6e3/keycloak' ||
      c.repositoryArn !== 'arn:aws:ecr-public::060065238923:repository/keycloak' ||
      c.roleArn !== 'arn:aws:iam::060065238923:role/RambowKeycloakPublicEcrPublisher' ||
      c.environment !== 'ecr-public-release' || c.audience !== 'sts.amazonaws.com' ||
      c.subject !== prefix + ':environment:ecr-public-release') throw Error('Unexpected Public ECR trust or destination configuration');
  return c;
}
export function assertContext(context, workflowRef = process.env.GITHUB_WORKFLOW_REF) {
  if (context.repo.owner + '/' + context.repo.repo !== repository) throw Error('Unexpected publishing repository');
  const manual = context.eventName === 'workflow_dispatch' && context.ref === 'refs/heads/main';
  const release = context.eventName === 'release' && /^refs\/tags\/v\d+\.\d+\.\d+-r[1-9]\d*$/.test(context.ref) &&
    !context.payload.release?.draft && !context.payload.release?.prerelease;
  const suffix = manual ? 'refs/heads/main' : context.ref;
  const workflows = ['release.yml', 'ecr-public.yml'].map(w => repository + '/.github/workflows/' + w + '@' + suffix);
  if ((!manual && !release) || !workflows.includes(workflowRef) || (release && !workflowRef.includes('/release.yml@'))) {
    throw Error('Public ECR publication requires the trusted main/manual or formal-release workflow');
  }
}
export function validateToken(token, config, context, now = Date.now()) {
  const parts = token.split('.');
  if (parts.length !== 3) throw Error('Invalid GitHub OIDC token');
  const c = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  if (c.iss !== signingIssuer || c.aud !== config.audience || c.sub !== config.subject ||
      c.repository_id !== '1433566126' || c.repository_owner_id !== '333554680' ||
      c.ref !== context.ref || c.event_name !== context.eventName || c.workflow_ref !== process.env.GITHUB_WORKFLOW_REF ||
      !Number.isFinite(c.exp) || c.exp * 1000 < now + 30000 || c.exp * 1000 > now + 600000) {
    throw Error('Unexpected GitHub OIDC claims');
  }
  // STS validates the JWT signature. This check constrains the requested identity before transmission.
  return c;
}
export function mirrorPlan(record, config) {
  validateRecord(record); validateConfig(config);
  if (!record.plan.supplyChain || record.plan.schemaVersion !== 3) throw Error('A signed native multi-architecture publication is required');
  return { schemaVersion: 1, tag: record.plan.tag, releaseId: record.plan.releaseId,
    sourceRecordSha256: hash(json(record)), sourceCommit: record.plan.sourceCommit,
    sourceRegistry: record.plan.registry, target: config,
    images: record.plan.images.map(({ profile, tag, digest, children, changes }) => ({ profile, tag, digest, children, changes })),
    supplyChainSha256: canonicalHash(record.plan.supplyChain) };
}
function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 240000, maxBuffer: 24000000, ...options });
  if (result.error || result.status !== 0) throw Error(command + ' failed (exit ' + result.status + ')');
  return result.stdout;
}
function identity(context, plan) {
  return { runId: context.runId, attempt: Number(process.env.GITHUB_RUN_ATTEMPT), headSha: context.sha, planSha256: hash(json(plan)) };
}
function completion(record) {
  return { schemaVersion: 1, tag: record.plan.tag, recordSha256: hash(json(record)) };
}
export function validateMirrorRecord(record, plan) {
  if (record?.schemaVersion !== 1 || record.status !== 'published' || !equal(record.plan, plan) ||
      !Number.isFinite(Date.parse(record.publishedAt)) || record.publication?.status !== 'published' ||
      record.publication.planSha256 !== hash(json(plan)) || record.publication.sourceVerification?.status !== 'verified' ||
      record.publication.sourceVerification.contractSha256 !== plan.supplyChainSha256 ||
      !equal(record.publication.images, plan.images) || !Array.isArray(record.nativePulls) || record.nativePulls.length !== 2 ||
      ['amd64','arm64'].some(a => record.nativePulls.filter(p => p.architecture === a).length !== 1)) throw Error('Invalid immutable Public ECR publication record');
  const verification = record.publication.sourceVerification;
  const expected = plan.images.flatMap(i => [{ profile: i.profile, digest: i.digest }, ...i.children.map(c => ({ profile: i.profile, ...c }))]);
  if (verification.issuer !== signingIssuer || !equal(verification.identities, [
    'https://github.com/' + repository + '/.github/workflows/release.yml@refs/heads/main',
    'https://github.com/' + repository + '/.github/workflows/release.yml@refs/tags/' + plan.tag ]) ||
      verification.targets?.length !== expected.length || expected.some(t => verification.targets.filter(v =>
        v.profile === t.profile && v.digest === t.digest && v.architecture === t.architecture && v.signatureVerified === true &&
        (!t.architecture || v.attestationVerified === true && /^[a-f0-9]{64}$/.test(v.sbomSha256))).length !== 1)) throw Error('Incomplete source signature/attestation verification');
  if (!Number.isSafeInteger(record.publication.runId) || record.publication.runId < 1 ||
      !Number.isSafeInteger(record.publication.attempt) || record.publication.attempt < 1 ||
      !/^[a-f0-9]{40}$/.test(record.publication.headSha)) throw Error('Invalid publication run identity');
  for (const p of record.nativePulls) {
    if (p.status !== 'verified' || p.planSha256 !== hash(json(plan)) || p.runId !== record.publication.runId ||
        p.attempt !== record.publication.attempt || p.headSha !== record.publication.headSha ||
        !Array.isArray(p.images) || p.images.length !== plan.images.length) throw Error('Native pull evidence association mismatch');
    for (const image of plan.images) {
      const selected = p.images.filter(i => i.profile === image.profile);
      if (selected.length !== 1 || selected[0].digest !== image.digest ||
          selected[0].childDigest !== image.children.find(c => c.architecture === p.architecture)?.digest ||
          !/^sha256:[a-f0-9]{64}$/.test(selected[0].configDigest)) throw Error('Native pull digest mismatch');
    }
  }
  return record;
}
export async function prepareMirror({ github, context, core, tag, config }) {
  assertContext(context); validateConfig(config); parseRelease(tag);
  if (!config.enabled) { core.info('Public ECR distribution is disabled; no credentials requested.'); return { active: false }; }
  if (context.eventName === 'release' && context.payload.release?.tag_name !== tag) throw Error('Release event/tag mismatch');
  const { data: release } = await github.rest.repos.getReleaseByTag({ ...context.repo, tag });
  if (release.draft || release.prerelease || (context.payload.release && context.payload.release.id !== release.id)) throw Error('A stable matching Release is required');
  const catalog = await readCatalog(github, context.repo, process.env.MIRROR_TOOLS_COMMIT);
  const source = activeReleaseRecords(catalog).find(r => r.plan.tag === tag);
  if (!source || source.plan.releaseId !== release.id) throw Error('Source publication is not active and recorded on main');
  await assertTagSource(github, context.repo, tag, source.plan.sourceCommit);
  const { data: comparison } = await github.rest.repos.compareCommits({ ...context.repo, base: source.plan.sourceCommit, head: 'main' });
  if (comparison.merge_base_commit.sha !== source.plan.sourceCommit) throw Error('Source release is outside main history');
  const [sourcePlan, sourceRecord, sourceComplete, verification] = await Promise.all([
    readAsset(github, context.repo, release, 'publication-plan.json'),
    readAsset(github, context.repo, release, 'publication-record.json'),
    readAsset(github, context.repo, release, 'publication-complete.json'),
    readAsset(github, context.repo, release, 'supply-chain-verification.json') ]);
  if (!equal(sourcePlan, source.plan) || !equal(sourceRecord, source) || !equal(sourceComplete, completionAsset(source)) ||
      !equal(verification, source.supplyChain)) throw Error('Source catalog and immutable Release facts disagree');
  const plan = mirrorPlan(source, config);
  await putImmutableAsset(github, context.repo, release, asset('plan'), plan);
  const existing = await readAsset(github, context.repo, release, asset('record'));
  const complete = await readAsset(github, context.repo, release, asset('complete'));
  if (existing) {
    validateMirrorRecord(existing, plan);
    if (complete && !equal(complete, completion(existing))) throw Error('Public ECR completion conflicts with its record');
    await putImmutableAsset(github, context.repo, release, asset('complete'), completion(existing));
    return { active: false, complete: true, plan };
  }
  if (complete) throw Error('Public ECR completion exists without its publication record');
  return { active: true, plan, source };
}
async function verifySource({ github, context, source, work }) {
  const plan = source.plan;
  validateSupplyChainRecord(source);
  const { data: release } = await github.rest.repos.getReleaseByTag({ ...context.repo, tag: plan.tag });
  const policy = plan.supplyChain.cosign;
  const response = await fetch('https://github.com/sigstore/cosign/releases/download/v' + policy.version + '/cosign-linux-amd64', { signal: AbortSignal.timeout(120000) });
  if (!response.ok) throw Error('Pinned Cosign download failed');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (hash(bytes) !== policy.linuxAmd64Sha256) throw Error('Cosign checksum mismatch');
  const binary = join(work, 'cosign');
  await writeFile(binary, bytes, { mode: 0o755 });
  const sboms = new Map();
  for (const descriptor of plan.supplyChain.sboms) {
    const sbom = await readAsset(github, context.repo, release, descriptor.asset, 10000000);
    if (!sbom || sbomHash(sbom) !== descriptor.sha256) throw Error('Frozen source SBOM mismatch');
    validateSbom(sbom, descriptor);
    sboms.set(descriptor.profile + '/' + descriptor.architecture, { descriptor, sbom });
  }
  const flags = ['--certificate-oidc-issuer', signingIssuer, '--certificate-identity-regexp', signingIdentityPattern(plan)];
  const env = { ...process.env, DOCKER_CONFIG: work, REGISTRY_AUTH_FILE: join(work, 'auth.json') };
  const targets = [];
  for (const target of signatureTargets(plan)) {
    const ref = plan.registry + '@' + target.digest;
    const claims = JSON.parse(run(binary, ['verify', ...flags, ref], { env }));
    if (!Array.isArray(claims) || !claims.some(c => c.critical?.image?.['docker-manifest-digest'] === target.digest)) throw Error('Source signature digest mismatch');
    const verified = { ...target, signatureVerified: true };
    if (target.architecture) {
      const { descriptor, sbom } = sboms.get(target.profile + '/' + target.architecture);
      verifyAttestationPayload(run(binary, ['verify-attestation', '--type', 'cyclonedx', ...flags, ref], { env }), sbom, target);
      Object.assign(verified, { attestationVerified: true, sbomSha256: descriptor.sha256 });
    }
    targets.push(verified);
  }
  const evidence = { schemaVersion: 1, status: 'verified', issuer: signingIssuer, identities: signingIdentities(plan), contractSha256: canonicalHash(plan.supplyChain), targets };
  validateSupplyChainRecord({ plan, supplyChain: evidence });
  return evidence;
}
export function describeDestination(result, expected) {
  if (result.error) throw Error('AWS DescribeImages could not execute');
  if (result.status !== 0) {
    if (/\(ImageNotFoundException\)/.test(result.stderr ?? '')) return destinationAction(null, expected);
    throw Error('AWS DescribeImages failed; access/service errors are not missing tags');
  }
  const details = JSON.parse(result.stdout).imageDetails;
  if (!Array.isArray(details) || details.length !== 1) throw Error('Ambiguous destination tag');
  return destinationAction(details[0].imageDigest, expected);
}
export function inspectIndex(raw, image) {
  if ('sha256:' + hash(raw) !== image.digest) throw Error('Registry index digest changed');
  const index = JSON.parse(raw);
  if (index.schemaVersion !== 2 || index.manifests?.length !== image.children.length || index.manifests.some(m =>
    m.platform?.os !== 'linux' || !image.children.some(c => c.architecture === m.platform.architecture && c.digest === m.digest)) ||
    new Set(index.manifests.map(m => m.platform.architecture)).size !== image.children.length) throw Error('Registry index architecture set changed');
}
export async function publishMirror({ github, context, core, prepared, output }) {
  assertContext(context);
  const { plan, source } = prepared;
  if (!equal(mirrorPlan(source, validateConfig(plan.target)), plan) || !plan.target.enabled) throw Error('Frozen Public ECR source/config mismatch');
  await mkdir(output, { recursive: true });
  const work = await mkdtemp(join(tmpdir(), 'keycloak-ecr-'));
  const state = { schemaVersion: 1, ...identity(context, plan), status: 'partial', images: [] };
  const save = () => writeFile(join(output, 'publication.json'), json(state));
  await save();
  try {
    await writeFile(join(work, 'config.json'), '{"auths":{}}\n', { mode: 0o600 });
    await writeFile(join(work, 'auth.json'), '{"auths":{}}\n', { mode: 0o600 });
    state.sourceVerification = await verifySource({ github, context, source, work });
    await save();
    const token = await core.getIDToken(plan.target.audience);
    core.setSecret(token);
    validateToken(token, plan.target, context);
    const tokenPath = join(work, 'token');
    await writeFile(tokenPath, token, { mode: 0o600 });
    const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('AWS_')));
    Object.assign(cleanEnv, { AWS_EC2_METADATA_DISABLED: 'true', AWS_CONFIG_FILE: join(work, 'no-config'), AWS_SHARED_CREDENTIALS_FILE: join(work, 'no-credentials') });
    const credentials = JSON.parse(run('aws', ['sts','assume-role-with-web-identity','--role-arn',plan.target.roleArn,
      '--role-session-name','keycloak-ecr-' + context.runId + '-' + process.env.GITHUB_RUN_ATTEMPT,
      '--duration-seconds','900','--web-identity-token','file://' + tokenPath,'--region','us-east-1','--output','json','--no-cli-pager'], { env: cleanEnv })).Credentials;
    for (const key of ['AccessKeyId','SecretAccessKey','SessionToken']) {
      if (typeof credentials?.[key] !== 'string' || !credentials[key]) throw Error('Incomplete temporary STS credentials');
      core.setSecret(credentials[key]);
    }
    const awsEnv = { ...cleanEnv, AWS_ACCESS_KEY_ID: credentials.AccessKeyId, AWS_SECRET_ACCESS_KEY: credentials.SecretAccessKey, AWS_SESSION_TOKEN: credentials.SessionToken };
    const password = run('aws',['ecr-public','get-login-password','--region','us-east-1','--no-cli-pager'], { env: awsEnv }).trim();
    if (!password) throw Error('Empty transient ECR password');
    core.setSecret(password);
    const auth = Buffer.from('AWS:' + password).toString('base64'); core.setSecret(auth);
    const authPath = join(work, 'push-auth.json');
    await writeFile(authPath, json({ auths: { 'public.ecr.aws': { auth } } }), { mode: 0o600 });
    for (const image of plan.images) {
      const described = spawnSync('aws',['ecr-public','describe-images','--registry-id',plan.target.accountId,'--repository-name','keycloak',
        '--image-ids','imageTag=' + image.tag,'--region','us-east-1','--output','json','--no-cli-pager'], { env: awsEnv, encoding: 'utf8', timeout: 60000 });
      const action = describeDestination(described, image.digest);
      if (action === 'copy') run('skopeo',['copy','--all','--preserve-digests','--src-authfile',join(work,'auth.json'),
        '--dest-authfile',authPath,'docker://' + plan.sourceRegistry + '@' + image.digest,'docker://' + plan.target.repository + ':' + image.tag], { timeout: 900000 });
      const raw = run('skopeo',['inspect','--raw','--authfile',join(work,'auth.json'),'docker://' + plan.target.repository + ':' + image.tag]);
      inspectIndex(raw, image);
      state.images.push(image); await save();
    }
    state.status = 'published'; await save();
  } finally { await rm(work, { recursive: true, force: true }); }
}
export async function nativePull(plan, architecture, context, output) {
  if ((process.arch === 'x64' ? 'amd64' : process.arch) !== architecture || process.platform !== 'linux') throw Error('Native Linux runner required');
  const work = await mkdtemp(join(tmpdir(), 'keycloak-public-pull-'));
  try {
    const authPath = join(work, 'auth.json');
    await writeFile(authPath, '{"auths":{}}\n');
    const env = { ...process.env, REGISTRY_AUTH_FILE: authPath, DOCKER_CONFIG: work };
    const evidence = { schemaVersion: 1, ...identity(context, plan), architecture, status: 'verified', images: [] };
    for (const image of plan.images) {
      const ref = plan.target.repository + '@' + image.digest;
      inspectIndex(run('skopeo',['inspect','--raw','--authfile',authPath,'docker://' + ref],{env}), image);
      const child = image.children.find(c => c.architecture === architecture);
      const raw = run('skopeo',['inspect','--raw','--authfile',authPath,'docker://' + plan.target.repository + '@' + child.digest],{env});
      if ('sha256:' + hash(raw) !== child.digest) throw Error('Public child manifest digest mismatch');
      const manifest = JSON.parse(raw);
      if (!/^sha256:[a-f0-9]{64}$/.test(manifest.config?.digest)) throw Error('Invalid child config digest');
      run('podman',['pull','--authfile',authPath,'--platform','linux/' + architecture,ref],{env,timeout:600000});
      const inspected = JSON.parse(run('podman',['image','inspect',ref],{env}));
      if (inspected.length !== 1 || inspected[0].Architecture !== architecture || inspected[0].Os !== 'linux' ||
          inspected[0].Id.replace(/^sha256:/,'') !== manifest.config.digest.slice(7) ||
          inspected[0].Labels?.['org.opencontainers.image.revision'] !== plan.sourceCommit ||
          inspected[0].Labels?.['cloud.rambow.keycloak.profile'] !== image.profile) throw Error('Anonymous native pull selected a different image');
      evidence.images.push({ profile: image.profile, digest: image.digest, childDigest: child.digest, configDigest: manifest.config.digest });
    }
    await mkdir(output, { recursive: true });
    await writeFile(join(output, architecture + '.json'), json(evidence));
  } finally { await rm(work, { recursive: true, force: true }); }
}
export async function recordMirror({ github, context, plan, directory }) {
  assertContext(context);
  const publication = JSON.parse(await readFile(join(directory, 'publication.json'),'utf8'));
  const nativePulls = await Promise.all(['amd64','arm64'].map(async a => JSON.parse(await readFile(join(directory,a + '.json'),'utf8'))));
  if (!equal(identity(context,plan), { runId: publication.runId, attempt: publication.attempt, headSha: publication.headSha, planSha256: publication.planSha256 })) throw Error('Publication attempt association mismatch');
  const record = validateMirrorRecord({ schemaVersion: 1, status: 'published', publishedAt: new Date().toISOString(), plan, publication, nativePulls }, plan);
  const { data: release } = await github.rest.repos.getReleaseByTag({ ...context.repo, tag: plan.tag });
  if (release.id !== plan.releaseId || release.draft || release.prerelease) throw Error('Release identity changed before recording');
  await assertTagSource(github,context.repo,plan.tag,plan.sourceCommit);
  const catalog = await readCatalog(github,context.repo,'main');
  const active = activeReleaseRecords(catalog).find(r => r.plan.tag === plan.tag);
  if (!active || !equal(mirrorPlan(active,plan.target),plan)) throw Error('Source publication changed or was withdrawn before recording');
  await putImmutableAsset(github, context.repo, release, asset('record'), record);
  await putImmutableAsset(github, context.repo, release, asset('complete'), completion(record));
  return record;
}
