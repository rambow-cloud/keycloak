const test = require('node:test');
const assert = require('node:assert/strict');
const { readFile, writeFile, mkdir, mkdtemp, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const { createHash } = require('node:crypto');
const sboms = import('../scripts/lib/sbom.mjs');
const signing = import('../scripts/lib/supply-chain.mjs');
const releases = import('../scripts/lib/releases.mjs');
const original = JSON.parse(require('node:fs').readFileSync(resolve('releases/records/v26.8.2-r2.json'), 'utf8'));

function report(architecture) {
  return { SchemaVersion: 2, Metadata: { ImageConfig: { architecture } }, Results: [
    { Type: 'jar', Packages: [
      { Name: 'io.opentelemetry:opentelemetry-api', Version: '1.67.0',
        Identifier: { PURL: 'pkg:maven/io.opentelemetry/opentelemetry-api@1.67.0' }, FilePath: 'original-name-1.62.0.jar' },
      { Name: 'org.keycloak:keycloak-core', Version: '26.8.2',
        Identifier: { PURL: 'pkg:maven/org.keycloak/keycloak-core@26.8.2' }, FilePath: 'keycloak-core.jar' },
    ] },
  ] };
}

async function fixture() {
  const { createSbom, sbomHash } = await sboms;
  const plan = structuredClone(original.plan);
  const assets = {};
  const descriptors = plan.images.flatMap(image => image.children.map(child => {
    const value = createSbom(report(child.architecture), { ...child, profile: image.profile, scannerVersion: '0.76.1' });
    const asset = 'sbom-' + image.profile + '-' + child.architecture + '.cdx.json';
    assets[asset] = value;
    return { profile: image.profile, ...child, asset, sha256: sbomHash(value) };
  }));
  const binary = Buffer.from('verified-cosign-test-binary');
  plan.supplyChain = { schemaVersion: 1, cosign: { version: '3.1.4',
    linuxAmd64Sha256: createHash('sha256').update(binary).digest('hex') }, sboms: descriptors };
  return { plan, assets, binary };
}

test('SBOM preserves identified versions, duplicate JAR locations, and exact RPM inventory', async () => {
  const { createSbom, inventoryPurls, validateSbom, sbomBytes } = await sboms;
  const runtime = JSON.parse(await readFile(resolve('dependencies/runtime/c5ab8cec00b8a1d999e5663b26a5f11646183a1b99ea82676f1fed4a02eee51f/amd64-sbom.cdx.json'), 'utf8'));
  const rpms = runtime.components.filter(component => component.purl?.startsWith('pkg:rpm/'));
  const source = report('amd64');
  source.Results.push({ Type: 'amazon', Packages: rpms.map(component => ({
    Name: component.name, Version: component.version, Identifier: { PURL: component.purl },
  })) });
  source.Results[0].Packages.push({ ...source.Results[0].Packages[0], FilePath: 'another-location.jar' });
  const identity = { ...original.plan.images[0].children[0], profile: 'core', scannerVersion: '0.76.1', runtimeSbom: runtime };
  const sbom = createSbom(source, identity);
  assert.deepEqual(sbom.components.filter(component => component.purl?.startsWith('pkg:rpm/')), [...rpms].sort((a,b) => a.purl.localeCompare(b.purl)));
  const telemetry = sbom.components.find(component => component.name === 'opentelemetry-api');
  assert.equal(telemetry.version, '1.67.0');
  assert.equal(telemetry.properties.length, 2);
  assert.equal(sbomBytes(sbom), sbomBytes(createSbom(source, identity)));
  assert.throws(() => validateSbom(sbom, { ...identity, architecture: 'arm64' }), /identity/);
  const missing = structuredClone(sbom);
  missing.components = missing.components.filter(component => component !== missing.components.find(item => item.name === 'keycloak-core'));
  assert.throws(() => validateSbom(missing, { ...identity, purls: inventoryPurls(source) }), /coverage/);
  source.Results[0].Packages[0].Identifier = {};
  assert.throws(() => createSbom(source, identity), /complete identified/);
});

test('release contract binds every child and forbids incomplete signing evidence', async () => {
  const { validatePlan, validateRecord } = await releases;
  const { signatureTargets, signingIdentities, signingIssuer, canonicalHash } = await signing;
  const { plan } = await fixture();
  validatePlan(plan);
  const changed = structuredClone(plan);
  changed.supplyChain.sboms[0].digest = changed.images[1].digest;
  assert.throws(() => validatePlan(changed), /match/);
  const missing = structuredClone(plan);
  missing.supplyChain.sboms.pop();
  assert.throws(() => validatePlan(missing), /contract/);
  const record = { ...original, plan };
  assert.throws(() => validateRecord(record), /signing evidence/);
  record.supplyChain = { schemaVersion: 1, status: 'verified', issuer: signingIssuer, identities: signingIdentities(plan),
    contractSha256: canonicalHash(plan.supplyChain), targets: signatureTargets(plan).map(target => ({
      ...target, signatureVerified: true, ...(target.architecture ? { attestationVerified: true,
        sbomSha256: plan.supplyChain.sboms.find(s => s.profile === target.profile && s.architecture === target.architecture).sha256 } : {}),
    })) };
  validateRecord(record);
  record.supplyChain.targets[0].signatureVerified = false;
  assert.throws(() => validateRecord(record), /signature verification/);
});

test('verified attestation must have the exact subject, predicate and strict workflow identity', async () => {
  const { verifyAttestationPayload, signingIdentityPattern, signingIdentities } = await signing;
  const { plan, assets } = await fixture();
  const target = plan.supplyChain.sboms[0];
  const sbom = assets[target.asset];
  const envelope = statement => JSON.stringify({ payload: Buffer.from(JSON.stringify(statement)).toString('base64') });
  const statement = { predicateType: 'https://cyclonedx.org/bom', subject: [{ digest: { sha256: target.digest.slice(7) } }], predicate: sbom };
  verifyAttestationPayload(envelope(statement), sbom, target);
  assert.throws(() => verifyAttestationPayload(envelope({ ...statement, predicate: { ...sbom, version: 2 } }), sbom, target), /differs/);
  assert.throws(() => verifyAttestationPayload(envelope({ ...statement, subject: [] }), sbom, target), /differs/);
  const pattern = new RegExp(signingIdentityPattern(plan));
  for (const identity of signingIdentities(plan)) assert.ok(pattern.test(identity));
  for (const identity of [
    signingIdentities(plan)[0] + '/evil',
    signingIdentities(plan)[0].replace('rambow-cloud', 'other-owner'),
    signingIdentities(plan)[0].replace('refs/heads/main', 'refs/heads/feature'),
    signingIdentities(plan)[1].replace('v26.8.2-r2', 'v26.8.2-r3'),
  ]) assert.ok(!pattern.test(identity));
});

test('partial signature recovery reuses valid signatures and verifies anonymously before recording', async () => {
  const { prepareSigning } = await import('../scripts/sign-release.mjs');
  const { validateSupplyChainRecord } = await signing;
  const { plan, assets, binary } = await fixture();
  const work = await mkdtemp(join(tmpdir(), 'keycloak-signing-test-'));
  const output = join(work, 'evidence');
  await mkdir(output);
  const previous = process.env.GITHUB_WORKFLOW_REF;
  process.env.GITHUB_WORKFLOW_REF = 'rambow-cloud/keycloak/.github/workflows/release.yml@refs/heads/main';
  const completed = new Set();
  const operations = [];
  let failOnce = true;
  const github = { rest: { repos: {
    getReleaseByTag: async () => ({ data: { id: plan.releaseId } }),
    listReleaseAssets: 'assets',
    getReleaseAsset: async ({ asset_id }) => ({ data: JSON.stringify(assets[asset_id]) }),
  } }, paginate: async () => Object.keys(assets).map(name => ({ name, id: name, size: 1000 })) };
  const runCosign = (_binary, args, options) => {
    const [action] = args;
    const reference = args.find(value => value.startsWith('quay.io/'));
    const digest = reference.split('@')[1];
    const kind = action.includes('attest') ? 'attestation' : 'signature';
    const key = kind + digest;
    operations.push({ action, digest, config: options.env.DOCKER_CONFIG });
    if (['sign', 'attest'].includes(action)) {
      assert.equal(args.at(-1), 'masked-transient-token');
      completed.add(key);
      return { status: 0 };
    }
    assert.equal(options.env.DOCKER_CONFIG, join(work, 'anonymous'));
    assert.ok(args.includes('https://token.actions.githubusercontent.com'));
    if (failOnce && action === 'verify-attestation') { failOnce = false; return { status: 1 }; }
    if (!completed.has(key)) return { status: 1 };
    if (kind === 'signature') return { status: 0, stdout: JSON.stringify([{ critical: { image: { 'docker-manifest-digest': digest } } }]) };
    const descriptor = plan.supplyChain.sboms.find(item => item.digest === digest);
    return { status: 0, stdout: JSON.stringify({ payload: Buffer.from(JSON.stringify({
      predicateType: 'https://cyclonedx.org/bom', subject: [{ digest: { sha256: digest.slice(7) } }], predicate: assets[descriptor.asset],
    })).toString('base64') }) };
  };
  try {
    const secure = await prepareSigning(plan, { github, context: { repo: { owner: 'rambow-cloud', repo: 'keycloak' } },
      work, output, mask: () => {}, getIDToken: async audience => { assert.equal(audience, 'sigstore'); return 'masked-transient-token'; },
      fetchImpl: async () => ({ ok: true, arrayBuffer: async () => binary }), runCosign });
    const evidence = await secure(work);
    validateSupplyChainRecord({ plan, supplyChain: evidence });
    const writes = operations.filter(item => ['sign', 'attest'].includes(item.action)).length;
    assert.equal(writes, 10);
    await secure(work);
    assert.equal(operations.filter(item => ['sign', 'attest'].includes(item.action)).length, writes);
    assert.equal(JSON.parse(await readFile(join(output, 'supply-chain-verification.json'), 'utf8')).status, 'verified');
  } finally {
    if (previous === undefined) delete process.env.GITHUB_WORKFLOW_REF;
    else process.env.GITHUB_WORKFLOW_REF = previous;
    await rm(work, { recursive: true, force: true });
  }
});

test('signature failure preserves uploaded tags and blocks aliases', async () => {
  const { publishImages } = await import('../scripts/lib/quay-publish.mjs');
  const { plan } = await fixture();
  plan.aliases = [{ tag: 'stable-core', profile: 'core', keycloakVersion: plan.keycloakVersion }];
  plan.previousAliases = { 'stable-core': null };
  const copied = [];
  const adapter = { inspect: async () => null, copy: async (image, reference) => { copied.push(reference); return image.digest; },
    secure: async () => { throw Error('Attestation upload interrupted'); } };
  let state;
  await assert.rejects(publishImages(plan, adapter, { runId: 1234, progress: value => { state = value; } }), /interrupted/);
  assert.equal(state.status, 'partial');
  assert.deepEqual(state.completedTags, plan.images.map(image => image.tag));
  assert.equal(copied.length, 2);
});

test('freeze saves SBOMs before the plan and recovery requires the original inventory assets', async () => {
  const { makeFrozenPlan, freezeRelease } = await import('../scripts/quay-release.mjs');
  const { canonicalHash } = await signing;
  const { plan, assets } = await fixture();
  const scans = plan.images.map(image => ({ ...image, sourceCommit: plan.sourceCommit, sourceRunId: plan.sourceRun.id,
    lockSha256: plan.lockSha256, sboms: plan.supplyChain.sboms.filter(sbom => sbom.profile === image.profile) }));
  const prepared = { ...plan, supplyChain: { schemaVersion: 1, cosign: plan.supplyChain.cosign } };
  const frozen = makeFrozenPlan(prepared, scans);
  assert.equal(canonicalHash(frozen), canonicalHash(plan));
  assert.throws(() => makeFrozenPlan(prepared, scans.map(scan => ({ ...scan, sboms: [] }))), /contract/);
  const work = await mkdtemp(join(tmpdir(), 'keycloak-freeze-test-'));
  const uploaded = {};
  const order = [];
  const context = { repo: { owner: 'rambow-cloud', repo: 'keycloak' } };
  const github = { rest: { repos: {
    getCommit: async () => ({ data: { sha: plan.sourceCommit } }),
    getReleaseByTag: async () => ({ data: { id: plan.releaseId } }),
    listReleaseAssets: 'assets',
    getReleaseAsset: async ({ asset_id }) => ({ data: JSON.stringify(uploaded[asset_id]) }),
    uploadReleaseAsset: async ({ name, data }) => { order.push(name); uploaded[name] = JSON.parse(data.toString()); },
  } }, paginate: async () => Object.keys(uploaded).map(name => ({ name, id: name, size: 1000 })) };
  const previous = process.env.GITHUB_RUN_ATTEMPT;
  process.env.GITHUB_RUN_ATTEMPT = '1';
  try {
    for (const sbom of plan.supplyChain.sboms) {
      const directory = join(work, 'release-scan-' + sbom.profile + '-1', sbom.architecture);
      await mkdir(directory, { recursive: true });
      await writeFile(join(directory, 'sbom.cdx.json'), JSON.stringify(assets[sbom.asset]));
    }
    await freezeRelease({ github, context, prepared, scans, sbomDirectory: work });
    assert.equal(order.length, 5);
    assert.equal(order.at(-1), 'publication-plan.json');
    // Fresh scan data may vary on recovery. The frozen inventory must remain identical.
    await rm(work, { recursive: true, force: true });
    await freezeRelease({ github, context, prepared: { ...prepared, frozen }, scans, sbomDirectory: work });
    assert.equal(order.length, 5);
    delete uploaded[plan.supplyChain.sboms[0].asset];
    await assert.rejects(freezeRelease({ github, context, prepared: { ...prepared, frozen }, scans }), /checksum/);
  } finally {
    if (previous === undefined) delete process.env.GITHUB_RUN_ATTEMPT;
    else process.env.GITHUB_RUN_ATTEMPT = previous;
    await rm(work, { recursive: true, force: true });
  }
});
