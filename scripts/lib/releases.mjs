import { createHash } from 'node:crypto';
export const registry = 'quay.io/rambow-cloud/keycloak';
export const repository = 'rambow-cloud/keycloak';
export const profiles = ['core', 'aws'];
export const json = value => JSON.stringify(value, null, 2) + '\n';
export const hash = value => createHash('sha256').update(value).digest('hex');
export const equal = (a, b) => json(a) === json(b);
export const isSha = value => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);
export const isDigest = value => typeof value === 'string' && /^sha256:[a-f0-9]{64}$/.test(value);
export function parseRelease(tag) {
  const m = /^v((?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*))-r([1-9]\d*)$/.exec(tag ?? '');
  if (!m || !Number.isSafeInteger(Number(m[2]))) throw new Error('Release tag must be v<Keycloak x.y.z>-r<positive revision>.');
  return { tag, keycloakVersion: m[1], revision: Number(m[2]) };
}
export function canonicalTag(tag, profile) {
  parseRelease(tag);
  if (!profiles.includes(profile)) throw new Error('Unknown image profile.');
  return tag.slice(1) + '-' + profile;
}
export function validateAliases(config) {
  if (config.schemaVersion !== 1 || !Array.isArray(config.aliases)) throw new Error('Invalid alias configuration.');
  const seen = new Set();
  for (const alias of config.aliases) {
    if (!/^[a-z0-9_][a-z0-9_.-]{0,127}$/.test(alias.tag ?? '') || alias.tag === 'latest' ||
        /^v?\d+\.\d+\.\d+-r\d+-(core|aws)$/.test(alias.tag) || !profiles.includes(alias.profile) ||
        !/^\d+\.\d+\.\d+$/.test(alias.keycloakVersion ?? '') || seen.has(alias.tag)) throw new Error('Alias needs a unique non-reserved tag, explicit profile and Keycloak version.');
    seen.add(alias.tag);
  }
  return config;
}
export function validatePlan(plan) {
  const version = parseRelease(plan.tag);
  if (plan.schemaVersion !== 1 || plan.registry !== registry || plan.releaseId < 1 || !Number.isSafeInteger(plan.releaseId) ||
      !isSha(plan.sourceCommit) || !isSha(plan.toolsCommit) || !Number.isSafeInteger(plan.sourceRun?.id) || plan.sourceRun.id < 1 ||
      !Number.isSafeInteger(plan.sourceRun?.attempt) || plan.sourceRun.attempt < 1 ||
      plan.keycloakVersion !== version.keycloakVersion || plan.revision !== version.revision ||
      !/^[a-f0-9]{64}$/.test(plan.lockSha256 ?? '') || plan.imageLock?.keycloakVersion !== version.keycloakVersion ||
      plan.imageLock?.platform !== 'linux/amd64') throw new Error('Invalid frozen publication identity.');
  validateAliases({ schemaVersion: 1, aliases: plan.aliases });
  if (plan.aliases.some(a => a.keycloakVersion !== plan.keycloakVersion)) throw new Error('Frozen alias version mismatch.');
  if (!plan.previousAliases || Object.keys(plan.previousAliases).length !== plan.aliases.length || plan.aliases.some(a =>
    !Object.hasOwn(plan.previousAliases, a.tag) || (plan.previousAliases[a.tag] !== null && !isDigest(plan.previousAliases[a.tag])))) throw new Error('Invalid previous alias bindings.');
  if (!Array.isArray(plan.images) || plan.images.length !== 2) throw new Error('Both image profiles must be frozen.');
  for (const profile of profiles) {
    const images = plan.images.filter(i => i.profile === profile);
    const i = images[0];
    if (images.length !== 1 || i.tag !== canonicalTag(plan.tag, profile) || !isDigest(i.digest) ||
        !Number.isSafeInteger(i.artifactId) || i.artifactId < 1 ||
        i.artifactName !== 'keycloak-oci-' + profile + '-amd64-' + plan.sourceCommit ||
        !/^[a-f0-9]{64}$/.test(i.archiveSha256 ?? '')) throw new Error('Invalid frozen image/profile/artifact.');
  }
  return plan;
}
export function validateRecord(record) {
  validatePlan(record.plan);
  if (record.schemaVersion !== 1 || record.status !== 'published' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(record.publishedAt ?? '') ||
      !Number.isFinite(Date.parse(record.publishedAt)) || !isSha(record.validationToolsCommit) ||
      !Number.isSafeInteger(record.publishRunId) || record.publishRunId < 1 || !Array.isArray(record.aliasChanges) ||
      record.aliasChanges.length !== record.plan.aliases.length) throw new Error('Invalid publication record.');
  for (const alias of record.plan.aliases) {
    const changes = record.aliasChanges.filter(c => c.tag === alias.tag);
    const c = changes[0];
    const image = record.plan.images.find(i => i.profile === alias.profile);
    if (changes.length !== 1 || c.profile !== alias.profile || c.toDigest !== image.digest || c.fromDigest !== record.plan.previousAliases[c.tag] ||
        (c.fromDigest !== null && !isDigest(c.fromDigest))) throw new Error('Invalid alias history.');
  }
  return record;
}
export function validateCatalog(records) {
  const releases = new Set();
  const ids = new Set();
  for (const record of records) {
    validateRecord(record);
    if (releases.has(record.plan.tag) || ids.has(record.plan.releaseId)) throw new Error('Duplicate release record.');
    releases.add(record.plan.tag); ids.add(record.plan.releaseId);
  }
  // An alias cannot silently jump away from its last recorded binding.
  const state = new Map();
  for (const r of [...records].sort((a, b) => Date.parse(a.publishedAt) - Date.parse(b.publishedAt) || a.publishRunId - b.publishRunId)) {
    for (const c of r.aliasChanges) {
      if ((state.get(c.tag) ?? null) !== c.fromDigest) throw new Error('Alias history is not continuous: ' + c.tag);
      state.set(c.tag, c.toDigest);
    }
  }
  return records;
}
export function priorAliasDigest(records, tag) {
  return [...records].sort((a, b) => Date.parse(b.publishedAt) - Date.parse(a.publishedAt) || b.publishRunId - a.publishRunId)
    .flatMap(r => r.aliasChanges).find(c => c.tag === tag)?.toDigest ?? null;
}
export function assertNewRevision(records, tag) {
  const next = parseRelease(tag);
  if (records.some(r => r.plan.keycloakVersion === next.keycloakVersion && r.plan.revision >= next.revision)) throw new Error('Use a higher unused image revision for this Keycloak version.');
}
export function selectRun(runs, { sha, main, tag }) {
  return runs.filter(r => r.head_sha === sha && r.repository?.full_name === repository && r.head_repository?.full_name === repository &&
    ((r.event === 'push' && r.head_branch === main) || (r.event === 'workflow_dispatch' && [main, tag].includes(r.head_branch))))
    .sort((a, b) => b.id - a.id || b.run_attempt - a.run_attempt)[0];
}
export function chooseArtifacts(artifacts, sha) {
  return profiles.map(profile => {
    const name = 'keycloak-oci-' + profile + '-amd64-' + sha;
    const matches = artifacts.filter(a => a.name === name && !a.expired);
    if (matches.length !== 1 || matches[0].size_in_bytes > 3000000000) throw new Error('Missing, ambiguous or oversized OCI artifact: ' + name);
    return { profile, artifactId: matches[0].id, artifactName: name };
  });
}
export function destinationAction(existingDigest, expectedDigest, mutable = false) {
  if (!isDigest(expectedDigest)) throw new Error('Invalid expected image digest.');
  if (existingDigest === expectedDigest) return 'reuse';
  if (existingDigest !== null && !isDigest(existingDigest)) throw new Error('Cannot determine destination state.');
  if (existingDigest !== null && !mutable) throw new Error('Immutable Quay tag already points to a different digest.');
  return 'copy';
}
export function resolveTag(records, tag, releaseTag) {
  validateCatalog(records);
  const ordered = [...records].sort((a, b) => Date.parse(b.publishedAt) - Date.parse(a.publishedAt) || b.publishRunId - a.publishRunId);
  for (const record of ordered) {
    if (releaseTag && record.plan.tag !== releaseTag) continue;
    const image = record.plan.images.find(i => i.tag === tag) ??
      record.plan.images.find(i => record.plan.aliases.some(a => a.tag === tag && a.profile === i.profile));
    if (image) return { tag, release: record.plan.tag, profile: image.profile, digest: image.digest,
      reference: registry + '@' + image.digest, sourceCommit: record.plan.sourceCommit };
  }
  throw new Error('No recorded binding for tag: ' + tag);
}
export function renderCatalog(records) {
  validateCatalog(records);
  let md = '# Published images\n\n<!-- Generated from release JSON records. Do not edit by hand. -->\n\n' +
    'Registry: `' + registry + '`. Formal releases only; no `latest` tag. Use digest-pinned references for deployments.\n\n';
  if (!records.length) return md + 'No image releases have been recorded yet.\n';
  md += '| Release | Keycloak | Profile | Image tag | Digest | Aliases | Published (UTC) |\n| --- | --- | --- | --- | --- | --- | --- |\n';
  const ordered = [...records].sort((a, b) => Date.parse(b.publishedAt) - Date.parse(a.publishedAt) || b.publishRunId - a.publishRunId);
  for (const r of ordered) for (const i of r.plan.images) {
    md += '| [' + r.plan.tag + '](https://github.com/' + repository + '/releases/tag/' + r.plan.tag + ') | ' + r.plan.keycloakVersion + ' | ' + i.profile +
      ' | `' + i.tag + '` | `' + i.digest + '` | ' + (r.plan.aliases.filter(a => a.profile === i.profile).map(a => '`' + a.tag + '`').join(', ') || '—') + ' | ' + r.publishedAt + ' |\n';
  }
  for (const r of ordered) {
    md += '\n## ' + r.plan.tag + '\n\n' +
      '[Source commit](https://github.com/' + repository + '/commit/' + r.plan.sourceCommit + ') · ' +
      '[Source CI](https://github.com/' + repository + '/actions/runs/' + r.plan.sourceRun.id + ') · ' +
      '[Publication and fresh scans](https://github.com/' + repository + '/actions/runs/' + r.publishRunId + ')\n\n';
    for (const i of r.plan.images) md += i.profile + ':\n\n```sh\npodman pull ' + registry + '@' + i.digest + '\n```\n\n';
    if (r.aliasChanges.length) md += 'Alias changes:\n\n' + r.aliasChanges.map(c => '- `' + c.tag + '`: ' + (c.fromDigest ? '`' + c.fromDigest + '`' : 'unassigned') + ' → `' + c.toDigest + '`').join('\n') + '\n';
  }
  return md.trimEnd() + '\n';
}
