import { createHash } from 'node:crypto';

export const marker = '<!-- rambow-upstream-updates:v1 -->';
export const managedPaths = ['images.lock.json', 'README.md', 'AGENTS.md', 'config/java.options', 'changes/upstream.json'];
export const sha256 = value => createHash('sha256').update(value).digest('hex');
export const formatJson = value => JSON.stringify(value, null, 2) + '\n';
export const filesHash = files => sha256(JSON.stringify(managedPaths.map(path => [path, files[path]])));
// Public identifiers, pinned after registering the private organization App.
export const updaterApp = Object.freeze({ schemaVersion: 1, appId: 5523068, clientId: 'Iv23li88vLKtqCEQifBK',
  slug: 'rambow-keycloak-updater', bot: Object.freeze({ login: 'rambow-keycloak-updater[bot]', type: 'Bot',
    id: 349720571, node_id: 'BOT_kgDOFNhP-w' }) });

export function validateUpdaterIdentity(identity) {
  if (!identity || identity.type !== 'Bot' || !/^[a-z0-9][a-z0-9-]*\[bot\]$/.test(identity.login ?? '') ||
      identity.login === 'github-actions[bot]' || !Number.isSafeInteger(identity.id) || identity.id <= 0 ||
      typeof identity.node_id !== 'string' || !identity.node_id.length) {
    throw new Error('A pinned dedicated GitHub App bot identity is required; GITHUB_TOKEN writes are disabled.');
  }
  return identity;
}

export const sameUpdater = (actual, expected) => actual?.type === 'Bot' && actual.login === expected.login &&
  actual.id === expected.id && actual.node_id === expected.node_id;

export function validateUpdaterApp(config, mintedSlug) {
  validateUpdaterIdentity(config?.bot);
  if (config.schemaVersion !== 1 || !Number.isSafeInteger(config.appId) || config.appId <= 0 ||
      !/^Iv[0-9A-Za-z]+$/.test(config.clientId ?? '') || config.bot.login !== config.slug + '[bot]' ||
      (mintedSlug !== undefined && mintedSlug !== config.slug)) {
    throw new Error('GitHub App configuration/token identity mismatch.');
  }
  return config;
}

export function chooseVersion(current, release) {
  const valid = value => /^\d+\.\d+\.\d+$/.test(value);
  if (!valid(current)) throw new Error('Current Keycloak version must be stable semver');
  if (release.draft || release.prerelease || !valid(release.tag_name)) return current;
  const old = current.split('.').map(Number);
  const next = release.tag_name.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if (next[i] > old[i]) return release.tag_name;
    if (next[i] < old[i]) return current;
  }
  return current;
}

export async function inspectCompatibility(version, javaMajor, baseline, fetcher = fetch) {
  if (!/^\d+\.\d+\.\d+$/.test(version)) throw new Error('Invalid Keycloak source ref');
  const prefix = 'https://raw.githubusercontent.com/keycloak/keycloak/' + version + '/';
  const paths = ['quarkus/dist/src/main/content/bin/kc.sh', 'docs/guides/server/supported-configurations.adoc'];
  const sources = await Promise.all(paths.map(async path => {
    const response = await fetcher(prefix + path, { signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw new Error('Cannot inspect pinned Keycloak source: ' + path + ' (' + response.status + ')');
    return response.text();
  }));
  const startupHash = sha256(sources[0]);
  const supported = [...sources[1].matchAll(/\* OpenJDK (\d+) \(LTS\)/g)].map(m => Number(m[1]));
  const warnings = [];
  if (startupHash !== baseline.startupScriptSha256) warnings.push('The upstream kc.sh differs from the reviewed launcher baseline. Review JVM flags, startup behavior and config/java.options before updating the baseline hash.');
  if (!supported.length) warnings.push('Cannot determine supported LTS Java versions from pinned Keycloak documentation. Manual review is required.');
  else if (Math.max(...supported) !== javaMajor || !supported.includes(javaMajor)) warnings.push('The latest supported Java LTS is ' + Math.max(...supported) + ', while this lock uses ' + javaMajor + '. Review both Java image families and launcher compatibility.');
  if (javaMajor !== baseline.javaMajor) warnings.push('The Java major differs from the reviewed compatibility baseline.');
  return { startupHash, supported, warnings };
}

export function candidateFiles(currentFiles, nextLock, warnings, issue) {
  const old = JSON.parse(currentFiles['images.lock.json']);
  const result = { ...currentFiles, 'images.lock.json': formatJson(nextLock) };
  if (old.keycloakVersion !== nextLock.keycloakVersion) {
    result['AGENTS.md'] = result['AGENTS.md'].replaceAll(old.keycloakVersion, nextLock.keycloakVersion);
    if (!warnings.length) result['config/java.options'] = result['config/java.options'].replaceAll(old.keycloakVersion, nextLock.keycloakVersion);
  }
  if (issue && ['keycloak', 'runtime', 'builder'].some(k => old[k] !== nextLock[k])) {
    const details = ['keycloak', 'runtime', 'builder'].filter(k => old[k] !== nextLock[k]).map(k =>
      k === 'keycloak' && old.keycloakVersion !== nextLock.keycloakVersion ? 'Upgrade Keycloak from ' + old.keycloakVersion + ' to ' + nextLock.keycloakVersion :
        'Refresh ' + k + ' digest from ' + old[k].split('@sha256:')[1].slice(0, 16) + ' to ' + nextLock[k].split('@sha256:')[1].slice(0, 16));
    result['changes/upstream.json'] = formatJson({ schemaVersion: 1, changes: [{
      type: 'maintenance',
      summary: details.join('; ') + '.', issues: [issue], profiles: ['core', 'aws'],
    }] });
  }
  return result;
}

export function autoMergeEligible(previous, next, warnings) {
  if (warnings.length || previous.keycloakVersion.split('.').slice(0, 2).join('.') !== next.keycloakVersion.split('.').slice(0, 2).join('.')) return false;
  const rest = lock => Object.fromEntries(Object.entries(lock).filter(([key]) => !['keycloakVersion', 'keycloak', 'builder', 'runtime'].includes(key)));
  return JSON.stringify(rest(previous)) === JSON.stringify(rest(next)) &&
    ['builder', 'runtime'].every(key => previous[key].split('@')[0] === next[key].split('@')[0]);
}

export function issueBody() {
  return '### Maintenance goal\nKeep the pinned Keycloak release, distroless nonroot runtime, and current Temurin build-image family current through a reviewed, tested PR.\n\n' +
    '### Scope\nRefresh only the managed upstream image locks, associated version references and Issue-linked fix/feature change fragment. Preserve PostgreSQL fixtures, AWS dependencies, Java major and Debian family. The PR contains the current detected changes and source links.\n\n' +
    '### Security and compatibility\nKeep immutable digests, distroless UID 65532, Buildah and protected main. Changed startup code or supported Java LTS blocks compatibility checks until reviewed. Native auto-merge is limited to patch/digest updates after required checks; larger upgrades need review. No deployment, registry publication, review approval or persistent token.\n\n' +
    '### Acceptance criteria\n- [ ] Confirm patch/digest eligibility or review larger/compatibility-changing upgrades\n- [ ] Confirm Issue policy and both core/aws image checks pass\n- [ ] Merge only after the required checks and any required review\n\n' +
    '### Validation plan\nRun the required Issue policy and CI workflows on the update branch. Verify startup-source/Java compatibility, locked inputs, both image profiles, TLS failures, authentication, offline IAM signing and graceful shutdown. Live cloud validation remains separate.\n';
}

export function pullBody(issue, previous, next, files, warnings, headSha) {
  const rows = ['keycloak', 'runtime', 'builder'].filter(key => previous[key] !== next[key])
    .map(key => '| ' + key + ' | `' + previous[key] + '` | `' + next[key] + '` |').join('\n');
  const body = marker + '\n<!-- generated-head-sha:' + headSha + ' -->\n<!-- generated-files-sha256:' + filesHash(files) + ' -->\n' +
    '## Linked issues\n\nCloses #' + issue + '\n\n## Problem and resulting behavior\n\nRefresh upstream image inputs while preserving the existing image families and Java major.\n\n' +
    '| Input | Previous | Candidate |\n| --- | --- | --- |\n' + rows + '\n\n' +
    'Sources: [Keycloak release](https://github.com/keycloak/keycloak/releases/tag/' + next.keycloakVersion + '), [distroless](https://github.com/GoogleContainerTools/distroless).\n\n' +
    '## Validation\n\nGitHub App PR events trigger CI and Issue policy for this branch. Required checks gate merging; runtime checks cover core/aws images, TLS, authentication and shutdown.\n\n' +
    '## Security and compatibility\n\n' + (autoMergeEligible(previous, next, warnings) ? 'Eligible for native auto-merge after required checks: patch/digest changes within reviewed image families.' : '**Maintainer review required.** Auto-merge is disabled for this candidate.') + '\n\n' + (warnings.length ? warnings.map(w => '- **Review required:** ' + w).join('\n') : 'Upstream startup code matches the reviewed baseline and the locked Java major remains the latest supported LTS.') + '\n\n' +
    '## Checklist\n\n- [x] The linked maintenance Issue follows its template.\n- [ ] The required checks and any required maintainer review are complete.\n- [x] No secrets, Docker tooling, protection bypass or deployment were introduced.\n\n' +
    'This PR is managed by the upstream updater. Editing its commits, managed files or generated body stops automatic refresh; close it to start a fresh update after preserving any needed work.\n';
  return body + '<!-- generated-body-sha256:' + sha256(body) + ' -->\n';
}

export function assertBotOwned(pr, commit, files, identity) {
  validateUpdaterIdentity(identity);
  if (!sameUpdater(pr.user, identity) || !sameUpdater(commit.author, identity)) throw new Error('Update branch has human/unknown commits; refusing to overwrite it.');
  const expectedHead = pr.body?.match(/<!-- generated-head-sha:([a-f0-9]{40}) -->/)?.[1];
  if (!expectedHead || expectedHead !== commit.sha) throw new Error('Update branch contains untracked commits; refusing to overwrite it.');
  const expectedFiles = pr.body?.match(/<!-- generated-files-sha256:([a-f0-9]{64}) -->/)?.[1];
  const expectedBody = pr.body?.match(/<!-- generated-body-sha256:([a-f0-9]{64}) -->\n?$/)?.[1];
  const cleanBody = pr.body?.replace(/<!-- generated-body-sha256:[a-f0-9]{64} -->\n?$/, '');
  if (!expectedFiles || filesHash(files) !== expectedFiles || !expectedBody || sha256(cleanBody) !== expectedBody) throw new Error('Update files or PR body were edited; refusing to overwrite human work.');
}
