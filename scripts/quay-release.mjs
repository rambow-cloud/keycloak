import { registry, repository, profiles, json, hash, equal, parseRelease, canonicalTag, validateAliases,
  validatePlan, validateRecord, validateCatalog, priorAliasDigest, assertNewRevision, selectRun, chooseArtifacts } from './lib/releases.mjs';
import { assessRelease as assessImageRelease, readJSON } from './lib/image-changes.mjs';

export async function readText(github, repo, path, ref) {
  const { data } = await github.rest.repos.getContent({ ...repo, path, ref });
  if (Array.isArray(data) || data.encoding !== 'base64' || data.size > 2000000) throw new Error('Expected bounded text file: ' + path);
  return Buffer.from(data.content, 'base64').toString('utf8');
}
export async function readCatalog(github, repo, ref) {
  const { data } = await github.rest.git.getTree({ ...repo, tree_sha: ref, recursive: '1' });
  if (data.truncated) throw new Error('Cannot validate a truncated Git tree.');
  const paths = data.tree.filter(e => /^releases\/records\/v\d+\.\d+\.\d+-r\d+\.json$/.test(e.path) && e.type === 'blob').map(e => e.path);
  const records = await Promise.all(paths.map(async path => {
    const record = JSON.parse(await readText(github, repo, path, ref));
    if (path !== 'releases/records/' + record.plan?.tag + '.json') throw new Error('Record path mismatch.');
    return record;
  }));
  return validateCatalog(records);
}
export async function readHistory(github, repo, ref, records) {
  const tags = [...new Set(records.flatMap(r => r.plan.images.filter(i => !i.changes).map(i => i.tag)))];
  return Object.fromEntries(await Promise.all(tags.map(async tag => [tag, await readJSON(github, repo, 'releases/history/' + tag + '.json', ref)])));
}
export async function readAsset(github, repo, release, name) {
  const assets = await github.paginate(github.rest.repos.listReleaseAssets, { ...repo, release_id: release.id, per_page: 100 });
  const matching = assets.filter(a => a.name === name);
  if (matching.length > 1) throw new Error('Ambiguous release asset: ' + name);
  if (!matching.length) return null;
  const asset = matching[0];
  if (asset.size > 2000000) throw new Error('Release metadata asset exceeds limit.');
  const { data } = await github.rest.repos.getReleaseAsset({ ...repo, asset_id: asset.id, headers: { accept: 'application/octet-stream' } });
  const text = typeof data === 'string' ? data : Buffer.from(data).toString('utf8');
  return JSON.parse(text);
}
export async function putImmutableAsset(github, repo, release, name, value) {
  const existing = await readAsset(github, repo, release, name);
  if (existing) {
    if (!equal(existing, value)) throw new Error('Release metadata is already frozen with different contents: ' + name);
    return;
  }
  await github.rest.repos.uploadReleaseAsset({ ...repo, release_id: release.id, name,
    data: Buffer.from(json(value)), headers: { 'content-type': 'application/json' } });
}
export async function assertTagSource(github, repo, tag, sourceCommit) {
  const { data } = await github.rest.repos.getCommit({ ...repo, ref: 'refs/tags/' + tag });
  if (data.sha !== sourceCommit) throw new Error('Release tag moved after validation. Use a new revision.');
}
export function completionAsset(record) {
  validateRecord(record);
  return { schemaVersion: 1, tag: record.plan.tag, recordSha256: hash(json(record)),
    catalog: 'https://github.com/' + repository + '/blob/main/releases/README.md' };
}

export async function prepareRelease({ github, context, core, tag, preview = false,
  trustedToolsCommit,
  assessRelease = assessImageRelease,
  pause = ms => new Promise(resolve => setTimeout(resolve, ms)), maxPolls = 100 }) {
  const repo = context.repo;
  if (repo.owner + '/' + repo.repo !== repository) throw new Error('Unexpected publishing repository.');
  const { data: metadata } = await github.rest.repos.get(repo);
  const main = metadata.default_branch;
  if (context.eventName === 'workflow_dispatch' && context.ref !== 'refs/heads/' + main) throw new Error('Manual release/recovery must run from main.');
  const { data: mainRef } = await github.rest.git.getRef({ ...repo, ref: 'heads/' + main });
  const toolsCommit = mainRef.object.sha;
  if (trustedToolsCommit && toolsCommit !== trustedToolsCommit) throw new Error('Main advanced before preparation; rerun with the current trusted workflow code.');
  const version = parseRelease(tag);
  let release;
  let sourceCommit;
  if (preview) {
    if (context.eventName !== 'workflow_dispatch') throw new Error('Preview is manual only.');
    release = { id: 0, tag_name: tag };
    sourceCommit = toolsCommit;
  } else {
    ({ data: release } = await github.rest.repos.getReleaseByTag({ ...repo, tag }));
    if (release.draft || release.prerelease) { core.info('Draft/prerelease: no publication.'); return { skipped: true }; }
    if (context.payload.release && context.payload.release.id !== release.id) throw new Error('Release event identity mismatch.');
    const { data: commit } = await github.rest.repos.getCommit({ ...repo, ref: 'refs/tags/' + tag });
    sourceCommit = commit.sha;
    const { data: comparison } = await github.rest.repos.compareCommits({ ...repo, base: sourceCommit, head: toolsCommit });
    if (comparison.merge_base_commit.sha !== sourceCommit) throw new Error('Release commit is not in main history.');
    if (context.eventName === 'release') {
      // Stable publication can emit both published and released. A failed first event
      // must not cause its duplicate to retry unchanged scans/uploads automatically.
      const events = await github.paginate(github.rest.actions.listWorkflowRuns, { ...repo, workflow_id: 'release.yml',
        event: 'release', head_sha: sourceCommit, per_page: 100 });
      if (events.some(r => r.id < context.runId && r.conclusion !== 'skipped' && r.head_branch === tag && r.head_sha === sourceCommit &&
          r.created_at >= release.created_at)) {
        core.info('Duplicate event for this Release; use manual recovery for a failed first attempt.');
        return { skipped: true };
      }
    }
  }
  const lockText = await readText(github, repo, 'images.lock.json', sourceCommit);
  const imageLock = JSON.parse(lockText);
  if (imageLock.keycloakVersion !== version.keycloakVersion || imageLock.platform !== 'linux/amd64') throw new Error('Release version/platform does not match the image lock.');
  const records = await readCatalog(github, repo, toolsCommit);
  const existingRecord = records.find(r => r.plan.tag === tag);
  if (existingRecord) {
    if (existingRecord.plan.releaseId !== release.id || existingRecord.plan.sourceCommit !== sourceCommit) throw new Error('Recorded release identity conflict.');
    const completed = await readAsset(github, repo, release, 'publication-complete.json');
    if (completed) {
      if (!equal(completed, completionAsset(existingRecord))) throw new Error('Completion attachment conflicts with the recorded publication.');
      core.info('Release already published, recorded and complete; duplicate event skipped.');
      return { complete: true, tag };
    }
    core.info('Catalog already merged; recovering the missing completion attachment only.');
    return { tag, toolsCommit, sourceCommit, releaseId: release.id, recordOnly: true, plan: existingRecord.plan, record: existingRecord };
  }
  const config = validateAliases(JSON.parse(await readText(github, repo, 'releases/aliases.json', toolsCommit)));
  const aliases = config.aliases.filter(a => a.keycloakVersion === version.keycloakVersion);
  const previousAliases = Object.fromEntries(aliases.map(a => [a.tag, priorAliasDigest(records, a.tag)]));
  const frozen = preview ? null : await readAsset(github, repo, release, 'publication-plan.json');
  if (!preview && !frozen) assertNewRevision(records, tag);
  if (frozen) {
    validatePlan(frozen);
    if (frozen.releaseId !== release.id || frozen.tag !== tag || frozen.sourceCommit !== sourceCommit || frozen.lockSha256 !== hash(lockText)) throw new Error('Frozen release identity conflicts with current tag/lock.');
    const published = await readAsset(github, repo, release, 'publication-record.json');
    if (published) {
      validateRecord(published);
      if (!equal(published.plan, frozen)) throw new Error('Publication result conflicts with frozen plan.');
      core.info('Images already published; recovering catalog only.');
      return { tag, toolsCommit, sourceCommit, releaseId: release.id, recordOnly: true, plan: frozen, record: published };
    }
  }
  const intent = frozen ? { images: frozen.images, profiles: frozen.images.map(i => i.profile) }
    : await assessRelease({ github, repo, sourceCommit, records });
  if (!intent.profiles.length) {
    core.info('No image fix/feature since the published input fingerprints; skipping builds, scans and publication.');
    return { skipped: true, preview, tag, toolsCommit, sourceCommit, reason: 'No changed image inputs or new profile feature/fix.' };
  }
  const activeAliases = (frozen?.aliases ?? aliases).filter(a => intent.profiles.includes(a.profile));
  let run;
  let dispatched = false;
  let dispatchedAfterId = 0;
  for (let n = 0; n < maxPolls; n++) {
    const runs = frozen ? [] : await github.paginate(github.rest.actions.listWorkflowRuns, { ...repo, workflow_id: 'ci.yml', head_sha: sourceCommit, per_page: 100 });
    run = frozen ? (await github.rest.actions.getWorkflowRunAttempt({ ...repo, run_id: frozen.sourceRun.id, attempt_number: frozen.sourceRun.attempt })).data
      : selectRun(runs, { sha: sourceCommit, main, tag });
    if (dispatched && run && run.id <= dispatchedAfterId) run = null;
    if (run) {
      // Even a frozen run must remain a trusted exact-source CI run.
      if (!selectRun([run], { sha: sourceCommit, main, tag }) || run.path !== '.github/workflows/ci.yml') throw new Error('Untrusted source CI run.');
      if (frozen && run.run_attempt !== frozen.sourceRun.attempt) throw new Error('Frozen source CI was rerun; original artifact identity must be retained.');
      if (run.status === 'completed') {
        if (run.conclusion !== 'success') throw new Error('Latest source CI failed/cancelled; investigate it before release recovery.');
        const artifacts = await github.paginate(github.rest.actions.listWorkflowRunArtifacts, { ...repo, run_id: run.id, per_page: 100 });
        let selected;
        try { selected = chooseArtifacts(frozen ? artifacts.filter(a => frozen.images.some(i => i.artifactId === a.id)) : artifacts, sourceCommit, intent.profiles); }
        catch (error) {
          if (frozen) throw new Error('Frozen OCI artifacts are unavailable. Restore the original artifacts or use a new revision.');
          if (dispatched || preview) throw error;
        }
        if (selected) {
          if (frozen && selected.some(i => !frozen.images.some(f => f.profile === i.profile && f.artifactId === i.artifactId))) throw new Error('Frozen artifact IDs changed.');
          return { ...version, preview, toolsCommit, sourceCommit, releaseId: release.id,
            imageLock, lockSha256: hash(lockText), aliases: activeAliases,
            previousAliases: Object.fromEntries(activeAliases.map(a => [a.tag, (frozen?.previousAliases ?? previousAliases)[a.tag]])),
            sourceRun: { id: run.id, attempt: run.run_attempt }, images: selected.map(i => ({ ...intent.images.find(n => n.profile === i.profile), ...i })), frozen };
        }
        dispatchedAfterId = run.id;
        run = null;
      }
    } else if (frozen) throw new Error('Frozen source CI run cannot be found.');
    if (!run && !dispatched) {
      if (preview) throw new Error('Preview requires an existing successful main CI with OCI artifacts.');
      core.info('Dispatching read-only CI for release tag ' + tag);
      await github.rest.actions.createWorkflowDispatch({ ...repo, workflow_id: 'ci.yml', ref: tag });
      dispatched = true;
    }
    if (n === 0) core.info('Waiting for exact-commit CI; no old successful run fallback.');
    await pause(20000);
  }
  throw new Error('Timed out waiting for release CI; recover this release after investigating its run.');
}

export function makeFrozenPlan(prepared, scans) {
  const images = prepared.images.map(image => {
    const scan = scans.find(s => s.profile === image.profile);
    if (!scan || scan.sourceCommit !== prepared.sourceCommit || scan.sourceRunId !== prepared.sourceRun.id ||
        scan.artifactId !== image.artifactId || scan.lockSha256 !== prepared.lockSha256) throw new Error('Scan evidence does not match source artifact.');
    return { ...image, tag: canonicalTag(prepared.tag, image.profile), digest: scan.digest, archiveSha256: scan.archiveSha256 };
  });
  const plan = { schemaVersion: prepared.frozen?.schemaVersion ?? 2, registry, tag: prepared.tag, releaseId: prepared.releaseId,
    keycloakVersion: prepared.keycloakVersion, revision: prepared.revision, sourceCommit: prepared.sourceCommit,
    toolsCommit: prepared.frozen?.toolsCommit ?? prepared.toolsCommit, sourceRun: prepared.sourceRun,
    lockSha256: prepared.lockSha256, imageLock: prepared.imageLock, aliases: prepared.aliases,
    previousAliases: prepared.previousAliases, images };
  validatePlan(plan);
  if (prepared.frozen && !equal(prepared.frozen, plan)) throw new Error('Freshly inspected artifacts differ from the frozen publication plan.');
  return plan;
}
export async function freezeRelease({ github, context, prepared, scans }) {
  const plan = makeFrozenPlan(prepared, scans);
  const repo = context.repo;
  await assertTagSource(github, repo, plan.tag, plan.sourceCommit);
  const { data: release } = await github.rest.repos.getReleaseByTag({ ...repo, tag: plan.tag });
  if (release.id !== plan.releaseId || release.draft || release.prerelease) throw new Error('Release state changed before freeze.');
  await putImmutableAsset(github, repo, release, 'publication-plan.json', plan);
  return plan;
}
