import { registry, repository, json, hash, equal, validateRecord, validateCatalog, renderCatalog } from './lib/releases.mjs';
import { readText, readCatalog, readHistory, readAsset, putImmutableAsset, assertTagSource, completionAsset } from './quay-release.mjs';
import { dispatchMissingChecks, configureAutoMerge } from './upstream-update.mjs';
import policy from './issue-policy.cjs';
import { validateChanges, validateFragment } from './lib/image-changes.mjs';

const marker = '<!-- quay-catalog:v1 -->';
const actionsBot = 'MDM6Qm90NDE4OTgyODI=';
const codesmithBot = 'BOT_kgDOCWWZcg';
const legacyCatalogTools = 'a6bca23dd39652b70c38db10953a2e2a18ac3360';
const pathFor = record => 'releases/records/' + record.plan.tag + '.json';
const filesHash = files => hash(json(Object.entries(files).sort(([a], [b]) => a.localeCompare(b))));
function bodyFor(issue, record, sha, files) {
  const body = marker + '\n<!-- catalog-release:' + record.plan.releaseId + ' -->\n<!-- catalog-head:' + sha + ' -->\n<!-- catalog-files:' + filesHash(files) + ' -->\n' +
    '## Linked issues\n\nCloses #' + issue + '\n\n## Problem and resulting behavior\n\n' +
    'Record the successfully published Quay release `' + record.plan.tag + '` as JSON and regenerate the human-readable catalog.\n\n' +
    '## Validation\n\nAll selected profiles passed fresh Trivy gates and digest-preserving publication with nonempty per-tag changes. Required CI and Issue policy must pass before native auto-merge; catalog-only CI skips image builds.\n\n' +
    '## Security and compatibility\n\nOnly the generated release record and catalog Markdown may change. Human edits disable automatic maintenance/merge. No alias configuration, image inputs, code or workflow changes are permitted.\n';
  return body + '<!-- catalog-body:' + hash(body) + ' -->\n';
}
function issueBody(record) {
  return '### Maintenance goal\nRecord published Quay release ' + record.plan.tag + ' in the Git catalog.\n\n' +
    '### Scope\nAdd its immutable JSON publication record and regenerate releases/README.md.\n\n' +
    '### Security and compatibility\nThe record matches the frozen Release attachment, verified images and aliases. Only generated catalog data may auto-merge; preserve protected checks and human edits.\n\n' +
    '### Acceptance criteria\n- [ ] JSON matches the published record\n- [ ] Generated Markdown is consistent\n- [ ] Required checks pass before merge\n\n' +
    '### Validation plan\nCompare the record with the Release attachment, validate all catalog records and alias history, regenerate Markdown and run both required checks on the bot branch.\n';
}

export async function checkRecordChanges({ github, context, pr }) {
  const repo = context.repo;
  const changes = await github.paginate(github.rest.pulls.listFiles, { ...repo, pull_number: pr.number, per_page: 100 });
  for (const change of changes.filter(c => /^changes\/.+\.json$/.test(c.filename))) {
    if (change.previous_filename || (change.status !== 'added' && !(change.filename === 'changes/upstream.json' && change.status === 'modified'))) throw new Error('Reviewed change fragments are append-only; only managed upstream notes may refresh.');
    const fragment = validateFragment(JSON.parse(await readText(github, repo, change.filename, pr.head.sha)), { allowEmpty: change.filename === 'changes/upstream.json' });
    const linked = policy.issueNumbers(pr.body);
    if (fragment.changes.some(c => c.issues.some(n => !linked.includes(n)))) throw new Error('Change fragment Issues must be linked by standalone PR closing references.');
  }
  for (const change of changes.filter(c => /^releases\/history\/.+\.json$/.test(c.filename))) {
    if (change.status !== 'added' || change.previous_filename) throw new Error('Published historical notes are append-only.');
    const note = JSON.parse(await readText(github, repo, change.filename, pr.head.sha));
    const records = await readCatalog(github, repo, pr.head.sha);
    const record = records.find(r => r.plan.images.some(i => i.tag === note.tag && i.profile === note.profile && !i.changes));
    if (!record || note.schemaVersion !== 1 || change.filename !== 'releases/history/' + note.tag + '.json') throw new Error('Historical notes must supplement a published legacy tag.');
    validateChanges(note.changes);
    for (const issue_number of new Set(note.changes.flatMap(c => c.issues))) {
      const { data } = await github.rest.issues.get({ ...repo, issue_number });
      policy.validateIssue({ ...data, state: 'open' });
    }
  }
  for (const change of changes.filter(c => c.filename.startsWith('releases/records/') && c.filename.endsWith('.json'))) {
    if (change.status !== 'added' || change.previous_filename) throw new Error('Published JSON records are append-only; modifications/deletions/renames are forbidden.');
    const record = validateRecord(JSON.parse(await readText(github, repo, change.filename, pr.head.sha)));
    if (change.filename !== pathFor(record)) throw new Error('Release record path mismatch.');
    const { data: release } = await github.rest.repos.getReleaseByTag({ ...repo, tag: record.plan.tag });
    if (!equal(await readAsset(github, repo, release, 'publication-record.json'), record)) throw new Error('New release record must match its published Release attachment.');
  }
}

export async function canonicalCatalogBody({ github, context, pr }) {
  const body = pr.body ?? '';
  if (!body.includes('<!-- codesmith:footer -->')) return body;
  const parts = /^(.*<!-- catalog-body:[a-f0-9]{64} -->\n)\n(<!-- codesmith:footer -->\n[\s\S]*\n<!-- \/codesmith:footer -->)\n?$/s.exec(body);
  if (!parts || parts[2].length > 8192 || (body.match(/<!-- codesmith:footer -->/g) ?? []).length !== 1 ||
      (body.match(/<!-- \/codesmith:footer -->/g) ?? []).length !== 1 || parts[2].includes('<!-- catalog-') ||
      !parts[2].startsWith('<!-- codesmith:footer -->\n---\n<a href="https://app.blacksmith.sh/rambow-cloud/codesmith/keycloak/pr/' + pr.number + '?')) {
    throw new Error('Unexpected catalog footer; refusing automatic maintenance/merge.');
  }
  const { repository: result } = await github.graphql(`query($owner:String!,$name:String!,$number:Int!){
    repository(owner:$owner,name:$name){pullRequest(number:$number){body headRefOid
      editor{__typename ... on Bot{id}}
      userContentEdits(first:100){totalCount pageInfo{hasNextPage} nodes{editor{__typename ... on Bot{id}}}}
    }}}`, { owner: context.repo.owner, name: context.repo.repo, number: pr.number });
  const current = result?.pullRequest;
  const edits = current?.userContentEdits;
  if (current?.body !== body || current?.headRefOid !== pr.head.sha || current?.editor?.__typename !== 'Bot' ||
      current.editor.id !== codesmithBot || !edits?.totalCount || edits.totalCount !== edits.nodes?.length ||
      edits.pageInfo?.hasNextPage !== false || edits.nodes.some(e => e?.editor?.__typename !== 'Bot' ||
        ![actionsBot, codesmithBot].includes(e.editor.id))) {
    throw new Error('Catalog footer edit history is not exclusively attributable to the pinned automation bots.');
  }
  return parts[1];
}

export async function assertCatalogOwned({ github, context, pr }) {
  const repo = context.repo;
  if (pr.user?.login !== 'github-actions[bot]' || pr.head.repo?.full_name !== repository ||
      !/^chore\/[1-9]\d*-record-release-v\d+\.\d+\.\d+-r\d+$/.test(pr.head.ref) || !pr.body?.startsWith(marker)) throw new Error('Catalog PR is not bot-owned.');
  const body = await canonicalCatalogBody({ github, context, pr });
  const expectedHead = body.match(/<!-- catalog-head:([a-f0-9]{40}) -->/)?.[1];
  const expectedBody = body.match(/<!-- catalog-body:([a-f0-9]{64}) -->\n?$/)?.[1];
  const clean = body.replace(/<!-- catalog-body:[a-f0-9]{64} -->\n?$/, '');
  if (expectedHead !== pr.head.sha || !expectedBody || hash(clean) !== expectedBody) throw new Error('Catalog PR was edited; refusing automatic maintenance/merge.');
  const { data: commit } = await github.rest.repos.getCommit({ ...repo, ref: pr.head.sha });
  if (commit.author?.login !== 'github-actions[bot]') throw new Error('Catalog branch has human/unknown commits.');
  const changes = await github.paginate(github.rest.pulls.listFiles, { ...repo, pull_number: pr.number, per_page: 100 });
  const recordPaths = changes.filter(f => /^releases\/records\/v\d+\.\d+\.\d+-r\d+\.json$/.test(f.filename));
  if (changes.length !== 2 || recordPaths.length !== 1 || recordPaths[0].status !== 'added' ||
      changes.some(f => f.status === 'removed' || f.previous_filename) || !changes.some(f => f.filename === 'releases/README.md')) throw new Error('Catalog PR changes files outside the generated allowlist.');
  const path = recordPaths[0].filename;
  const files = { [path]: await readText(github, repo, path, pr.head.sha),
    'releases/README.md': await readText(github, repo, 'releases/README.md', pr.head.sha) };
  if (filesHash(files) !== pr.body.match(/<!-- catalog-files:([a-f0-9]{64}) -->/)?.[1]) throw new Error('Generated catalog files were edited.');
  const record = validateRecord(JSON.parse(files[path]));
  if (path !== pathFor(record) || String(record.plan.releaseId) !== pr.body.match(/<!-- catalog-release:(\d+) -->/)?.[1]) throw new Error('Catalog release identity mismatch.');
  const { data: release } = await github.rest.repos.getReleaseByTag({ ...repo, tag: record.plan.tag });
  const published = await readAsset(github, repo, release, 'publication-record.json');
  if (!equal(published, record)) throw new Error('Catalog record differs from the published Release attachment.');
  const records = await readCatalog(github, repo, pr.head.sha);
  const rendered = renderCatalog(records, await readHistory(github, repo, pr.head.sha, records));
  // Recover the untouched first-release PR generated by the original renderer.
  // Its exact hashed extra EOF is accepted only for ownership checks; current CI
  // still requires regeneration with the corrected single-newline renderer.
  if (rendered !== files['releases/README.md'] && !(record.plan.toolsCommit === legacyCatalogTools &&
      rendered + '\n' === files['releases/README.md'])) throw new Error('Catalog Markdown is not generated from its JSON.');
  return { record, files, commit };
}

// Runs inside the existing required Issue policy, using trusted base/default-branch code.
export async function checkCatalogPullRequest({ github, context, pr }) {
  try { return await assertCatalogOwned({ github, context, pr }); }
  catch (error) {
    if (pr.auto_merge) await configureAutoMerge(github, context.repo, pr, false, () => {});
    throw error;
  }
}

export async function ensureCatalogPR({ github, context, core, record }) {
  validateRecord(record);
  const repo = context.repo;
  const { data: metadata } = await github.rest.repos.get(repo);
  const main = metadata.default_branch;
  const { data: ref } = await github.rest.git.getRef({ ...repo, ref: 'heads/' + main });
  const baseSha = ref.object.sha;
  const records = await readCatalog(github, repo, baseSha);
  const existing = records.find(r => r.plan.tag === record.plan.tag);
  if (existing) {
    if (!equal(existing, record)) throw new Error('Git catalog contains a conflicting release record.');
    return { merged: true, baseSha };
  }
  const next = validateCatalog([...records, record]);
  const files = { [pathFor(record)]: json(record), 'releases/README.md': renderCatalog(next, await readHistory(github, repo, baseSha, next)) };
  const pulls = await github.paginate(github.rest.pulls.list, { ...repo, state: 'open', base: main, per_page: 100 });
  const candidates = pulls.filter(p => p.body?.includes('<!-- catalog-release:' + record.plan.releaseId + ' -->'));
  if (candidates.length > 1) throw new Error('Multiple catalog PRs refer to the same release.');
  let pr = candidates[0];
  let issue;
  let owned;
  if (pr) {
    owned = await assertCatalogOwned({ github, context, pr });
    if (!equal(owned.record, record)) throw new Error('Pending catalog PR contains a different publication record.');
    [issue] = policy.issueNumbers(pr.body);
    const { data: linked } = await github.rest.issues.get({ ...repo, issue_number: issue });
    policy.validateIssue(linked);
    if (policy.issueNumbers(pr.body).length !== 1 || pr.head.ref !== 'chore/' + issue + '-record-release-' + record.plan.tag) throw new Error('Unexpected catalog Issue/branch.');
    if (equal(owned.files, files) && owned.commit.parents.some(p => p.sha === baseSha)) {
      await dispatchMissingChecks(github, repo, pr, core.info);
      await configureAutoMerge(github, repo, pr, true, core.info);
      return { number: pr.number, url: pr.html_url, baseSha };
    }
    await configureAutoMerge(github, repo, pr, false, core.info);
  } else {
    const { data } = await github.rest.issues.create({ ...repo, title: '[Maintenance]: Record Quay release ' + record.plan.tag,
      body: issueBody(record), labels: ['maintenance'] });
    issue = data.number;
  }
  const branch = 'chore/' + issue + '-record-release-' + record.plan.tag;
  const { data: baseCommit } = await github.rest.git.getCommit({ ...repo, commit_sha: baseSha });
  const { data: tree } = await github.rest.git.createTree({ ...repo, base_tree: baseCommit.tree.sha,
    tree: Object.entries(files).map(([path, content]) => ({ path, content, mode: '100644', type: 'blob' })) });
  const { data: commit } = await github.rest.git.createCommit({ ...repo, message: 'chore: record Quay release ' + record.plan.tag + ' (#' + issue + ')',
    tree: tree.sha, parents: [...new Set([pr?.head.sha, baseSha].filter(Boolean))] });
  const body = bodyFor(issue, record, commit.sha, files);
  if (pr) {
    const { data: latest } = await github.rest.pulls.get({ ...repo, pull_number: pr.number });
    if (latest.head.sha !== pr.head.sha || latest.body !== pr.body || latest.state !== 'open') throw new Error('Catalog PR changed concurrently.');
    await github.rest.git.updateRef({ ...repo, ref: 'heads/' + branch, sha: commit.sha, force: false });
    await github.rest.pulls.update({ ...repo, pull_number: pr.number, body });
    pr = { ...pr, head: { ...pr.head, sha: commit.sha }, body };
  } else {
    await github.rest.git.createRef({ ...repo, ref: 'refs/heads/' + branch, sha: commit.sha });
    ({ data: pr } = await github.rest.pulls.create({ ...repo, base: main, head: branch,
      title: 'chore: record Quay release ' + record.plan.tag, body }));
  }
  // Validate the real diff and Release attachment before enabling any merge.
  await assertCatalogOwned({ github, context, pr });
  await dispatchMissingChecks(github, repo, pr, core.info);
  await configureAutoMerge(github, repo, pr, true, core.info);
  core.info('Catalog PR: ' + pr.html_url);
  return { number: pr.number, url: pr.html_url, baseSha };
}

export function selectCatalogCI(runs, pr) {
  return runs.filter(r => r.event === 'workflow_dispatch' && r.path === '.github/workflows/ci.yml' &&
    r.head_sha === pr.head.sha && r.head_branch === pr.head.ref && r.repository?.full_name === repository &&
    r.head_repository?.full_name === repository).sort((a, b) => b.id - a.id)[0];
}

export async function recordRelease({ github, context, core, record,
  pause = ms => new Promise(resolve => setTimeout(resolve, ms)), maxPolls = 100 }) {
  validateRecord(record);
  const repo = context.repo;
  await assertTagSource(github, repo, record.plan.tag, record.plan.sourceCommit);
  const { data: release } = await github.rest.repos.getReleaseByTag({ ...repo, tag: record.plan.tag });
  const frozen = await readAsset(github, repo, release, 'publication-plan.json');
  if (!equal(frozen, record.plan)) throw new Error('Publication record does not match the frozen Release plan.');
  await putImmutableAsset(github, repo, release, 'publication-record.json', record);
  const pending = await ensureCatalogPR({ github, context, core, record });
  if (!pending.merged) {
    for (let n = 0; n < maxPolls; n++) {
      const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: pending.number });
      if (pr.merged_at) break;
      if (pr.state !== 'open') throw new Error('Catalog PR was closed without merging; preserve its work before recovery.');
      await assertCatalogOwned({ github, context, pr });
      if (!pr.auto_merge) throw new Error('Catalog auto-merge was disabled; inspect the PR before recovery.');
      const runs = await github.paginate(github.rest.actions.listWorkflowRuns, { ...repo, workflow_id: 'ci.yml', head_sha: pr.head.sha, per_page: 100 });
      const latest = selectCatalogCI(runs, pr);
      if (latest?.status === 'completed' && latest.conclusion !== 'success') throw new Error('Catalog CI failed; published images remain intact. Inspect the PR before recovery.');
      const { data: head } = await github.rest.git.getRef({ ...repo, ref: 'heads/' + pr.base.ref });
      if (head.object.sha !== pending.baseSha) {
        try {
          const merged = JSON.parse(await readText(github, repo, pathFor(record), head.object.sha));
          if (equal(merged, record)) break;
        } catch (error) { if (error.status !== 404) throw error; }
        throw new Error('Main advanced while catalog was pending. Recover to refresh the guarded catalog PR.');
      }
      if (n === maxPolls - 1) throw new Error('Catalog is not merged yet; publication remains pending record completion.');
      await pause(20000);
    }
  }
  const { data: main } = await github.rest.repos.get(repo);
  const text = await readText(github, repo, pathFor(record), main.default_branch);
  if (!equal(JSON.parse(text), record)) throw new Error('Catalog merge did not retain the expected record.');
  await putImmutableAsset(github, repo, release, 'publication-complete.json', completionAsset(record));
  core.info('Publication and catalog merge complete for ' + registry + ' ' + record.plan.tag);
  return pending;
}

export { bodyFor as catalogBody, filesHash as catalogFilesHash, issueBody as catalogIssueBody };
