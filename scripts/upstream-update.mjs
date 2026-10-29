import { resolveImageDigest } from './lib/oci.mjs';
import { marker, managedPaths, chooseVersion, inspectCompatibility, candidateFiles, filesHash, issueBody, pullBody, assertBotOwned, autoMergeEligible, validateUpdaterIdentity, sameUpdater } from './lib/upstream.mjs';
import policy from './issue-policy.cjs';

// All writes use a repository-scoped installation token. Never execute update PR code.
export async function runUpstreamUpdate({ github, context, core, dryRun = false, identity,
  resolve = resolveImageDigest, inspect = inspectCompatibility }) {
  const repo = context.repo;
  const { data: metadata } = await github.rest.repos.get(repo);
  const base = metadata.default_branch;
  if (context.ref !== 'refs/heads/' + base) throw new Error('Run the updater only from the default branch.');
  if (!dryRun) validateUpdaterIdentity(identity);
  const { data: baseRef } = await github.rest.git.getRef({ ...repo, ref: 'heads/' + base });
  const baseSha = baseRef.object.sha;
  const content = async (path, ref) => {
    const { data } = await github.rest.repos.getContent({ ...repo, path, ref });
    if (Array.isArray(data) || data.encoding !== 'base64' || typeof data.content !== 'string') throw new Error('Expected a small UTF-8 file: ' + path);
    return Buffer.from(data.content, 'base64').toString('utf8');
  };
  const readManaged = async ref => Object.fromEntries(await Promise.all(managedPaths.map(async path => [path, await content(path, ref)])));
  const currentFiles = await readManaged(baseSha);
  const current = JSON.parse(currentFiles['images.lock.json']);
  const baseline = JSON.parse(await content('config/upstream-compatibility.json', baseSha));
  const { data: release } = await github.rest.repos.getLatestRelease({ owner: 'keycloak', repo: 'keycloak' });
  const version = chooseVersion(current.keycloakVersion, release);
  const refs = { keycloak: 'quay.io/keycloak/keycloak:' + version,
    runtime: current.runtime.split('@')[0], builder: current.builder.split('@')[0] };
  const resolved = Object.fromEntries(await Promise.all(Object.entries(refs).map(async ([key, ref]) => [key, await resolve(ref)])));
  const next = { ...current, keycloakVersion: version, ...resolved };
  const { warnings } = await inspect(version, current.javaVersion, baseline);
  let files = candidateFiles(currentFiles, next, warnings);
  const eligible = autoMergeEligible(current, next, warnings);
  let changed = managedPaths.filter(path => files[path] !== currentFiles[path]);
  const report = message => core.info(message);
  for (const warning of warnings) core.warning(warning);
  if (!changed.length) {
    report('Upstream image locks are current; no writes or builds.');
    if (warnings.length) throw new Error('Reviewed compatibility no longer matches; see warnings.');
    return { changed: false };
  }
  report('Detected upstream changes: ' + changed.join(', '));
  if (dryRun) {
    report('Dry run: no Issues, branches, PRs or workflow dispatches were created.');
    return { changed: true, dryRun: true, warnings };
  }
  const pulls = await github.paginate(github.rest.pulls.list, { ...repo, state: 'open', base, per_page: 100 });
  const candidates = pulls.filter(pr => pr.head.repo?.full_name === metadata.full_name && /^chore\/\d+-upstream-images$/.test(pr.head.ref));
  if (candidates.length > 1) throw new Error('Multiple upstream update PRs exist; resolve them before refreshing.');
  let pr = candidates[0];
  let issue;
  if (pr) {
    if (!sameUpdater(pr.user, identity)) {
      throw new Error('Existing upstream PR is not owned by the configured App. Preserve its branch and evidence, then close it after review before App migration; no automatic overwrite or approval.');
    }
    if (!pr.body?.includes(marker)) throw new Error('An upstream update branch is not managed by this updater.');
    const [{ data: commit }, branchFiles] = await Promise.all([
      github.rest.repos.getCommit({ ...repo, ref: pr.head.sha }), readManaged(pr.head.sha),
    ]);
    const body = await canonicalUpstreamBody({ github, context, pr, identity });
    assertBotOwned({ ...pr, body }, commit, branchFiles, identity);
    [issue] = policy.issueNumbers(pr.body);
    if (policy.issueNumbers(pr.body).length !== 1 || pr.head.ref !== 'chore/' + issue + '-upstream-images') throw new Error('Unexpected update Issue/branch association.');
    const { data: linked } = await github.rest.issues.get({ ...repo, issue_number: issue });
    policy.validateIssue(linked);
    if (!linked.title.startsWith('[Maintenance]:')) throw new Error('Expected a maintenance Issue.');
    files = candidateFiles(currentFiles, next, warnings, issue);
    changed = managedPaths.filter(path => files[path] !== currentFiles[path]);
    if (filesHash(branchFiles) === filesHash(files) && commit.parents.some(parent => parent.sha === baseSha)) {
      report('Existing PR already contains this candidate: ' + pr.html_url);
      report('Reusing native PR checks; no duplicate dispatch or automatic retry.');
      await configureAutoMerge(github, repo, pr, eligible, report);
      return { changed: true, pullRequest: pr.html_url, refreshed: false };
    }
  } else {
    const { data: created } = await github.rest.issues.create({ ...repo,
      title: '[Maintenance]: Refresh upstream Keycloak and Java image inputs', body: issueBody(), labels: ['maintenance'] });
    issue = created.number;
    files = candidateFiles(currentFiles, next, warnings, issue);
    changed = managedPaths.filter(path => files[path] !== currentFiles[path]);
  }
  const branch = pr?.head.ref ?? 'chore/' + issue + '-upstream-images';
  const { data: baseCommit } = await github.rest.git.getCommit({ ...repo, commit_sha: baseSha });
  const { data: tree } = await github.rest.git.createTree({ ...repo, base_tree: baseCommit.tree.sha,
    tree: changed.map(path => ({ path, mode: '100644', type: 'blob', content: files[path] })) });
  const { data: commit } = await github.rest.git.createCommit({ ...repo,
    message: 'chore: refresh upstream images (#' + issue + ')', tree: tree.sha,
    parents: [...new Set([pr?.head.sha, baseSha].filter(Boolean))] });
  const body = pullBody(issue, current, next, files, warnings, commit.sha);
  if (pr) {
    // A concurrent push makes this non-fast-forward and is rejected; never force-push.
    const { data: latest } = await github.rest.pulls.get({ ...repo, pull_number: pr.number });
    if (latest.head.sha !== pr.head.sha || latest.body !== pr.body || latest.state !== 'open') throw new Error('PR changed during refresh; refusing to overwrite it.');
    await configureAutoMerge(github, repo, pr, false, report);
    await github.rest.git.updateRef({ ...repo, ref: 'heads/' + branch, sha: commit.sha, force: false });
    await github.rest.pulls.update({ ...repo, pull_number: pr.number, body });
    pr = { ...pr, head: { ...pr.head, sha: commit.sha } };
  } else {
    await github.rest.git.createRef({ ...repo, ref: 'refs/heads/' + branch, sha: commit.sha });
    const { data } = await github.rest.pulls.create({ ...repo, head: branch, base,
      title: 'chore: refresh upstream Keycloak and Java images', body, draft: !eligible });
    pr = data;
  }
  report('Update PR: ' + pr.html_url);
  report('GitHub App PR events trigger required checks; no explicit CI dispatch.');
  await configureAutoMerge(github, repo, pr, eligible, report);
  return { changed: true, pullRequest: pr.html_url, refreshed: true, warnings };
}

// This is the same bounded automation exception used by the release catalog.
// Never strip arbitrary trailing text, or trust a footer based on its text alone.
export async function canonicalUpstreamBody({ github, context, pr, identity }) {
  validateUpdaterIdentity(identity);
  const body = pr.body ?? '';
  if (!body.includes('<!-- codesmith:footer -->')) return body;
  const parts = /^(.*<!-- generated-body-sha256:[a-f0-9]{64} -->\n)\n(<!-- codesmith:footer -->\n[\s\S]*\n<!-- \/codesmith:footer -->)\n?$/s.exec(body);
  if (!parts || parts[2].length > 8192 || (body.match(/<!-- codesmith:footer -->/g) ?? []).length !== 1 ||
      (body.match(/<!-- \/codesmith:footer -->/g) ?? []).length !== 1 || parts[2].includes('<!-- generated-') ||
      parts[2].includes(marker) || !parts[2].startsWith('<!-- codesmith:footer -->\n---\n<a href="https://app.blacksmith.sh/' +
        context.repo.owner + '/codesmith/' + context.repo.repo + '/pr/' + pr.number + '?')) {
    throw new Error('Unexpected upstream PR footer; refusing automatic refresh.');
  }
  const { repository: result } = await github.graphql(`query($owner:String!,$name:String!,$number:Int!){
    repository(owner:$owner,name:$name){pullRequest(number:$number){body headRefOid
      editor{__typename ... on Bot{id}}
      userContentEdits(first:100){totalCount pageInfo{hasNextPage} nodes{editor{__typename ... on Bot{id}}}}
    }}}`, { owner: context.repo.owner, name: context.repo.repo, number: pr.number });
  const current = result?.pullRequest;
  const edits = current?.userContentEdits;
  const footerBot = 'BOT_kgDOCWWZcg';
  if (current?.body !== body || current?.headRefOid !== pr.head.sha || current?.editor?.__typename !== 'Bot' ||
      current.editor.id !== footerBot || !edits?.totalCount || edits.totalCount !== edits.nodes?.length ||
      edits.pageInfo?.hasNextPage !== false || edits.nodes.some(e => e?.editor?.__typename !== 'Bot' ||
        ![identity.node_id, footerBot].includes(e.editor.id))) {
    throw new Error('Upstream PR footer edit history is not exclusively attributable to the pinned automation bots.');
  }
  return parts[1];
}

export async function configureAutoMerge(github, repo, pr, eligible, report) {
  const { repository: { pullRequest: state } } = await github.graphql(`query($owner: String!, $repo: String!, $number: Int!) {
    repository(owner: $owner, name: $repo) { pullRequest(number: $number) { id headRefOid isDraft autoMergeRequest { enabledAt } } }
  }`, { ...repo, number: pr.number });
  if (state.headRefOid !== pr.head.sha) throw new Error('PR head changed before configuring auto-merge.');
  if (!eligible && state.autoMergeRequest) {
    await github.graphql('mutation($id: ID!) { disablePullRequestAutoMerge(input: {pullRequestId: $id}) { clientMutationId } }', { id: state.id });
    report('Disabled auto-merge; this candidate requires review.');
  } else if (eligible && !state.isDraft && !state.autoMergeRequest) {
    await github.graphql('mutation($id: ID!, $sha: GitObjectID!) { enablePullRequestAutoMerge(input: {pullRequestId: $id, expectedHeadOid: $sha, mergeMethod: SQUASH}) { clientMutationId } }', { id: state.id, sha: pr.head.sha });
    report('Enabled protected auto-merge for a patch/digest update.');
  }
}

// Retained for the separate GITHUB_TOKEN publication-record bot only.
// The App upstream updater must not call this or duplicate native PR CI runs.
export async function dispatchMissingChecks(github, repo, pr, report) {
  for (const workflow_id of ['ci.yml', 'issue-policy.yml']) {
    const runs = await github.paginate(github.rest.actions.listWorkflowRuns, { ...repo, workflow_id,
      branch: pr.head.ref, event: 'workflow_dispatch', per_page: 100 });
    if (runs.some(run => run.head_sha === pr.head.sha)) continue;
    await github.rest.actions.createWorkflowDispatch({ ...repo, workflow_id, ref: pr.head.ref,
      ...(workflow_id === 'issue-policy.yml' ? { inputs: { pull_request_number: String(pr.number) } } : {}) });
    report('Dispatched ' + workflow_id + ' for ' + pr.head.sha);
  }
}
