import { readFile, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { profiles, commentMarker, validateSummary, renderReport } from './lib/trivy.mjs';

export function plannedScanProfiles(jobs, conclusion) {
  if (!jobs.some(j => j.name === 'Image impact' && j.conclusion === 'success')) return profiles;
  const active = profiles.filter(p => jobs.some(j => j.name === 'Build ' + p && j.conclusion !== 'skipped'));
  if (active.length) return active;
  if (conclusion === 'success' && jobs.some(j => j.name === 'Build and verify' && j.conclusion === 'success') &&
      jobs.some(j => (/^Build(?: (?:core|aws))?$/.test(j.name) || j.name === 'Build ${{ matrix.profile }}') &&
        j.conclusion === 'skipped')) return [];
  return profiles; // Missing/failed planning evidence must never turn missing scans into skips.
}
export function plannedScanTargets(jobs) {
  const native = jobs.map(j => /^Build (core|aws) \((amd64|arm64)\)$/.exec(j.name)).filter(Boolean);
  if (!native.length) return undefined;
  const selected = profiles.filter(p => native.some(m => m[1] === p));
  return selected.flatMap(p => ['amd64','arm64'].map(a => p + '/' + a));
}

// This module is loaded only from the trusted default branch by the write-enabled reporter.
export async function prepareReport({ github, context, runId, core }) {
  if (!/^[1-9][0-9]*$/.test(String(runId))) throw new Error('A CI run ID is required.');
  const repo = context.repo;
  const fullName = repo.owner + '/' + repo.repo;
  const { data: run } = await github.rest.actions.getWorkflowRun({ ...repo, run_id: Number(runId) });
  if (run.repository.full_name !== fullName || run.path !== '.github/workflows/ci.yml' ||
      !['pull_request', 'workflow_dispatch'].includes(run.event) || run.status !== 'completed') {
    core.info('Not a completed PR-associated CI run; no comment.');
    return null;
  }
  const { data: workflow } = await github.rest.actions.getWorkflow({ ...repo, workflow_id: run.workflow_id });
  if (workflow.path !== '.github/workflows/ci.yml') throw new Error('Unexpected source workflow.');
  const { data: metadata } = await github.rest.repos.get(repo);
  const associated = await github.paginate(github.rest.repos.listPullRequestsAssociatedWithCommit, { ...repo, commit_sha: run.head_sha, per_page: 100 });
  const prs = associated.filter(pr => pr.base.repo.full_name === fullName && pr.base.ref === metadata.default_branch &&
    pr.head.repo?.full_name === run.head_repository?.full_name && pr.head.ref === run.head_branch &&
    pr.head.sha === run.head_sha && (pr.state === 'open' || pr.merged_at));
  if (!prs.length) { core.info('No current matching PR head; stale/unrelated run skipped.'); return null; }
  const recent = await github.paginate(github.rest.actions.listWorkflowRuns, { ...repo, workflow_id: run.workflow_id, head_sha: run.head_sha, per_page: 100 });
  if (recent.some(other => ['pull_request', 'workflow_dispatch'].includes(other.event) && other.head_branch === run.head_branch &&
    other.head_repository?.full_name === run.head_repository?.full_name && other.id > run.id)) {
    core.info('A newer CI run exists for this head; older results skipped.'); return null;
  }
  const artifacts = await github.paginate(github.rest.actions.listWorkflowRunArtifacts, { ...repo, run_id: run.id, per_page: 100 });
  let expectedProfiles = profiles;
  let expectedTargets;
  if (github.rest.actions.listJobsForWorkflowRunAttempt) {
    const jobs = await github.paginate(github.rest.actions.listJobsForWorkflowRunAttempt, { ...repo, run_id: run.id, attempt_number: run.run_attempt, per_page: 100 });
    expectedProfiles = plannedScanProfiles(jobs, run.conclusion);
    expectedTargets = plannedScanTargets(jobs);
  }
  const selected = [];
  for (const target of expectedTargets ?? expectedProfiles) {
    const [profile, architecture] = target.split('/');
    const name = 'trivy-' + profile + (architecture ? '-' + architecture : '') + '-' + run.run_attempt;
    const matches = artifacts.filter(a => a.name === name && !a.expired);
    if (matches.length > 1) throw new Error('Ambiguous scan artifacts for ' + profile);
    if (matches.length && matches[0].size_in_bytes > 20000000) throw new Error('Scan artifact exceeds the download limit.');
    if (matches.length) selected.push({ profile, ...(architecture ? {architecture} : {}), name, id: matches[0].id });
  }
  return { run: { id: run.id, run_attempt: run.run_attempt, head_sha: run.head_sha, head_branch: run.head_branch,
    head_repository: { full_name: run.head_repository.full_name }, conclusion: run.conclusion, workflow_id: run.workflow_id },
  prs: prs.map(pr => pr.number), artifacts: selected, expectedProfiles, ...(expectedTargets ? {expectedTargets} : {}) };
}

export async function publishReport({ github, context, prepared, directory, core, loadSummary }) {
  const { run, artifacts } = prepared;
  const summaries = {};
  for (const artifact of artifacts) {
    try {
      let summary;
      if (loadSummary) summary = await loadSummary(artifact);
      else {
        const path = join(directory, artifact.name, 'summary.json');
        const stat = await lstat(path);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 128000) throw new Error('Invalid summary file');
        summary = JSON.parse(await readFile(path, 'utf8'));
      }
      const key = artifact.architecture ? artifact.profile + '/' + artifact.architecture : artifact.profile;
      summaries[key] = validateSummary(summary, { profile: artifact.profile, architecture: artifact.architecture, headSha: run.head_sha, runId: run.id, runAttempt: run.run_attempt });
    } catch {
      core.warning('Missing or invalid ' + artifact.profile + ' summary; reporting incomplete scan.');
    }
  }
  const repo = context.repo;
  const body = renderReport(summaries, { runUrl: 'https://github.com/' + repo.owner + '/' + repo.repo + '/actions/runs/' + run.id,
    headSha: run.head_sha, runId: run.id, runAttempt: run.run_attempt, conclusion: run.conclusion ?? 'unknown', expectedProfiles: prepared.expectedProfiles ?? profiles, expectedTargets: prepared.expectedTargets });
  for (const number of prepared.prs) {
    // Re-check immediately before writing; the PR might have advanced while artifacts downloaded.
    const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: number });
    if (pr.head.sha !== run.head_sha || pr.head.repo?.full_name !== run.head_repository?.full_name) continue;
    const { data: latest } = await github.rest.actions.getWorkflowRun({ ...repo, run_id: run.id });
    if (latest.run_attempt !== run.run_attempt || latest.status !== 'completed') continue;
    const recent = await github.paginate(github.rest.actions.listWorkflowRuns, { ...repo, workflow_id: run.workflow_id, head_sha: run.head_sha, per_page: 100 });
    if (recent.some(other => ['pull_request', 'workflow_dispatch'].includes(other.event) && other.head_branch === run.head_branch &&
      other.head_repository?.full_name === run.head_repository.full_name && other.id > run.id)) continue;
    const comments = await github.paginate(github.rest.issues.listComments, { ...repo, issue_number: number, per_page: 100 });
    const previous = comments.filter(c => c.user?.login === 'github-actions[bot]' && c.body?.startsWith(commentMarker)).sort((a, b) => b.id - a.id)[0];
    const order = previous?.body.match(/<!-- run-order:(\d+):(\d+) -->/);
    if (order && (Number(order[1]) > run.id || (Number(order[1]) === run.id && Number(order[2]) > run.run_attempt))) continue;
    if (previous?.body === body) { core.info('PR #' + number + ' already has this report.'); continue; }
    const { data: comment } = previous
      ? await github.rest.issues.updateComment({ ...repo, comment_id: previous.id, body })
      : await github.rest.issues.createComment({ ...repo, issue_number: number, body });
    core.info('Trivy PR comment: ' + comment.html_url);
  }
}
