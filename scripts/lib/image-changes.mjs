import { createHash } from 'node:crypto';
import policy from '../issue-policy.cjs';

export const imageProfiles = ['core', 'aws'];
const sha256 = value => createHash('sha256').update(value).digest('hex');
const ordered = value => Array.isArray(value) ? value.map(ordered) : value && typeof value === 'object'
  ? Object.fromEntries(Object.entries(value).sort(([a],[b]) => a.localeCompare(b)).map(([k,v]) => [k,ordered(v)])) : value;
const stringify = value => JSON.stringify(ordered(value));
const metadata = /^(?:docs\/|releases\/|changes\/|\.github\/(?:ISSUE_TEMPLATE\/|pull_request_template\.md|issue-policy\.json)|.*\.md$|LICENSE(?:\..*)?$|\.gitignore$)/;
const bookkeeping = /^scripts\/(?:quay-release|release-catalog|releases|upstream-update|lock-images|issue-policy|trivy-comment)\.(?:mjs|cjs)$|^scripts\/lib\/(?:releases|quay-publish|quay-auth|upstream)\.mjs$|^\.github\/workflows\/(?!ci\.yml$)[^/]+\.yml$|^tests\/[^/]+\.test\.cjs$/;
const validation = /^scripts\/(?:verify-|scan-image|trivy-gate|release-image|check-upstream-compatibility)|^scripts\/lib\/(?:trivy|oci|image-changes)\.mjs$|^config\/(?:trivy|upstream-compatibility)\.json$|^\.github\/workflows\/ci\.yml$|^tests\//;
export function sourceProfiles(path) {
  if (path.startsWith('experiments/')) return [];
  if (metadata.test(path) || bookkeeping.test(path) || validation.test(path)) return [];
  if (/^dependencies\/aws\/|^scripts\/aws-dependencies\.mjs$/.test(path)) return ['aws'];
  return imageProfiles;
}
export function validationProfiles(path) {
  if (path.startsWith('experiments/')) return imageProfiles;
  if (bookkeeping.test(path) || metadata.test(path)) return [];
  if (path === 'tests/AwsHttpTransport.java') return ['aws'];
  return validation.test(path) ? imageProfiles : [];
}
export function validateChanges(changes) {
  if (!Array.isArray(changes) || !changes.length || changes.length > 100) throw new Error('Every image tag needs nonempty fix/feature changes.');
  for (const c of changes) {
    if (!['fix', 'feature'].includes(c.type) || typeof c.summary !== 'string' || c.summary.trim() !== c.summary ||
        c.summary.length < 20 || c.summary.length > 600 || /[\x00-\x1f\x7f<>]/.test(c.summary) ||
        /^(?:no (?:image )?(?:changes?|updates?)\b|nothing\b)|^(?:n\/?a|none|todo|tbd|placeholder|updates?|fix(?:es)?)\b[.! ]*$/i.test(c.summary) ||
        !Array.isArray(c.issues) || !c.issues.length || c.issues.length > 20 || c.issues.some(n => !Number.isSafeInteger(n) || n < 1) ||
        new Set(c.issues).size !== c.issues.length) throw new Error('Changes require a substantive fix/feature summary and local Issue numbers.');
  }
  return changes;
}
export function validateFragment(fragment, { allowEmpty = false } = {}) {
  if (fragment.schemaVersion !== 1 || !Array.isArray(fragment.changes)) throw new Error('Invalid change fragment.');
  if (!(allowEmpty && fragment.changes.length === 0)) validateChanges(fragment.changes);
  for (const c of fragment.changes) if (!Array.isArray(c.profiles) || !c.profiles.length ||
    c.profiles.some(p => !imageProfiles.includes(p)) || new Set(c.profiles).size !== c.profiles.length) throw new Error('Change fragments require explicit unique profiles.');
  return fragment;
}
async function readContent(github, repo, path, ref) {
  const { data } = await github.rest.repos.getContent({ ...repo, path, ref });
  if (data.encoding !== 'base64' || data.size > 1000000) throw new Error('Expected bounded JSON: ' + path);
  return Buffer.from(data.content, 'base64').toString('utf8');
}
export async function readJSON(github, repo, path, ref) { return JSON.parse(await readContent(github, repo, path, ref)); }
export async function snapshot(github, repo, ref) {
  const [{ data: tree }, lock, containerfile] = await Promise.all([
    github.rest.git.getTree({ ...repo, tree_sha: ref, recursive: '1' }), readJSON(github, repo, 'images.lock.json', ref),
    readContent(github, repo, 'Containerfile', ref),
  ]);
  if (tree.truncated) throw new Error('Cannot classify an incomplete Git tree.');
  if (!Array.isArray(tree.tree) || tree.tree.some(e => e.type !== 'tree' && !/^[a-f0-9]{40}$/.test(e.sha ?? ''))) throw new Error('Cannot classify an invalid Git tree.');
  const files = Object.fromEntries(tree.tree.filter(e => e.type !== 'tree').map(e => [e.path, { sha: e.sha, mode: e.mode, type: e.type }]));
  return { ref, files, lock, containerfile };
}
export function containerInputs(text, profile) {
  if (typeof text !== 'string') throw new Error('Containerfile source is required.');
  if (/<<|--from=\$|from=\$/.test(text)) return text; // Ambiguous/dynamic syntax is conservative.
  const lines = text.split(/\r?\n/).filter(l => !/^\s*#(?!\s*(?:syntax|escape)\s*=)/i.test(l));
  const stages = new Map();
  const global = [];
  let stage;
  for (const line of lines) {
    if (/^\s*FROM\s/i.test(line)) {
      const m = /^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)\s+AS\s+([a-z0-9_-]+)\s*$/i.exec(line);
      if (!m || stages.has(m[2].toLowerCase())) return text;
      stage = { parent:m[1].toLowerCase(), lines:[] };
      stages.set(m[2].toLowerCase(), stage);
    }
    (stage?.lines ?? global).push(line);
  }
  if (!stages.has(profile)) return text;
  const selected = new Set();
  function visit(name) {
    if (!stages.has(name) || selected.has(name)) return;
    selected.add(name);
    const s = stages.get(name);
    visit(s.parent);
    for (const m of s.lines.join('\n').matchAll(/(?:--from=|\bfrom=)([a-z0-9_-]+)/gi)) visit(m[1].toLowerCase());
  }
  visit(profile);
  return [...global, ...[...stages].filter(([name]) => selected.has(name)).flatMap(([,s]) => s.lines)].join('\n').trim();
}
const lockInputs = (lock, profile) => Object.fromEntries(Object.entries(lock).sort(([a], [b]) => a.localeCompare(b))
  .filter(([k]) => k !== 'postgres' && (profile === 'aws' || k !== 'awsDependencies')));
export function fingerprint(source, profile) {
  if (!imageProfiles.includes(profile)) throw new Error('Unknown fingerprint profile.');
  const files = Object.entries(source.files).filter(([path]) => !['images.lock.json','Containerfile'].includes(path) && sourceProfiles(path).includes(profile)).sort(([a], [b]) => a.localeCompare(b));
  return sha256(stringify({ schemaVersion: 1, profile, lock: lockInputs(source.lock, profile), containerfile:containerInputs(source.containerfile,profile), files }));
}
export function classifyCI(base, head) {
  const changed = [...new Set([...Object.keys(base.files), ...Object.keys(head.files)])].filter(path => stringify(base.files[path]) !== stringify(head.files[path]));
  const inputs = imageProfiles.filter(p => fingerprint(base, p) !== fingerprint(head, p));
  const checks = changed.flatMap(validationProfiles);
  if (base.lock.postgres !== head.lock.postgres) checks.push(...imageProfiles);
  return { profiles: imageProfiles.filter(p => inputs.includes(p) || checks.includes(p)), imageChanges: inputs, changed };
}
export async function changedNotes({ github, repo, base, source, selected, checkedIssues = new Set() }) {
  const paths = Object.keys(source.files).filter(path => /^changes\/[a-z0-9][a-z0-9._-]*\.json$/.test(path) && source.files[path].sha !== base?.files[path]?.sha);
  for (const path of Object.keys(base?.files ?? {}).filter(p => /^changes\/.+\.json$/.test(p))) {
    if (!source.files[path] || (path !== 'changes/upstream.json' && source.files[path].sha !== base.files[path].sha)) throw new Error('Published change fragments cannot be removed or rewritten.');
  }
  if (paths.length > 100) throw new Error('Too many change fragments.');
  const byProfile = Object.fromEntries(selected.map(p => [p, []]));
  for (const path of paths) {
    const f = validateFragment(await readJSON(github, repo, path, source.ref), { allowEmpty: path === 'changes/upstream.json' });
    for (const change of f.changes) for (const profile of selected.filter(p => change.profiles.includes(p))) {
      byProfile[profile].push({ type: change.type, summary: change.summary, issues: change.issues });
    }
  }
  for (const profile of selected) validateChanges(byProfile[profile]);
  const issues = [...new Set(Object.values(byProfile).flat().flatMap(c => c.issues))];
  if (issues.length > 100) throw new Error('Too many change Issue references.');
  for (const issue_number of issues.filter(n => !checkedIssues.has(n))) {
    const { data } = await github.rest.issues.get({ ...repo, issue_number });
    policy.validateIssue({ ...data, state: 'open' }); // Released fixes normally reference already-closed Issues.
    checkedIssues.add(issue_number);
  }
  return byProfile;
}
export async function assessRelease({ github, repo, sourceCommit, records }) {
  const source = await snapshot(github, repo, sourceCommit);
  const snapshots = new Map([[sourceCommit, Promise.resolve(source)]]);
  const checkedIssues = new Set();
  const compared = new Set();
  const images = [];
  const ordered = [...records].sort((a, b) => Date.parse(b.publishedAt) - Date.parse(a.publishedAt) || b.publishRunId - a.publishRunId);
  for (const profile of imageProfiles) {
    const prior = ordered.find(r => r.plan.images.some(i => i.profile === profile));
    const previous = prior?.plan.images.find(i => i.profile === profile);
    let base;
    if (prior) {
      if (!compared.has(prior.plan.sourceCommit)) {
        const { data: comparison } = await github.rest.repos.compareCommits({ ...repo, base: prior.plan.sourceCommit, head: sourceCommit });
        if (comparison.merge_base_commit.sha !== prior.plan.sourceCommit) throw new Error('Release source predates the published profile baseline.');
        compared.add(prior.plan.sourceCommit);
      }
      if (!snapshots.has(prior.plan.sourceCommit)) snapshots.set(prior.plan.sourceCommit, snapshot(github, repo, prior.plan.sourceCommit));
      base = await snapshots.get(prior.plan.sourceCommit);
    }
    const inputSha256 = fingerprint(source, profile);
    if (previous && inputSha256 === (previous.inputSha256 ?? fingerprint(base, profile))) continue;
    const changes = (await changedNotes({ github, repo, base, source, selected: [profile], checkedIssues }))[profile];
    images.push({ profile, inputSha256, changes });
  }
  return { images, profiles: images.map(i => i.profile) };
}
export async function assessCI({ github, context, assessReleaseForCI }) {
  const repo = context.repo;
  const head = context.payload.pull_request?.head.sha ?? context.sha;
  let base = context.payload.pull_request?.base.sha ?? context.payload.before;
  if (context.eventName === 'workflow_dispatch') {
    const { data: metadata } = await github.rest.repos.get(repo);
    if (context.ref === 'refs/heads/' + metadata.default_branch || /^refs\/tags\/v\d+\.\d+\.\d+-r\d+$/.test(context.ref)) {
      return { ...(await assessReleaseForCI(head)), reason: 'Compared with published per-profile input fingerprints.' };
    }
    const prs = await github.paginate(github.rest.repos.listPullRequestsAssociatedWithCommit, { ...repo, commit_sha: head, per_page: 100 });
    base = prs.find(p => p.state === 'open' && p.head.sha === head && p.base.repo.full_name === repo.owner + '/' + repo.repo)?.base.sha;
  }
  if (!base || /^0+$/.test(base)) return { profiles: imageProfiles, reason: 'No reliable diff baseline; conservative validation.' };
  const [old, current] = await Promise.all([snapshot(github, repo, base), snapshot(github, repo, head)]);
  const impact = classifyCI(old, current);
  if (impact.imageChanges.length) await changedNotes({ github, repo, base: old, source: current, selected: impact.imageChanges });
  return { profiles: impact.profiles, reason: impact.profiles.length ? 'Image inputs or their validation changed.' : 'No image fix/feature or validation change; image builds skipped.' };
}
