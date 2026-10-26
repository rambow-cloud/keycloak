import { readFile, writeFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const directory = dirname(fileURLToPath(import.meta.url));
const repository = resolve(directory, '../..');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const unique = values => new Set(values).size === values.length;
const text = value => typeof value === 'string' && value.trim() === value && value.length > 0 && value.length <= 1000 && !/[\x00-\x1f\x7f<>]/.test(value);
const numbers = values => Array.isArray(values) && values.length > 0 && values.length <= 20 && unique(values) && values.every(n => Number.isSafeInteger(n) && n > 0);
const escape = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('|', '&#124;').replace(/([\\`*_[\]{}()!~])/g, '\\$1').replaceAll('@', '@\u200b');
const issueLinks = values => values.map(n => '[#' + n + '](https://github.com/rambow-cloud/keycloak/issues/' + n + ')').join(', ');
export function parseLedger(source) {
  const normalized = source.replaceAll('\r\n', '\n');
  if (!normalized.endsWith('\n') || normalized.startsWith('\uFEFF') || normalized.includes('\r')) throw Error('JSONL must have complete newline-terminated records without a BOM');
  const lines = normalized.slice(0, -1).split('\n');
  if (!lines.length || lines.some(line => !line.trim())) throw Error('The ledger must contain nonempty JSONL records');
  return lines.map((line, index) => {
    try { return JSON.parse(line); } catch { throw Error('Invalid JSONL at line ' + (index + 1)); }
  });
}
export function assertAppendOnly(previous, current) {
  const old = previous.replaceAll('\r\n', '\n'), next = current.replaceAll('\r\n', '\n');
  if ((old && !old.endsWith('\n')) || !next.startsWith(old)) throw Error('Existing ledger lines are immutable; append a correction record');
  parseLedger(next);
}
export function validateRecords(records, catalog) {
  const seen = new Set();
  const allowed = ['schemaVersion', 'id', 'recordedAt', 'kind', 'status', 'advisories', 'summary', 'details', 'issues', 'pullRequests', 'images', 'references', 'evidence', 'supersedes'];
  for (const r of records) {
    if (!r || typeof r !== 'object' || Array.isArray(r) || Object.keys(r).some(k => !allowed.includes(k)) || r.schemaVersion !== 1 ||
        !/^SEC-\d{4}-\d{3,}$/.test(r.id ?? '') || seen.has(r.id) ||
        !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(r.recordedAt ?? '') || !Number.isFinite(Date.parse(r.recordedAt)) || new Date(r.recordedAt).toISOString() !== r.recordedAt ||
        !['fix', 'verification', 'correction'].includes(r.kind) || !['fixed-before-publication', 'verified-existing', 'under-review', 'retracted'].includes(r.status) ||
        !text(r.summary) || r.summary.length < 20 || !Array.isArray(r.details) || !r.details.length || !r.details.every(text) ||
        !Array.isArray(r.advisories) || !r.advisories.length || !unique(r.advisories) || r.advisories.some(a => !/^(?:CVE-\d{4}-\d{4,}|GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|[A-Z]+-\d{4}-\d{2})$/.test(a)) ||
        !numbers(r.issues) || !Array.isArray(r.pullRequests) || (r.pullRequests.length > 0 && !numbers(r.pullRequests))) throw Error('Invalid security record: ' + (r?.id ?? 'unknown'));
    if ((r.kind === 'correction') !== Boolean(r.supersedes) || (r.supersedes && !seen.has(r.supersedes))) throw Error('Correction must reference an earlier record');
    if ((r.kind === 'fix' && r.status !== 'fixed-before-publication') || (r.kind === 'verification' && r.status !== 'verified-existing')) throw Error('Record kind/status mismatch');
    if (!Array.isArray(r.images) || !r.images.length || r.images.length > 20 || !unique(r.images.map(i => i.tag))) throw Error('Explicit unique published images are required');
    for (const image of r.images) {
      if (!catalog.some(p => p.profile === image.profile && p.tag === image.tag && p.digest === image.digest)) throw Error('Image tag/profile/digest is absent from the publication catalog');
    }
    if (!Array.isArray(r.references) || !r.references.length || r.references.length > 20 || r.references.some(ref => {
      try {
        const url = new URL(ref.url);
        return !text(ref.label) || !text(ref.url) || url.protocol !== 'https:' || url.username || url.password ||
          !['github.com', 'hc.apache.org', 'emudhra.we-have-a-problem.com', 'nvd.nist.gov'].includes(url.hostname);
      } catch { return true; }
    })) throw Error('Invalid evidence reference');
    if (!Array.isArray(r.evidence) || r.evidence.length > 20 || !unique(r.evidence.map(e => e.path)) || r.evidence.some(e =>
      !/^evidence\/[a-z0-9][a-z0-9-]*\.json$/.test(e.path ?? '') || !/^[a-f0-9]{64}$/.test(e.sha256 ?? '') || !text(e.label))) throw Error('Invalid local evidence');
    if (r.kind === 'verification' && !r.evidence.length) throw Error('Verification needs durable local evidence');
    seen.add(r.id);
  }
  return records;
}
export async function readLedger() {
  const files = (await readdir(resolve(repository, 'releases/records'))).filter(n => n.endsWith('.json'));
  const catalog = (await Promise.all(files.map(async n => JSON.parse(await readFile(resolve(repository, 'releases/records', n), 'utf8'))))).flatMap(r => r.plan.images);
  const source = await readFile(resolve(directory, 'records.jsonl'), 'utf8');
  const records = validateRecords(parseLedger(source), catalog);
  for (const record of records) for (const evidence of record.evidence) {
    const bytes = await readFile(resolve(directory, evidence.path));
    if (sha256(bytes) !== evidence.sha256) throw Error('Evidence checksum mismatch: ' + evidence.path);
    const report = JSON.parse(bytes);
    if (report.schemaVersion !== 1 || !record.images.some(i => i.profile === report.profile && report.image === 'quay.io/rambow-cloud/keycloak@' + i.digest) ||
        report.branch !== 'chore/37-emudhra-regression' || !/^[a-f0-9]{40}$/.test(report.codeCommit ?? '') ||
        !Number.isSafeInteger(report.runId) || report.runId < 1 || report.runUrl !== 'https://github.com/rambow-cloud/keycloak/actions/runs/' + report.runId ||
        report.result?.status !== 'passed' || report.result.os !== 'Linux' || report.result.positiveControl !== 'accepted' ||
        report.result.chains?.length !== 14 || !unique(report.result.chains.map(c => c.name)) ||
        report.result.chains.some(c => c.defaultTrust !== 'rejected' || c.restoredRootsControl !== 'accepted' || !report.fixtures.chains.some(f => f.name === c.name && f.sha256 === c.sha256 && sha256(f.pem) === c.sha256))) throw Error('Regression evidence does not match the record');
  }
  return { source, records };
}
export function query(records, value) {
  return records.filter(r => r.id === value || r.supersedes === value || r.advisories.includes(value) || r.images.some(i => i.tag === value || i.digest === value));
}
export function render(records) {
  const status = { 'fixed-before-publication': 'Fixed before first publication', 'verified-existing': 'Existing images verified', 'under-review': 'Under review', retracted: 'Retracted' };
  let md = '# Security remediation ledger\n\n<!-- Generated from records.jsonl by ledger.mjs. Do not edit by hand. -->\n\n' +
    'Git-backed JSONL records; no database service. This page documents reviewed repairs and verification events. It is not a complete current vulnerability inventory or a continuous scan dashboard.\n\n' +
    '[Published images](../../releases/README.md) · [Scan policy](../vulnerability-scanning.md) · [Text records](records.jsonl)\n\n' +
    '## Repair and verification history\n\n| Record | Advisories / event | Result | Published image tags | Issues |\n| --- | --- | --- | --- | --- |\n';
  for (const r of records) md += '| [' + r.id + '](#' + r.id.toLowerCase() + ') | ' + r.advisories.map(escape).join(', ') + ' | ' + status[r.status] +
    ' | ' + r.images.map(i => '`' + i.tag + '`').join(', ') + ' | ' + issueLinks(r.issues) + ' |\n';
  md += '\n## CVE and security event index\n\n';
  for (const id of [...new Set(records.flatMap(r => r.advisories))].sort()) md += '- **' + id + '**: ' + query(records, id).map(r => '[' + r.id + '](#' + r.id.toLowerCase() + ')').join(', ') + '\n';
  for (const r of records) {
    const corrections = records.filter(n => n.supersedes === r.id);
    md += '\n## ' + r.id + '\n\n' + escape(r.summary) + '\n\nRecorded (UTC): `' + r.recordedAt + '`. Result: **' + status[r.status] + '**.\n';
    if (r.supersedes) md += '\nCorrects [' + r.supersedes + '](#' + r.supersedes.toLowerCase() + '). The earlier record remains visible.\n';
    if (corrections.length) md += '\n**Later corrections:** ' + corrections.map(n => '[' + n.id + '](#' + n.id.toLowerCase() + ')').join(', ') + '. Read these before relying on this historical conclusion.\n';
    md += '\n' + r.details.map(d => '- ' + escape(d)).join('\n') + '\n\n| Profile | Published tag | Digest |\n| --- | --- | --- |\n';
    for (const i of r.images) md += '| ' + i.profile + ' | `' + i.tag + '` | `' + i.digest + '` |\n';
    md += '\nIssues: ' + issueLinks(r.issues) + '.\n';
    if (r.pullRequests.length) md += '\nReference PRs: ' + r.pullRequests.map(n => '[#' + n + '](https://github.com/rambow-cloud/keycloak/pull/' + n + ')').join(', ') + '.\n';
    md += '\nEvidence and sources:\n\n' + r.references.map(ref => '- [' + escape(ref.label) + '](<' + ref.url + '>)').join('\n') + '\n';
    for (const e of r.evidence) md += '- [' + escape(e.label) + '](' + e.path + ') — SHA-256 `' + e.sha256 + '`\n';
  }
  return md + '\n## Maintain and query\n\nAppend one complete JSON object per line to `records.jsonl`; retain existing lines, apart from Git newline conversion. Corrections use `kind: "correction"` and `supersedes` with the earlier record ID. Existing publication records and image digests are never rewritten.\n\n' +
    'Every repair PR must include a ledger record or reference its existing record and explain why no new event is needed. Evidence-only verification records do not justify rebuilding or publishing an unchanged image. Both the text ledger and generated page are reviewed through the normal Issue/PR process.\n\n' +
    'From the repository root:\n\n```sh\nnode docs/security/ledger.mjs render\nnode docs/security/ledger.mjs render --check\nnode docs/security/ledger.mjs show CVE-2026-54399\nnode docs/security/ledger.mjs show EMUDHRA-2026-10\nnode docs/security/ledger.mjs show 26.8.1-r1-aws\nnode docs/security/ledger.mjs append-check origin/main\n```\n\n' +
    'The retained regression branch is `chore/37-emudhra-regression` ([draft PR #38](https://github.com/rambow-cloud/keycloak/pull/38)). Its test code/workflow stays outside main. Reports above include the exact code commit and Actions run, all public chain fixtures and checksums, JVM/trust-store identity, controls and limits; expiring Actions artifacts are supplemental evidence. No scheduled rescan or automatic triage is implemented by this ledger.\n';
}
export function checkBaseline(base, current, cwd = repository) {
  if (!/^(?:[a-f0-9]{40}|origin\/main)$/.test(base)) throw Error('Expected a commit SHA or origin/main');
  const exists = spawnSync('git', ['cat-file', '-e', base + '^{commit}'], { cwd, encoding: 'utf8' });
  if (exists.status !== 0) {
    if (process.env.GITHUB_ACTIONS !== 'true') throw Error('Append-only baseline commit is unavailable');
    const target = base === 'origin/main' ? 'refs/heads/main:refs/remotes/origin/main' : base;
    const fetch = spawnSync('git', ['fetch', '--no-tags', '--depth=1', 'https://github.com/rambow-cloud/keycloak.git', target], { cwd, encoding: 'utf8', timeout: 60000 });
    if (fetch.status !== 0) throw Error('Cannot fetch append-only baseline');
  }
  const path = 'docs/security/records.jsonl';
  const hasPath = spawnSync('git', ['ls-tree', '--name-only', base, '--', path], { cwd, encoding: 'utf8' });
  if (hasPath.status !== 0) throw Error('Cannot inspect append-only baseline tree');
  const previous = hasPath.stdout.trim() ? spawnSync('git', ['show', base + ':' + path], { cwd, encoding: 'utf8' }) : { status: 0, stdout: '' };
  if (previous.status !== 0) throw Error('Cannot read append-only baseline');
  assertAppendOnly(previous.stdout, current);
}
async function main() {
  const { records, source } = await readLedger();
  const [command, value] = process.argv.slice(2);
  if (command === 'render') {
    const markdown = render(records), path = resolve(directory, 'README.md');
    if (value === '--check') {
      if (await readFile(path, 'utf8') !== markdown) throw Error('Security Markdown is stale; run node docs/security/ledger.mjs render');
      console.log('Security ledger, durable evidence and generated Markdown are consistent.');
    } else if (value === undefined) await writeFile(path, markdown);
    else throw Error('Unknown render option');
  } else if (command === 'show') {
    const result = query(records, value); if (!result.length) throw Error('No security records match this identifier');
    console.log(JSON.stringify(result, null, 2));
  } else if (command === 'append-check') { checkBaseline(value, source); console.log('Existing security records are preserved.'); }
  else throw Error('Usage: node docs/security/ledger.mjs render [--check] | show <record/CVE/event/tag/digest> | append-check <base>');
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) await main();
