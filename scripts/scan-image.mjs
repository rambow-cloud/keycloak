import { readFile, writeFile, mkdir, mkdtemp } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { summarize, validatePolicy, renderReport, verifyScannerArchive } from './lib/trivy.mjs';

const profile = process.env.BUILD_PROFILE ?? 'core';
const headSha = process.env.SCAN_HEAD_SHA ?? process.env.GITHUB_SHA;
const runId = Number(process.env.GITHUB_RUN_ID ?? 0);
const runAttempt = Number(process.env.GITHUB_RUN_ATTEMPT ?? 1);
const image = resolve(process.argv[2] ?? '.cache/trivy-image');
const output = resolve(process.argv[3] ?? '.cache/trivy-report');
await mkdir(output, { recursive: true });
let summary = { schemaVersion: 1, profile, headSha, runId, runAttempt, status: 'error' };
try {
  if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('The pinned Trivy binary requires Linux amd64.');
  const policy = JSON.parse(await readFile(new URL('../config/trivy.json', import.meta.url), 'utf8'));
  validatePolicy(policy);
  const work = await mkdtemp(join(tmpdir(), 'rambow-trivy-'));
  const url = 'https://github.com/aquasecurity/trivy/releases/download/v' + policy.version + '/trivy_' + policy.version + '_Linux-64bit.tar.gz';
  const response = await fetch(url, { signal: AbortSignal.timeout(120000) });
  if (!response.ok) throw new Error('Cannot download pinned Trivy: HTTP ' + response.status);
  const archive = Buffer.from(await response.arrayBuffer());
  verifyScannerArchive(archive, policy.linuxAmd64Sha256);
  await writeFile(join(work, 'trivy.tar.gz'), archive);
  const extract = spawnSync('tar', ['-xzf', join(work, 'trivy.tar.gz'), '-C', work, '--no-same-owner', 'trivy'], { stdio: 'inherit' });
  if (extract.status !== 0) throw new Error('Cannot extract Trivy binary.');
  const scan = spawnSync(join(work, 'trivy'), ['image', '--config', '', '--ignorefile', '', '--scanners', 'vuln',
    '--pkg-types', 'os,library', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--ignore-unfixed=false',
    '--list-all-pkgs', '--format', 'json', '--output', join(output, 'trivy.json'), '--exit-code', '0',
    '--cache-dir', join(work, 'cache'), '--timeout', '10m', '--no-progress', '--skip-version-check', '--input', image],
  { stdio: 'inherit', timeout: 660000 });
  if (scan.status !== 0) throw new Error('Trivy failed; see scanner/database logs above.');
  const report = JSON.parse(await readFile(join(output, 'trivy.json'), 'utf8'));
  const lock = JSON.parse(await readFile(new URL('../images.lock.json', import.meta.url), 'utf8'));
  summary = summarize(report, { profile, headSha, runId, runAttempt, policy, expectedOS: lock.runtimeOs ?? 'debian' });
  for (const name of ['db', 'java-db']) {
    try { await writeFile(join(output, name + '-metadata.json'), await readFile(join(work, 'cache', name, 'metadata.json'))); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
} catch (error) {
  console.error(error.message);
  summary = { schemaVersion: 1, profile, headSha, runId, runAttempt, status: 'error' };
  process.exitCode = 1;
}
await writeFile(join(output, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
if (process.env.GITHUB_STEP_SUMMARY) {
  const { appendFile } = await import('node:fs/promises');
  await appendFile(process.env.GITHUB_STEP_SUMMARY, renderReport({ [profile]: summary }, {
    runUrl: 'https://github.com/' + process.env.GITHUB_REPOSITORY + '/actions/runs/' + runId,
    headSha, runId, runAttempt, conclusion: summary.status === 'complete' ? 'Scan complete; policy gate follows' : 'Scan failed' }));
}
