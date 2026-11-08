import { readFile, writeFile, mkdir, mkdtemp } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { summarize, renderReport, downloadScannerArchive } from './lib/trivy.mjs';
import { nativeArchitecture } from './lib/platforms.mjs';
import { isRambowRuntime, readRuntimeSbom, combineRuntimeScans } from './lib/runtime-sbom.mjs';

const profile = process.env.BUILD_PROFILE ?? 'core';
const architecture = process.env.BUILD_ARCH;
const runtime = process.env.SCAN_RUNTIME;
const headSha = process.env.SCAN_HEAD_SHA ?? process.env.GITHUB_SHA;
const runId = Number(process.env.GITHUB_RUN_ID ?? 0);
const runAttempt = Number(process.env.GITHUB_RUN_ATTEMPT ?? 1);
const image = resolve(process.argv[2] ?? '.cache/trivy-image');
const output = resolve(process.argv[3] ?? '.cache/trivy-report');
await mkdir(output, { recursive: true });
const errorSummary = () => ({ schemaVersion: architecture ? 2 : 1, profile, ...(architecture ? {architecture} : {}), headSha, runId, runAttempt, status: 'error' });
let summary = errorSummary();
try {
  if (process.platform !== 'linux') throw new Error('The pinned Trivy binary requires Linux.');
  const hostArchitecture = nativeArchitecture();
  const policy = JSON.parse(await readFile(new URL('../config/trivy.json', import.meta.url), 'utf8'));
  const work = await mkdtemp(join(tmpdir(), 'rambow-trivy-'));
  const archive = await downloadScannerArchive(policy, hostArchitecture);
  await writeFile(join(work, 'trivy.tar.gz'), archive);
  const extract = spawnSync('tar', ['-xzf', join(work, 'trivy.tar.gz'), '-C', work, '--no-same-owner', 'trivy'], { stdio: 'inherit' });
  if (extract.status !== 0) throw new Error('Cannot extract Trivy binary.');
  const inventory = isRambowRuntime(runtime) ? await readRuntimeSbom(runtime, architecture) : null;
  const scan = async (command, file, args) => {
    const path = join(output, file);
    const result = spawnSync(join(work, 'trivy'), [command, '--config', '', '--ignorefile', '', '--scanners', 'vuln',
      '--pkg-types', 'os,library', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--ignore-unfixed=false',
      '--list-all-pkgs', '--format', 'json', '--output', path, '--exit-code', '0', '--cache-dir', join(work, 'cache'),
      '--timeout', '10m', '--no-progress', '--skip-version-check', ...args], { stdio: 'inherit', timeout: 660000 });
    if (result.status !== 0) throw new Error('Trivy ' + command + ' scan failed. See scanner/database logs.');
    return JSON.parse(await readFile(path, 'utf8'));
  };
  let report = await scan('image', inventory ? 'trivy-image.json' : 'trivy.json', ['--input', image]);
  if (inventory) {
    const baseReport = await scan('sbom', 'trivy-runtime.json', ['--skip-db-update', '--skip-java-db-update', fileURLToPath(inventory.path)]);
    report = combineRuntimeScans(report, baseReport, inventory);
    await writeFile(join(output, 'trivy.json'), JSON.stringify(report, null, 2) + '\n');
  }
  summary = summarize(report, { profile, architecture, headSha, runId, runAttempt, policy, runtime });
  for (const name of ['db', 'java-db']) {
    try { await writeFile(join(output, name + '-metadata.json'), await readFile(join(work, 'cache', name, 'metadata.json'))); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
} catch (error) {
  console.error(error.message);
  summary = errorSummary();
  process.exitCode = 1;
}
await writeFile(join(output, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
if (process.env.GITHUB_STEP_SUMMARY) {
  const { appendFile } = await import('node:fs/promises');
  const key = architecture ? profile + '/' + architecture : profile;
  await appendFile(process.env.GITHUB_STEP_SUMMARY, renderReport({ [key]: summary }, {
    runUrl: 'https://github.com/' + process.env.GITHUB_REPOSITORY + '/actions/runs/' + runId,
    headSha, runId, runAttempt, ...(architecture ? {expectedTargets:[key]} : {}), conclusion: summary.status === 'complete' ? 'Scan complete; policy gate follows' : 'Scan failed' }));
}
