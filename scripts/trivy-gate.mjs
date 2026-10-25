import { readFile } from 'node:fs/promises';
import { validateSummary, gateSummary } from './lib/trivy.mjs';
const summary = JSON.parse(await readFile(process.argv[2], 'utf8'));
validateSummary(summary, { profile: process.env.BUILD_PROFILE ?? 'core',
  headSha: process.env.SCAN_HEAD_SHA ?? process.env.GITHUB_SHA,
  runId: Number(process.env.GITHUB_RUN_ID ?? 0), runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT ?? 1) });
gateSummary(summary);
console.log('Trivy vulnerability gate passed.');
