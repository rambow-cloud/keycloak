import { readFile } from 'node:fs/promises';
import { gateTargetSummaries } from './lib/trivy.mjs';
const summary = JSON.parse(await readFile(process.argv[2], 'utf8'));
const context = { profile: process.env.BUILD_PROFILE ?? 'core',
  architecture: process.env.BUILD_ARCH,
  headSha: process.env.SCAN_HEAD_SHA ?? process.env.GITHUB_SHA,
  runId: Number(process.env.GITHUB_RUN_ID ?? 0), runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT ?? 1) };
gateTargetSummaries(summary,context);
console.log('Trivy vulnerability gate passed.');
