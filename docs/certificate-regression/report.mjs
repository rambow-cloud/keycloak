import fs from 'node:fs/promises';
import { createHash } from 'node:crypto';
const directory = '.cache/certificate-regression';
const result = JSON.parse(await fs.readFile(directory + '/result.json', 'utf8'));
const fixtures = JSON.parse(await fs.readFile(directory + '/fixtures.json', 'utf8'));
if (result.status !== 'passed' || result.os !== 'Linux' || result.chains.length !== 14 || result.positiveControl !== 'accepted' ||
    result.chains.some(c => c.defaultTrust !== 'rejected' || c.restoredRootsControl !== 'accepted' || !fixtures.chains.some(f => f.name === c.name && f.sha256 === c.sha256))) throw Error('Incomplete certificate regression');
const code = await fs.readFile('docs/certificate-regression/CertificateChains.java');
const report = { schemaVersion: 1, profile: process.env.PROFILE, image: process.argv[2],
  branch: 'chore/37-emudhra-regression', codeCommit: process.env.HEAD_SHA,
  runId: Number(process.env.GITHUB_RUN_ID), runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
  runUrl: 'https://github.com/rambow-cloud/keycloak/actions/runs/' + process.env.GITHUB_RUN_ID,
  probeSha256: createHash('sha256').update(code).digest('hex'), result, fixtures,
  limits: ['Offline PKIX certificate-path validation, not a live Keycloak outbound HTTPS integration test.',
    'Default image trust anchors and Java security configuration only; custom runtime trust stores are outside this result.',
    'Revocation checks and AIA downloads are disabled to isolate removal of trust anchors; all image validation runs without network access.'] };
await fs.writeFile(directory + '/report.json', JSON.stringify(report, null, 2) + '\n');
console.log(JSON.stringify({ profile: report.profile, image: report.image, status: result.status,
  rejected: result.chains.length, restoredControlsAccepted: result.chains.length, normalControl: result.positiveControl }));
