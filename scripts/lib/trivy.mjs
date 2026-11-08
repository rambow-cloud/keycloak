import { createHash } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { isRambowRuntime } from './runtime-sbom.mjs';

export const profiles = ['core', 'aws'];
export const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
export const commentMarker = '<!-- rambow-trivy-report:v1 -->';
export const maxFindings = 20;

export function validatePolicy(policy) {
  if (!/^\d+\.\d+\.\d+$/.test(policy.version) || !/^[a-f0-9]{64}$/.test(policy.linuxAmd64Sha256) ||
      (policy.linuxArm64Sha256 !== undefined && !/^[a-f0-9]{64}$/.test(policy.linuxArm64Sha256)) ||
      !Array.isArray(policy.blockingSeverities) || !policy.blockingSeverities.length ||
      new Set(policy.blockingSeverities).size !== policy.blockingSeverities.length ||
      policy.blockingSeverities.some(s => !severities.includes(s)) || typeof policy.blockUnfixed !== 'boolean') throw new Error('Invalid Trivy policy');
}

export function hasScanCoverage(report, runtime, requireInventory = false) {
  if (report.SchemaVersion !== 2 || report.ArtifactType !== 'container_image' || !Array.isArray(report.Results)) return false;
  const java = report.Results.some(r => r.Class === 'lang-pkgs' && r.Type === 'jar' && (!requireInventory || r.Packages?.length));
  const os = report.Metadata?.OS;
  if (isRambowRuntime(runtime)) {
    return os?.Family === 'amazon' && os.Name === '2023' && report.RuntimeSbom?.reference === runtime &&
      report.RuntimeSbom.architecture === report.Metadata.ImageConfig?.architecture && /^[a-f0-9]{64}$/.test(report.RuntimeSbom.sha256) &&
      report.Results.some(r => r.Class === 'os-pkgs' && r.Type === 'amazon' && r.Packages?.length) && java;
  }
  return os?.Family === 'debian' && report.Results.some(r => r.Class === 'os-pkgs' && (!requireInventory || r.Packages?.length)) && java;
}

export function summarize(report, { profile, architecture, headSha, runId, runAttempt, policy, runtime }) {
  validatePolicy(policy);
  if (architecture && (!['amd64','arm64'].includes(architecture) || report.Metadata?.ImageConfig?.architecture !== architecture || report.Metadata?.ImageConfig?.os !== 'linux')) throw Error('Scan image architecture does not match the requested Linux target');
  if (!profiles.includes(profile) || !/^[a-f0-9]{40}$/.test(headSha) || !Number.isSafeInteger(runId) || !Number.isSafeInteger(runAttempt)) throw new Error('Invalid scan context');
  if (!hasScanCoverage(report, runtime, isRambowRuntime(runtime))) throw new Error('Missing expected OS or Java scan coverage');
  const unique = new Map();
  for (const result of report.Results) {
    if (result.Vulnerabilities !== undefined && !Array.isArray(result.Vulnerabilities)) throw new Error('Invalid vulnerability list');
    for (const v of result.Vulnerabilities ?? []) {
      const finding = { id: v.VulnerabilityID, package: v.PkgName, installed: v.InstalledVersion,
        fixed: v.FixedVersion ?? '', severity: v.Severity, target: result.Target };
      for (const key of ['id', 'package', 'installed', 'fixed', 'target']) {
        if (typeof finding[key] !== 'string') throw new Error('Malformed vulnerability field: ' + key);
        finding[key] = finding[key].slice(0, key === 'target' ? 512 : 256);
      }
      if (!severities.includes(finding.severity)) throw new Error('Unknown vulnerability severity');
      unique.set(JSON.stringify([finding.id, finding.package, finding.installed, finding.target]), finding);
    }
  }
  const findings = [...unique.values()].sort((a, b) =>
    Number(Boolean(b.fixed.trim()) && policy.blockingSeverities.includes(b.severity)) - Number(Boolean(a.fixed.trim()) && policy.blockingSeverities.includes(a.severity)) ||
    severities.indexOf(a.severity) - severities.indexOf(b.severity) || a.id.localeCompare(b.id) || a.package.localeCompare(b.package));
  const counts = Object.fromEntries(severities.map(s => [s, { total: 0, fixable: 0 }]));
  let blocking = 0;
  for (const finding of findings) {
    counts[finding.severity].total++;
    if (finding.fixed.trim()) counts[finding.severity].fixable++;
    if (policy.blockingSeverities.includes(finding.severity) && (policy.blockUnfixed || finding.fixed.trim())) blocking++;
  }
  return { schemaVersion: architecture ? 2 : 1, profile, ...(architecture ? {architecture} : {}), headSha, runId, runAttempt, status: 'complete', scannerVersion: policy.version,
    ...(isRambowRuntime(runtime) ? { osCoverage: 'al2023-sbom' } : {}),
    createdAt: report.CreatedAt, policy: { blockingSeverities: policy.blockingSeverities, blockUnfixed: policy.blockUnfixed },
    counts, total: findings.length, blocking, osEosl: report.Metadata.OS.EOSL === true,
    findings: findings.slice(0, maxFindings) };
}

export function validateSummary(summary, { profile, architecture, headSha, runId, runAttempt }) {
  if ((architecture ? summary.schemaVersion !== 2 || summary.architecture !== architecture || !['amd64','arm64'].includes(architecture) : summary.schemaVersion !== 1) || summary.profile !== profile || summary.headSha !== headSha ||
      summary.runId !== runId || summary.runAttempt !== runAttempt || !['complete', 'error'].includes(summary.status)) throw new Error('Scan summary does not match this run/profile/commit');
  if (summary.status === 'error') return summary;
  if (!/^\d+\.\d+\.\d+$/.test(summary.scannerVersion) || typeof summary.osEosl !== 'boolean' ||
      (summary.osCoverage !== undefined && summary.osCoverage !== 'al2023-sbom')) throw new Error('Invalid scanner metadata');
  const safeCount = n => Number.isSafeInteger(n) && n >= 0 && n <= 1000000;
  if (!safeCount(summary.total) || !safeCount(summary.blocking) || summary.blocking > summary.total ||
      !Array.isArray(summary.findings) || summary.findings.length > maxFindings || summary.findings.length > summary.total) throw new Error('Invalid summary totals');
  let total = 0;
  for (const severity of severities) {
    const c = summary.counts?.[severity];
    if (!c || !safeCount(c.total) || !safeCount(c.fixable) || c.fixable > c.total) throw new Error('Invalid severity counts');
    total += c.total;
  }
  if (total !== summary.total || !Array.isArray(summary.policy?.blockingSeverities) ||
      !summary.policy.blockingSeverities.length || summary.policy.blockingSeverities.some(s => !severities.includes(s)) ||
      typeof summary.policy.blockUnfixed !== 'boolean') throw new Error('Invalid summary policy/counts');
  const expectedBlocking = summary.policy.blockingSeverities.reduce((n, s) => n + summary.counts[s][summary.policy.blockUnfixed ? 'total' : 'fixable'], 0);
  if (summary.blocking !== expectedBlocking) throw new Error('Inconsistent blocking count');
  for (const finding of summary.findings) {
    if (!severities.includes(finding.severity) || ['id', 'package', 'installed', 'fixed', 'target'].some(key =>
      typeof finding[key] !== 'string' || finding[key].length > (key === 'target' ? 512 : 256))) throw new Error('Invalid finding');
  }
  return summary;
}

export function gateSummary(summary) {
  if (summary.status !== 'complete') throw new Error('Trivy scan failed or is missing; inspect CI logs.');
  if (summary.osEosl) throw new Error('Trivy reports an end-of-life operating system.');
  if (summary.blocking) throw new Error('Trivy policy blocked ' + summary.blocking + ' vulnerability findings.');
}
export function gateTargetSummaries(summary, context) {
  if (summary.schemaVersion !== 3) { validateSummary(summary,context); gateSummary(summary); return; }
  if (summary.profile !== context.profile || summary.summaries?.length !== 2) throw Error('Both architecture scans are required');
  for (const architecture of ['amd64','arm64']) {
    const matches = summary.summaries.filter(s=>s.architecture===architecture);
    if (matches.length !== 1) throw Error('Missing or duplicate architecture scan');
    validateSummary(matches[0],{...context,architecture}); gateSummary(matches[0]);
  }
}

export function verifyScannerArchive(bytes, expected) {
  if (!/^[a-f0-9]{64}$/.test(expected) || createHash('sha256').update(bytes).digest('hex') !== expected) throw new Error('Pinned Trivy archive checksum mismatch.');
}

export async function downloadScannerArchive(policy, architecture, { fetcher = fetch, pause = delay } = {}) {
  validatePolicy(policy);
  const assets = {
    amd64: { suffix: '64bit', checksum: policy.linuxAmd64Sha256 },
    arm64: { suffix: 'ARM64', checksum: policy.linuxArm64Sha256 },
  };
  const asset = Object.hasOwn(assets, architecture) ? assets[architecture] : undefined;
  if (!asset?.checksum) throw new Error('Missing pinned Trivy archive for ' + architecture);
  const url = `https://github.com/aquasecurity/trivy/releases/download/v${policy.version}/trivy_${policy.version}_Linux-${asset.suffix}.tar.gz`;

  for (let attempt = 1; attempt <= 3; attempt++) {
    let archive;
    let failure;
    let retryable = true;
    try {
      const response = await fetcher(url, { signal: AbortSignal.timeout(120000) });
      if (response.ok) {
        archive = Buffer.from(await response.arrayBuffer());
      } else {
        failure = 'HTTP ' + response.status;
        retryable = response.status === 408 || response.status === 429 || response.status >= 500;
        await response.body?.cancel();
      }
    } catch (error) {
      failure ??= error.message;
    }
    if (archive) {
      verifyScannerArchive(archive, asset.checksum);
      return archive;
    }
    if (!retryable || attempt === 3) throw new Error('Cannot download pinned Trivy: ' + failure);
    console.warn(`Pinned Trivy download attempt ${attempt} failed (${failure}). Retrying.`);
    await pause(attempt * 2000);
  }
}

// Render only bounded scalar data, never artifact-supplied Markdown, HTML, links or mentions.
export function escapeCell(value) {
  const escaped = String(value).replace(/[\x00-\x1f\x7f]/g, ' ').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/@/g, '@\u200b').replace(/\|/g, '&#124;').replace(/([\\`*_[\]{}()!~])/g, '\\$1');
  return escaped.length > 240 ? escaped.slice(0, 240).replace(/\\$/, '') + '…' : escaped;
}

export function renderReport(summaries, { runUrl, headSha, runId, runAttempt, conclusion, expectedProfiles = profiles, expectedTargets }) {
  if (!Array.isArray(expectedProfiles) || expectedProfiles.some(p => !profiles.includes(p)) || new Set(expectedProfiles).size !== expectedProfiles.length) throw new Error('Invalid planned scan profiles.');
  if (expectedTargets && (!Array.isArray(expectedTargets) || new Set(expectedTargets).size !== expectedTargets.length || expectedTargets.some(t => !/^(core|aws)\/(amd64|arm64)$/.test(t)))) throw Error('Invalid planned scan architectures');
  const rows = expectedTargets ?? profiles;
  const planned = expectedTargets ?? expectedProfiles;
  if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/actions\/runs\/\d+$/.test(runUrl) || !/^[a-f0-9]{40}$/.test(headSha)) throw new Error('Invalid report link/commit');
  let body = commentMarker + '\n<!-- run-order:' + runId + ':' + runAttempt + ' -->\n## Trivy image vulnerability scan\n\n' +
    'Commit: `' + headSha + '` · [CI run and full JSON artifacts](' + runUrl + ') · CI conclusion: **' + escapeCell(conclusion) + '**\n\n' +
    '| Profile | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | Blocking | Scan |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n';
  for (const profile of rows) {
    if (!planned.includes(profile)) {
      body += '| ' + profile + ' | — | — | — | — | — | — | SKIPPED (no image work planned) |\n';
      continue;
    }
    const summary = summaries[profile];
    if (!summary || summary.status !== 'complete') {
      body += '| ' + profile + ' | — | — | — | — | — | — | **FAILED / missing report** |\n';
      continue;
    }
    body += '| ' + profile + ' | ' + severities.map(s => summary.counts[s].total + ' (' + summary.counts[s].fixable + ' fixable)').join(' | ') +
      ' | ' + summary.blocking + ' | ' + (summary.osEosl ? '**EOL OS**' : 'Complete') + ' |\n';
  }
  body += '\nCounts are deduplicated vulnerability/package/version/target findings. Raw reports retain all findings returned by the scanner.\n';
  if (rows.some(target => summaries[target]?.osCoverage === 'al2023-sbom')) {
    body += '\nAL2023 OS coverage uses the pinned runtime SBOM and the Amazon Linux advisory feed. Unfixed AL2023 vulnerabilities and JVM advisories can be absent from that feed.\n';
  }
  for (const profile of rows) {
    if (!planned.includes(profile)) continue;
    const summary = summaries[profile];
    if (!summary || summary.status !== 'complete') continue;
    body += '\n### ' + profile + '\n\nTrivy ' + summary.scannerVersion + '. Gate: ' + summary.policy.blockingSeverities.join('/') +
      (summary.policy.blockUnfixed ? ', including unfixed findings.' : ' with an available fix.') + '\n\n';
    if (!summary.total) { body += 'No vulnerabilities reported by this scan.\n'; continue; }
    const findings = summary.findings.slice(0, rows.length > 2 ? 10 : maxFindings);
    body += '<details><summary>Top ' + findings.length + ' of ' + summary.total + ' findings (blocking/fixable first)</summary>\n\n' +
      '| Severity | Vulnerability | Package | Installed | Fixed |\n| --- | --- | --- | --- | --- |\n';
    for (const v of findings) {
      const id = /^CVE-\d{4}-\d{4,}$/.test(v.id) ? '[' + v.id + '](https://nvd.nist.gov/vuln/detail/' + v.id + ')' : escapeCell(v.id);
      body += '| ' + v.severity + ' | ' + id + ' | ' + escapeCell(v.package) + ' | ' + escapeCell(v.installed) + ' | ' + escapeCell(v.fixed || 'Not available') + ' |\n';
    }
    body += '\n</details>\n';
  }
  body += '\nThis is CI-reported scan data, not a zero-CVE certification. Scanner/database errors and EOL OS results fail the gate. Public vulnerability data only; no secret scanning output is posted.\n';
  if (body.length > 60000) throw new Error('Report exceeded the comment size limit');
  return body;
}
