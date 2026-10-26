import { createHash } from 'node:crypto';

export const profiles = ['core', 'aws'];
export const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
export const commentMarker = '<!-- rambow-trivy-report:v1 -->';
export const maxFindings = 20;

export function validatePolicy(policy) {
  if (!/^\d+\.\d+\.\d+$/.test(policy.version) || !/^[a-f0-9]{64}$/.test(policy.linuxAmd64Sha256) ||
      !Array.isArray(policy.blockingSeverities) || !policy.blockingSeverities.length ||
      new Set(policy.blockingSeverities).size !== policy.blockingSeverities.length ||
      policy.blockingSeverities.some(s => !severities.includes(s)) || typeof policy.blockUnfixed !== 'boolean') throw new Error('Invalid Trivy policy');
}

export function summarize(report, { profile, headSha, runId, runAttempt, policy, expectedOS = 'debian' }) {
  validatePolicy(policy);
  if (!profiles.includes(profile) || !/^[a-f0-9]{40}$/.test(headSha) || !Number.isSafeInteger(runId) || !Number.isSafeInteger(runAttempt)) throw new Error('Invalid scan context');
  if (!['debian', 'redhat'].includes(expectedOS)) throw new Error('Unsupported expected OS coverage');
  if (report.SchemaVersion !== 2 || report.ArtifactType !== 'container_image' || !Array.isArray(report.Results) ||
      report.Metadata?.OS?.Family !== expectedOS || !report.Results.some(r => r.Class === 'os-pkgs' && r.Type === expectedOS &&
        (expectedOS !== 'redhat' || r.Packages?.length > 0)) ||
      !report.Results.some(r => r.Class === 'lang-pkgs' && r.Type === 'jar' &&
        (expectedOS !== 'redhat' || r.Packages?.length > 0))) throw new Error('Missing expected ' + expectedOS + ' or Java scan coverage');
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
  return { schemaVersion: 1, profile, headSha, runId, runAttempt, status: 'complete', scannerVersion: policy.version,
    createdAt: report.CreatedAt, policy: { blockingSeverities: policy.blockingSeverities, blockUnfixed: policy.blockUnfixed },
    counts, total: findings.length, blocking, osEosl: report.Metadata.OS.EOSL === true,
    findings: findings.slice(0, maxFindings) };
}

export function validateSummary(summary, { profile, headSha, runId, runAttempt }) {
  if (summary.schemaVersion !== 1 || summary.profile !== profile || summary.headSha !== headSha ||
      summary.runId !== runId || summary.runAttempt !== runAttempt || !['complete', 'error'].includes(summary.status)) throw new Error('Scan summary does not match this run/profile/commit');
  if (summary.status === 'error') return summary;
  if (!/^\d+\.\d+\.\d+$/.test(summary.scannerVersion) || typeof summary.osEosl !== 'boolean') throw new Error('Invalid scanner metadata');
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

export function verifyScannerArchive(bytes, expected) {
  if (!/^[a-f0-9]{64}$/.test(expected) || createHash('sha256').update(bytes).digest('hex') !== expected) throw new Error('Pinned Trivy archive checksum mismatch.');
}

// Render only bounded scalar data, never artifact-supplied Markdown, HTML, links or mentions.
export function escapeCell(value) {
  const escaped = String(value).replace(/[\x00-\x1f\x7f]/g, ' ').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/@/g, '@\u200b').replace(/\|/g, '&#124;').replace(/([\\`*_[\]{}()!~])/g, '\\$1');
  return escaped.length > 240 ? escaped.slice(0, 240).replace(/\\$/, '') + '…' : escaped;
}

export function renderReport(summaries, { runUrl, headSha, runId, runAttempt, conclusion, expectedProfiles = profiles }) {
  if (!Array.isArray(expectedProfiles) || expectedProfiles.some(p => !profiles.includes(p)) || new Set(expectedProfiles).size !== expectedProfiles.length) throw new Error('Invalid planned scan profiles.');
  if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\/actions\/runs\/\d+$/.test(runUrl) || !/^[a-f0-9]{40}$/.test(headSha)) throw new Error('Invalid report link/commit');
  let body = commentMarker + '\n<!-- run-order:' + runId + ':' + runAttempt + ' -->\n## Trivy image vulnerability scan\n\n' +
    'Commit: `' + headSha + '` · [CI run and full JSON artifacts](' + runUrl + ') · CI conclusion: **' + escapeCell(conclusion) + '**\n\n' +
    '| Profile | CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN | Blocking | Scan |\n| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n';
  for (const profile of profiles) {
    if (!expectedProfiles.includes(profile)) {
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
  body += '\nCounts are deduplicated vulnerability/package/version/target findings, not unique CVE IDs. All severities and unfixed findings remain in the JSON artifacts.\n';
  for (const profile of profiles) {
    if (!expectedProfiles.includes(profile)) continue;
    const summary = summaries[profile];
    if (!summary || summary.status !== 'complete') continue;
    body += '\n### ' + profile + '\n\nTrivy ' + summary.scannerVersion + '. Gate: ' + summary.policy.blockingSeverities.join('/') +
      (summary.policy.blockUnfixed ? ', including unfixed findings.' : ' with an available fix.') + '\n\n';
    if (!summary.total) { body += 'No vulnerabilities reported by this scan.\n'; continue; }
    body += '<details><summary>Top ' + summary.findings.length + ' of ' + summary.total + ' findings (blocking/fixable first)</summary>\n\n' +
      '| Severity | Vulnerability | Package | Installed | Fixed |\n| --- | --- | --- | --- | --- |\n';
    for (const v of summary.findings) {
      const id = /^CVE-\d{4}-\d{4,}$/.test(v.id) ? '[' + v.id + '](https://nvd.nist.gov/vuln/detail/' + v.id + ')' : escapeCell(v.id);
      body += '| ' + v.severity + ' | ' + id + ' | ' + escapeCell(v.package) + ' | ' + escapeCell(v.installed) + ' | ' + escapeCell(v.fixed || 'Not available') + ' |\n';
    }
    body += '\n</details>\n';
  }
  body += '\nThis is CI-reported scan data, not a zero-CVE certification. Scanner/database errors and EOL OS results fail the gate. Public vulnerability data only; no secret scanning output is posted.\n';
  if (body.length > 60000) throw new Error('Report exceeded the comment size limit');
  return body;
}
