const { test } = require('node:test');
const assert = require('node:assert/strict');
const lib = import('../docs/experiments/ubi10-grype/compare.mjs');
const db = { status: 'valid', built: '2026-10-29T00:00:00Z', schemaVersion: '6.0.0', checksum: 'test-checksum' };
function fixture() {
  return { scan: { distro: { name: 'redhat', version: '10.2' }, descriptor: { name: 'grype', version: '0.121.0', db }, matches: [] },
    inventory: { distro: { id: 'rhel', versionID: '10.2' }, artifacts: [
      { name: 'glibc', version: '2.39', type: 'rpm' },
      { name: 'java-25-openjdk-headless', version: '25.0.4.1', type: 'rpm' },
      { name: 'guava', version: '33.7.2-jre', type: 'java-archive', locations: [{ path: '/opt/keycloak/lib/lib/main/com.google.guava.guava-33.6.0-jre.jar' }] },
    ] } };
}
test('RHEL 10 coverage needs the actual OS, live DB and both RPM/application inventories', async () => {
  const { summarize } = await lib;
  const f = fixture();
  const summary = summarize(f.scan, f.inventory, 'ubi10');
  assert.equal(summary.status, 'complete');
  assert.equal(summary.inventory.jvm[0].name, 'java-25-openjdk-headless');
  for (const change of [
    f => { f.inventory.distro.versionID = '9.8'; },
    f => { f.scan.distro.name = 'debian'; },
    f => { f.scan.descriptor.db = { status: 'invalid' }; },
    f => { f.inventory.artifacts = f.inventory.artifacts.filter(p => p.type !== 'rpm'); },
    f => { f.inventory.artifacts = f.inventory.artifacts.filter(p => p.type !== 'java-archive'); },
    f => { f.inventory.artifacts.at(-1).version = '33.6.0-jre'; },
  ]) { const input = fixture(); change(input); assert.equal(summarize(input.scan, input.inventory, 'ubi10').status, 'coverage-failed'); }
});
test('all severities/unfixed matches are retained; only fixable HIGH/CRITICAL block', async () => {
  const { summarize } = await lib;
  const f = fixture();
  f.scan.matches = [
    { vulnerability: { id: 'CVE-2026-10000', severity: 'High', fix: { state: 'fixed', versions: ['2.40'] } }, artifact: { name: 'glibc', version: '2.39', type: 'rpm' } },
    { vulnerability: { id: 'CVE-2026-10001', severity: 'Critical', fix: { state: 'not-fixed', versions: [] } }, artifact: { name: 'glibc', version: '2.39', type: 'rpm' } },
    { vulnerability: { id: 'CVE-2026-10002', severity: 'Medium', fix: { state: 'fixed', versions: ['2.40'] } }, artifact: { name: 'glibc', version: '2.39', type: 'rpm' } },
  ];
  const result = summarize(f.scan, f.inventory, 'ubi10');
  assert.equal(result.total, 3); assert.equal(result.blocking, 1);
  assert.equal(result.counts.CRITICAL.total, 1); assert.equal(result.counts.MEDIUM.fixable, 1);
});
test('Guava controls recognize both direct and related advisory identifiers', async () => {
  const { isGuavaFinding, summarize } = await lib;
  assert.equal(isGuavaFinding({ vulnerability: { id: 'GHSA-xxph-c9ww-hj94' } }), true);
  assert.equal(isGuavaFinding({ vulnerability: { id: 'other' }, relatedVulnerabilities: [{ id: 'CVE-2026-102554' }] }), true);
  assert.equal(isGuavaFinding({ vulnerability: { id: 'unrelated' } }), false);
  const f = fixture(); f.scan.matches = [{ vulnerability: { id: 'CVE-2026-102554', severity: 'High' }, artifact: { name: 'guava', type: 'java-archive' } }];
  assert.match(summarize(f.scan, f.inventory, 'ubi10').errors.join(), /Guava defect/);
});
test('failed candidates render as unknown rather than zero findings', async () => {
  const { render } = await lib;
  const text = render([{ runtime: 'ubi10', profile: 'core', status: 'failed' }]);
  assert.match(text, /unknown/); assert.match(text, /failed/); assert.doesNotMatch(text, /\| 0 \/ 0 \|/);
});
