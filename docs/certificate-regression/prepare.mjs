import fs from 'node:fs/promises';
import { createHash, X509Certificate } from 'node:crypto';
import tls from 'node:tls';
import { spawnSync } from 'node:child_process';

const dir = '.cache/certificate-regression';
await fs.mkdir(dir, { recursive: true });
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const inputs = [
  ['chains.zip', 'https://emudhra.we-have-a-problem.com/chains.zip', '7b949956955fc501a30f4d98d2f513d34c0bbbe92e29a968194c96e097ce2345'],
  ['roots.json', 'https://emudhra.we-have-a-problem.com/roots.json', '119f32cd81a6b5a4e3c4c2df5fe07daa90dc43cafa123a62f0394f1895d92380'],
];
for (const [name, url, expected] of inputs) {
  const r = await fetch(url, { signal: AbortSignal.timeout(60000) });
  if (!r.ok) throw Error('Fixture download failed: ' + name + ' HTTP ' + r.status);
  const bytes = Buffer.from(await r.arrayBuffer());
  if (hash(bytes) !== expected) throw Error('Fixture checksum mismatch: ' + name);
  await fs.writeFile(dir + '/' + name, bytes);
}
const unzip = spawnSync('unzip', ['-q', dir + '/chains.zip', '-d', dir], { stdio: 'inherit' });
if (unzip.status !== 0) throw Error('Cannot unpack checked fixture archive');
const roots = JSON.parse(await fs.readFile(dir + '/roots.json', 'utf8'));
const restored = ['emSign ECC Root CA - G3', 'AAA Certificate Services'].map(name => {
  const root = roots.find(r => r.name === name);
  if (!root || new X509Certificate(root.pem).fingerprint256.replaceAll(':', '') !== root.sha256) throw Error('Invalid restored-root fixture');
  return root;
});
await fs.writeFile(dir + '/restored-roots.crt', restored.map(r => r.pem).join('\n'));
// Capture public certificates only. A verified TLS connection establishes the
// normal control; all subsequent image PKIX checks run without network access.
const positive = await new Promise((resolve, reject) => {
  const socket = tls.connect({ host: 'github.com', port: 443, servername: 'github.com', rejectUnauthorized: true }, () => {
    try {
      if (!socket.authorized) throw Error('Normal-control TLS capture was not authorized');
      const certs = [], seen = new Set();
      let certificate = socket.getPeerCertificate(true);
      while (certificate?.raw) {
        const sha = hash(certificate.raw); if (seen.has(sha)) break; seen.add(sha);
        certs.push(new X509Certificate(certificate.raw).toString()); certificate = certificate.issuerCertificate;
      }
      if (certs.length < 2) throw Error('Incomplete normal-control chain');
      resolve(certs.join('\n'));
    } catch (error) { reject(error); } finally { socket.destroy(); }
  });
  socket.setTimeout(30000, () => socket.destroy(Error('Normal-control TLS capture timed out')));
  socket.on('error', reject);
});
await fs.writeFile(dir + '/positive.crt', positive);
const files = (await fs.readdir(dir + '/chains')).filter(n => n.endsWith('.pem')).sort();
if (files.length !== 14) throw Error('Expected exactly 14 incident chains');
const chains = await Promise.all(files.map(async name => {
  const pem = await fs.readFile(dir + '/chains/' + name, 'utf8');
  return { name, sha256: hash(pem), pem };
}));
const manifest = { schemaVersion: 1, validationTime: '2026-10-26T12:00:00Z', positiveTime: new Date().toISOString(),
  inputs: inputs.map(([name, url, sha256]) => ({ name, url, sha256 })), restoredRoots: restored,
  positive: { source: 'Verified TLS certificate capture from github.com:443', sha256: hash(positive), pem: positive }, chains };
await fs.writeFile(dir + '/fixtures.json', JSON.stringify(manifest, null, 2) + '\n');
console.log('Pinned 14 incident chains, two restored control roots and a verified normal control.');
