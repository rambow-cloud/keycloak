const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFile } = require('node:fs/promises');
const lib = import('../docs/security/ledger.mjs');
const digest = 'sha256:' + 'a'.repeat(64);
const image = { profile: 'aws', tag: '26.8.1-r1-aws', digest };
const record = () => ({ schemaVersion: 1, id: 'SEC-2026-001', recordedAt: '2026-10-26T12:00:00.000Z', kind: 'fix', status: 'fixed-before-publication',
  advisories: ['CVE-2026-12345'], summary: 'Repair a vulnerable component before its first publication.', details: ['Pinned a compatible patched component.'],
  issues: [13], pullRequests: [12], images: [image], references: [{label:'Reviewed repair',url:'https://github.com/rambow-cloud/keycloak/issues/13'}], evidence: [] });
test('JSONL rejects missing/partial records and append-only history preserves original lines', async () => {
  const { parseLedger, assertAppendOnly } = await lib;
  const original = JSON.stringify(record()) + '\n';
  assert.equal(parseLedger(original).length, 1);
  for (const source of ['', original.trimEnd(), original+'\n', '\uFEFF'+original, '{bad}\n']) assert.throws(() => parseLedger(source));
  assertAppendOnly(original, original + JSON.stringify({...record(),id:'SEC-2026-002'})+'\n');
  assertAppendOnly(original.replaceAll('\n','\r\n'),original);
  for (const source of ['', original.replace('Repair','Conceal'), ' '+original]) assert.throws(() => assertAppendOnly(original,source));
});
test('records require accurate published scope, safe references, evidence and explicit correction history', async () => {
  const { validateRecords } = await lib;
  validateRecords([record()],[image]);
  const mutations = [{images:[{...image,digest:'sha256:'+'b'.repeat(64)}]}, {images:[{...image,profile:'core'}]}, {images:[]}, {advisories:['unknown']},
    {issues:[]},{references:[{label:'unsafe',url:'javascript:alert(1)'}]},{evidence:[{label:'Escape',path:'../secret.json',sha256:'a'.repeat(64)}]},
    {kind:'verification',status:'verified-existing'},{supersedes:'SEC-2026-999',kind:'correction'}, {unknown:'field'}];
  for (const patch of mutations) assert.throws(() => validateRecords([{...record(),...patch}],[image]));
  assert.throws(() => validateRecords([record(),record()],[image]));
  const correction = {...record(),id:'SEC-2026-002',kind:'correction',status:'retracted',supersedes:'SEC-2026-001'};
  validateRecords([record(),correction],[image]);
});
test('rendering and queries retain per-image history and visibly link corrections', async () => {
  const { query, render } = await lib;
  const first = record(); first.summary += ' Pipe | and @mention.';
  const second = {...record(),id:'SEC-2026-002',kind:'correction',status:'under-review',supersedes:first.id};
  const rows=[first,second]; const markdown=render(rows);
  assert.equal(query(rows,first.advisories[0]).length,2);
  assert.equal(query(rows,image.tag).length,2);
  assert.equal(query(rows,image.digest).length,2);
  assert.equal(query(rows,'unknown').length,0);
  assert.match(markdown,/Later corrections/); assert.match(markdown,/&#124;/); assert.equal(markdown.includes('@mention'),false);
  assert.equal(markdown,render(rows));
});
test('repository ledger, durable evidence, generated page and PR baseline are consistent', async () => {
  const { readLedger, render, directory, checkBaseline } = await lib;
  const { records, source } = await readLedger();
  assert.equal(await readFile(directory+'/README.md','utf8'),render(records));
  let base='origin/main';
  if(process.env.GITHUB_EVENT_PATH){const event=JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH,'utf8'));base=event.pull_request?.base?.sha ?? (/^[a-f0-9]{40}$/.test(event.before??'') && !/^0+$/.test(event.before) ? event.before : base);}
  checkBaseline(base,source);
});
