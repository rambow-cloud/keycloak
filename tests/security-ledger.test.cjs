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
  const { query, renderHistory: render } = await lib;
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

test('candidate fixes label published images as affected until publication evidence is appended', async () => {
  const { validateRecords, renderHistory: render } = await lib;
  const pending = { ...record(), status: 'pending-publication' };
  validateRecords([pending], [image]);
  assert.match(render([pending]), /Fix pending publication; listed images are affected/);
  assert.throws(() => validateRecords([{ ...pending, kind: 'verification' }], [image]), /kind\/status/);
});
test('repository ledger, durable evidence, generated page and PR baseline are consistent', async () => {
  const { readLedger, render, renderHistory, directory, checkBaseline } = await lib;
  const { records, source, notes, publications } = await readLedger();
  assert.equal(await readFile(directory+'/README.md','utf8'),render(records,notes,publications));
  assert.equal(await readFile(directory+'/history.md','utf8'),renderHistory(records));
  let base='origin/main';
  if(process.env.GITHUB_EVENT_PATH){const event=JSON.parse(await readFile(process.env.GITHUB_EVENT_PATH,'utf8'));base=event.pull_request?.base?.sha ?? (/^[a-f0-9]{40}$/.test(event.before??'') && !/^0+$/.test(event.before) ? event.before : base);}
  checkBaseline(base,source);
});

test('release notes order versions numerically and report only newly published repairs with their profiles', async () => {
  const { render } = await lib;
  const first = record();
  const pending = {...record(),id:'SEC-2026-002',status:'pending-publication'};
  const secondImage = {...image,tag:'26.8.1-r2-core',profile:'core'};
  const second = {...record(),id:'SEC-2026-003',kind:'correction',supersedes:pending.id,images:[secondImage]};
  const tenthImage = {...image,tag:'26.8.1-r10-aws'};
  const tenth = {...record(),id:'SEC-2026-004',images:[tenthImage]};
  const verification = {...record(),id:'SEC-2026-005',kind:'verification',status:'verified-existing'};
  const records = [first,pending,second,tenth,verification];
  const publications = [first,second,tenth].map(r => ({status:'published',plan:{tag:'v'+r.images[0].tag.replace(/-(core|aws)$/,''),images:r.images}}));
  const notes = {schemaVersion:1,notes:[first,second,tenth].map(r=>({release:publications.find(p=>p.plan.images===r.images).plan.tag,record:r.id,fixes:[{advisory:r.advisories[0],summary:r.summary}]}))};
  const md = render(records,notes,publications);
  assert.ok(md.indexOf('## v26.8.1-r10') < md.indexOf('## v26.8.1-r2'));
  assert.ok(md.indexOf('## v26.8.1-r2') < md.indexOf('## v26.8.1-r1\n'));
  const r2 = md.split('## v26.8.1-r2\n')[1].split('## v26.8.1-r1\n')[0];
  assert.match(r2,/\(`core`\)/); assert.doesNotMatch(r2,/`aws`/);
  assert.match(md,/history.md#sec-2026-003/);
  for (const r of records) assert.ok(md.includes('id="'+r.id.toLowerCase()+'"'));
  assert.doesNotMatch(md,/pending publication|Existing images verified|sha256:/);
  assert.equal(md,render(records,{...notes,notes:[...notes.notes].reverse()},publications));
});

test('notes reject false publication scope, superseded repairs, incomplete CVEs and missing published fixes', async () => {
  const { validateNotes } = await lib;
  const repaired = record();
  const publication = {status:'published',plan:{tag:'v26.8.1-r1',images:[image]}};
  const note = {release:publication.plan.tag,record:repaired.id,fixes:[{advisory:repaired.advisories[0],summary:repaired.summary}]};
  const document = {schemaVersion:1,notes:[note]};
  validateNotes([repaired],document,[publication]);
  for (const status of ['pending-publication','verified-existing','under-review','retracted']) {
    assert.throws(()=>validateNotes([{...repaired,status}],document,[publication]));
  }
  assert.throws(()=>validateNotes([repaired],document,[{...publication,status:'planned'}]));
  assert.throws(()=>validateNotes([repaired],document,[{...publication,plan:{...publication.plan,images:[{...image,digest:'sha256:'+'b'.repeat(64)}]}}]));
  assert.throws(()=>validateNotes([repaired],{...document,notes:[{...note,release:'v26.8.1-r2'}]},[publication]));
  assert.throws(()=>validateNotes([repaired],{...document,notes:[note,note]},[publication]));
  assert.throws(()=>validateNotes([repaired],{...document,notes:[]},[publication]));
  assert.throws(()=>validateNotes([{...repaired,advisories:[...repaired.advisories,'CVE-2026-99999']}],document,[publication]));
  assert.throws(()=>validateNotes([repaired],{...document,notes:[{...note,fixes:[{...note.fixes[0],advisory:'CVE-2026-99999'}]}]},[publication]));
  const correction = {...repaired,id:'SEC-2026-002',kind:'correction',status:'retracted',supersedes:repaired.id};
  assert.throws(()=>validateNotes([repaired,correction],document,[publication]));
});
