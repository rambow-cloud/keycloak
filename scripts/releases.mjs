import { readFile, writeFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { json, validateAliases, validateCatalog, renderCatalog, resolveTag, tagHistory, imageChanges } from './lib/releases.mjs';
import { validateFragment } from './lib/image-changes.mjs';

const root = fileURLToPath(new URL('../releases/', import.meta.url));
const aliases = validateAliases(JSON.parse(await readFile(resolve(root, 'aliases.json'), 'utf8')));
const records = await Promise.all((await readdir(resolve(root, 'records'))).filter(n => n.endsWith('.json')).sort().map(async name => {
  const record = JSON.parse(await readFile(resolve(root, 'records', name), 'utf8'));
  if (name !== record.plan?.tag + '.json') throw new Error('Record filename does not match release identity.');
  return record;
}));
validateCatalog(records);
const history = Object.fromEntries(await Promise.all((await readdir(resolve(root, 'history'))).filter(n => n.endsWith('.json')).map(async name => {
  const note = JSON.parse(await readFile(resolve(root, 'history', name), 'utf8'));
  if (name !== note.tag + '.json') throw new Error('History filename mismatch.');
  return [note.tag, note];
})));
for (const note of Object.values(history)) {
  const record = records.find(r => r.plan.images.some(i => i.tag === note.tag && !i.changes));
  const image = record?.plan.images.find(i => i.tag === note.tag);
  if (!record) throw new Error('History must supplement an existing legacy image tag.');
  imageChanges(record, image, history);
}
for (const name of (await readdir(resolve(root, '../changes'))).filter(n => n.endsWith('.json'))) {
  validateFragment(JSON.parse(await readFile(resolve(root, '../changes', name), 'utf8')), { allowEmpty: name === 'upstream.json' });
}
const [command, ...args] = process.argv.slice(2);
if (command === 'render') {
  const markdown = renderCatalog(records, history);
  const path = resolve(root, 'README.md');
  if (args.includes('--check')) {
    if (await readFile(path, 'utf8') !== markdown) throw new Error('Release Markdown is stale; run node scripts/releases.mjs render.');
    console.log('Release JSON, alias configuration and generated Markdown are consistent.');
  } else await writeFile(path, markdown);
} else if (command === 'resolve') {
  const tag = args[0];
  const filter = args.indexOf('--release');
  console.log(json(resolveTag(records, tag, filter < 0 ? undefined : args[filter + 1])).trim());
} else if (command === 'history') {
  const tag = args[0];
  console.log(json(records.filter(r => !tag || r.plan.images.some(i => i.tag === tag) || r.plan.aliases.some(a => a.tag === tag))).trim());
} else if (command === 'changes') {
  const entries = tagHistory(records, args[0], history);
  if (!entries.length) throw new Error('No change history for this tag.');
  console.log(json(entries).trim());
} else throw new Error('Usage: node scripts/releases.mjs render [--check] | resolve <tag> [--release <release>] | history [tag] | changes <tag>');
void aliases;
