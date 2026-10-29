// Append-only corrections to live bindings; original publication records stay intact.
export function parseReleaseEvents(source) {
  const text = source.replaceAll('\r\n','\n');
  if (!text) return [];
  if (!text.endsWith('\n') || text.includes('\r')) throw Error('Release events require complete JSONL lines');
  return text.trimEnd().split('\n').map(line=>JSON.parse(line));
}
export function validateReleaseEvents(events, records) {
  const ids = new Set();
  for (const event of events) {
    const record = records.find(r=>r.plan.tag===event.tag);
    if (event.schemaVersion !== 1 || !record || ids.has(event.id) || !/^[a-z0-9.-]+$/.test(event.id??'') ||
        !['architecture-expansion','withdrawal'].includes(event.operation) || !Number.isSafeInteger(event.issue) || event.issue<1 ||
        !Number.isSafeInteger(event.runId) || event.runId<1 || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(event.recordedAt??'') || !Number.isFinite(Date.parse(event.recordedAt))) throw Error('Invalid release lifecycle event');
    if (event.operation === 'architecture-expansion') {
      if (!/^[a-f0-9]{40}$/.test(event.consumedSourceCommit??'') || event.images?.length!==2) throw Error('Invalid architecture expansion baseline');
      for (const profile of ['core','aws']) {
        const original=record.plan.images.find(i=>i.profile===profile), images=event.images.filter(i=>i.profile===profile), image=images[0];
        if (!original || images.length!==1 || image.tag!==original.tag || image.beforeDigest!==original.digest ||
            !/^sha256:[a-f0-9]{64}$/.test(image.digest??'') || image.children?.length!==2 ||
            image.children.filter(c=>c.architecture==='amd64'&&c.digest===original.digest).length!==1 ||
            image.children.filter(c=>c.architecture==='arm64'&&/^sha256:[a-f0-9]{64}$/.test(c.digest??'')).length!==1) throw Error('Expansion must retain both exact original amd64 children');
      }
    } else if (!Array.isArray(event.tags) || event.tags.length!==record.plan.images.length || record.plan.images.some(i=>!event.tags.includes(i.tag))) throw Error('Withdrawal must identify the exact original tags');
    ids.add(event.id);
  }
  return events;
}
export function activeReleaseRecords(records) {
  const withdrawn = new Set((records.lifecycle??[]).filter(e=>e.operation==='withdrawal').map(e=>e.tag));
  return records.filter(r=>!withdrawn.has(r.plan.tag));
}
export function liveImage(record, image, events=[]) {
  const extension=[...events].reverse().find(e=>e.operation==='architecture-expansion'&&e.tag===record.plan.tag);
  return extension ? {...image,...extension.images.find(i=>i.profile===image.profile),extensionRun:extension.runId} : image;
}
