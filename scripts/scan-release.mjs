import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { lockArchitectures } from './lib/platforms.mjs';
import { validateSummary, gateSummary } from './lib/trivy.mjs';
const [preparedPath, layout, output] = process.argv.slice(2);
const prepared = JSON.parse(await readFile(preparedPath,'utf8'));
const profile = process.env.BUILD_PROFILE;
const targets = lockArchitectures(prepared.imageLock);
const summaries = [];
let failed = false;
for (const architecture of targets) {
  const destination = resolve(output, architecture);
  await mkdir(destination,{recursive:true});
  const selected = resolve(output, architecture+'-layout');
  const copy = spawnSync('skopeo',['--override-os','linux','--override-arch',architecture,'copy','--preserve-digests','oci:'+resolve(layout),'oci:'+selected+':scan'],{stdio:'inherit',timeout:600000});
  if (copy.status !== 0) throw Error('Cannot select release architecture for scan');
  const env = {...process.env};
  if (prepared.imageLock.platforms) env.BUILD_ARCH = architecture;
  else delete env.BUILD_ARCH;
  const scan = spawnSync(process.execPath,[fileURLToPath(new URL('./scan-image.mjs',import.meta.url)),selected,destination],{stdio:'inherit',env,timeout:900000});
  const summary = JSON.parse(await readFile(join(destination,'summary.json'),'utf8'));
  validateSummary(summary,{profile,architecture:env.BUILD_ARCH,headSha:process.env.SCAN_HEAD_SHA,runId:Number(process.env.GITHUB_RUN_ID),runAttempt:Number(process.env.GITHUB_RUN_ATTEMPT)});
  summaries.push(summary);
  try { if (scan.status !== 0) throw Error('Scanner failed'); gateSummary(summary); }
  catch { failed = true; }
}
await writeFile(resolve(output,'summary.json'),JSON.stringify(prepared.imageLock.platforms ? {schemaVersion:3,profile,summaries} : summaries[0],null,2)+'\n');
if (failed) throw Error('One or more architecture scans failed the release gate');
