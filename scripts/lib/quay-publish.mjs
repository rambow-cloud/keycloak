import { registry, profiles, validatePlan, validateRecord, destinationAction } from './releases.mjs';

// Registry adapter never receives a tag from an unvalidated release or implicit profile selection.
export async function publishImages(plan, adapter, { runId, validationToolsCommit = plan.toolsCommit, now = () => new Date().toISOString(), progress = () => {} }) {
  validatePlan(plan);
  const state = { schemaVersion: 1, tag: plan.tag, status: 'publishing', completedTags: [], runId };
  const inspect = tag => adapter.inspect(registry + ':' + tag);
  try {
    const actions = {};
    // Detect every immutable conflict before making any registry changes.
    for (const image of plan.images) actions[image.profile] = destinationAction(await inspect(image.tag), image.digest);
    for (const profile of profiles) {
      const image = plan.images.find(i => i.profile === profile);
      if (actions[profile] === 'copy') {
        const copied = await adapter.copy(image, registry + ':' + image.tag);
        if (copied !== image.digest) throw new Error('Registry copy changed the frozen digest.');
      }
      state.completedTags.push(image.tag);
      progress({ ...state });
    }
    const aliasChanges = [];
    // Mutable aliases are not touched until both canonical image tags are present.
    for (const alias of plan.aliases) {
      const image = plan.images.find(i => i.profile === alias.profile);
      const current = await inspect(alias.tag);
      const previous = plan.previousAliases[alias.tag];
      if (current !== previous && current !== image.digest) throw new Error('Alias changed outside recorded history: ' + alias.tag);
      if (destinationAction(current, image.digest, true) === 'copy') {
        if (await adapter.copy(image, registry + ':' + alias.tag) !== image.digest) throw new Error('Alias copy changed digest.');
      }
      aliasChanges.push({ tag: alias.tag, profile: alias.profile, fromDigest: previous, toDigest: image.digest });
      state.completedTags.push(alias.tag);
      progress({ ...state });
    }
    const record = validateRecord({ schemaVersion: 1, status: 'published', publishedAt: now(), publishRunId: runId, validationToolsCommit, plan, aliasChanges });
    progress({ ...state, status: 'published' });
    return record;
  } catch (error) {
    progress({ ...state, status: state.completedTags.length ? 'partial' : 'failed', error: error.message });
    throw error;
  }
}
