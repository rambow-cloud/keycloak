export function rambowJavaVersion(reference) {
  const match = /^ghcr\.io\/rambow-cloud\/java:(25)\.(\d+)\.(\d+)-r([1-9]\d*)@sha256:[a-f0-9]{64}$/.exec(reference ?? '');
  if (!match) return null;
  const version = match.slice(1).map(Number);
  return version.every(Number.isSafeInteger) ? version : null;
}

export function compareRuntimeVersions(a, b) {
  for (let index = 0; index < a.length; index++) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return 0;
}

export function sameRuntimeFamily(previous, next) {
  const before = rambowJavaVersion(previous), after = rambowJavaVersion(next);
  if (before || after) return Boolean(before && after && before[1] === after[1] &&
    compareRuntimeVersions(after, before) >= 0 &&
    (previous.split('@')[0] !== next.split('@')[0] || previous === next));
  return previous.split('@')[0] === next.split('@')[0];
}
