export const architectures = ['amd64', 'arm64'];
export function lockArchitectures(lock) {
  if (!lock.platforms) {
    if (lock.platform !== 'linux/amd64') throw Error('Unsupported legacy image platform');
    return ['amd64'];
  }
  if (lock.platform !== undefined || !Array.isArray(lock.platforms) || lock.platforms.length !== 2 ||
      lock.platforms.some((p, n) => p !== 'linux/' + architectures[n])) throw Error('Expected explicit linux/amd64 and linux/arm64 platforms');
  return architectures;
}
export function nativeArchitecture(arch = process.arch) {
  const result = { x64: 'amd64', arm64: 'arm64' }[arch];
  if (!result) throw Error('Native Linux amd64 or arm64 is required');
  return result;
}
export function assertBasePlatforms(manifest, expected = architectures) {
  if (manifest.schemaVersion !== 2 || !Array.isArray(manifest.manifests) || expected.some(architecture =>
    manifest.manifests.filter(m => m.platform?.os === 'linux' && m.platform.architecture === architecture &&
      (!m.platform.variant || m.platform.variant === 'v8') && /^sha256:[a-f0-9]{64}$/.test(m.digest)).length !== 1)) throw Error('Pinned base index does not uniquely cover all required Linux architectures');
}
