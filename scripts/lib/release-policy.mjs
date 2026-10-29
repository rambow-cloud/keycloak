export function eligibleRevisionChange(change) {
  return change.release !== false && (change.type === 'feature' || change.type === 'fix' && Array.isArray(change.cves) && change.cves.length > 0 &&
    change.cves.every(id=>/^CVE-\d{4}-\d{4,}$/.test(id)));
}
export function revisionChanges(changes) { return changes.filter(eligibleRevisionChange); }
