# Revision eligibility and architecture coverage

Building and validating a candidate does not authorize a new public image revision.

| Reviewed change | Native CI | New revision |
| --- | --- | --- |
| New feature | Affected profiles | Eligible |
| CVE repair with explicit CVE IDs | Affected profiles | Eligible |
| Ordinary bug fix | Affected profiles | Not a release trigger |
| Builder, dependency or base-image maintenance without an identified CVE repair | Affected input validation | Not a release trigger |
| CI, scanner or runtime-test changes | Relevant validation | Not a release trigger |
| Documentation/catalog changes | Static checks | Not a release trigger |
| Missing architecture on an existing version | Build only the missing architecture; rescan existing children | Extend existing tags; no revision increment |

A CVE repair fragment uses `type: "fix"` and `cves: ["CVE-YYYY-NNNN"]`, plus its substantive summary, profiles and local Issues. A feature uses `type: "feature"`. All referenced Issues still require standalone PR closing lines. Ordinary `fix` notes remain usable for reviewed history but cannot trigger publication alone. When a release is eligible, its notes retain other reviewed fixes actually delivered with it.

The updater emits `maintenance` notes for detected upstream versions/digests. A version bump or builder hash is not evidence of a new feature or repaired CVE. A maintainer must add the reviewed feature/CVE declaration before a revision is eligible. Updating source versions must not rewrite the homepage's actually published tags.

An existing-release architecture extension uses `release: false` in its feature note. It preserves the original payload/base/provider pins and existing architecture manifests, builds only missing architectures, and freshly scans every child before protected publication. Its bounded migration accepts only the reviewed old digest or its own frozen replacement index. It does not make the general publisher mutable.

Original `releases/records/*.json` and security JSONL remain unchanged. Architecture bindings and withdrawals are appended to `releases/events.jsonl`, checked against protected Release evidence, and projected into the generated catalog, digest resolver and change history. Withdrawn releases remain in historical Git data but are excluded from active resolution. The event's consumed source baseline prevents an already-applied architecture feature from triggering another revision.

The reviewed r2 migration is implemented by `R2 architecture migration`: PR runs are read-only; only main workflow dispatch may freeze and publish through `quay-release`. Frozen retries use the original run/attempt's package and never rebuild substitute bytes. r3 facts are archived under `releases/archives/v26.8.1-r3/` before its live release and tags are withdrawn. The final live bindings and their evidence are recorded after execution; implementation alone is not a publication claim.
