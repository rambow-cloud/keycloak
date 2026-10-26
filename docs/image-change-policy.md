# Image work and per-tag history

No image fix or feature means no new image publication. Decisions are independent for core/aws: an AWS-only dependency fix builds/publishes AWS and leaves the existing core tag/digest unchanged. Releases may contain one profile; the catalog lists the tags actually published.

## CI

Static checks, Issue policy and the required `Build and verify` aggregate remain enabled. `Image impact` compares complete Git snapshots and semantic image-lock fields. Documentation, catalog/history, change fragments, release authentication, catalog bookkeeping and unit-test-only changes skip container jobs. Unknown files are conservative. Runtime/build/scanner/CI validation changes still test affected images, although validation-only work does not justify a new image release. Failed or missing classification cannot produce a successful skipped aggregate.

Shared Containerfile/Java/build inputs affect both profiles. AWS provider locks and download code affect AWS only. The PostgreSQL test-image lock affects validation, but not publication fingerprints. Every selected image retains runtime checks and current Trivy gates. PR comments distinguish deliberately unbuilt profiles from required missing/failed scans.

## Reviewed changes

Every actual image fix/feature adds a fragment such as `changes/35-rds-retry.json` through its Issue/PR:

```json
{
  "schemaVersion": 1,
  "changes": [{
    "type": "fix",
    "summary": "Correct the RDS connection retry behavior after a temporary database failover.",
    "issues": [35],
    "profiles": ["aws"]
  }]
}
```

Use `fix` for bugs, security remediation and dependency/runtime fixes; use `feature` for new behavior. Summaries are substantive single-line English text. Empty lists, placeholders, absent Issue references and implicit profiles are rejected. Each local Issue must follow its form and have a standalone `Closes #N` PR line. Reviewed fragments are append-only. The updater owns `changes/upstream.json`, adding concrete old/new input descriptions and its Maintenance Issue when inputs change. Its initially empty fragment describes no update and cannot authorize a release.

## Publication

Before CI lookup or dispatch, release preparation compares each profile's build-input fingerprint with its own last published baseline. Source Git labels, documentation and catalog commits do not count as new image bits. If neither profile changed, the Release is a successful no-op: no build dispatch, artifact download, scan, freeze, OIDC, Quay push or record PR. Notes and alias-only configuration cannot force unchanged-image publication. Aliases for unaffected profiles wait for a real profile update.

Changed profiles require applicable new fragments since their own published source. A schema-2 plan freezes each input fingerprint and nonempty typed change history. Only those profiles need exact-source CI artifacts, fresh scans and Skopeo publication. Changed aliases inherit that profile's history alongside their old/new digest. Frozen retries preserve the same notes and bits; legacy recovery remains compatible.

The first `26.8.1-r1-core` and `26.8.1-r1-aws` records predate this schema. Separate append-only `releases/history/<image-tag>.json` notes document their original features/fixes with Issue references. They supplement the catalog without altering original publication JSON, Release assets or digests. Future plans embed their own notes.

JSON deterministically generates a nonempty section for every image tag and alias binding in `releases/README.md`. CI rejects missing history. Query a tag's own updates with:

```sh
node scripts/releases.mjs changes 26.8.1-r1-core
node scripts/releases.mjs changes 26.8.1-r1-aws
node scripts/releases.mjs render --check
```

Main updates never push images. Formal Releases and explicit recovery remain the only publishing entries. Never invent a revision for documentation, CI bookkeeping or a no-op rebuild.

## Verified no-op behavior

[Implementation CI](https://github.com/rambow-cloud/keycloak/actions/runs/40278196763) verified both profiles, including PostgreSQL runtime checks and Trivy, before the planning changes merged. Validation-policy changes deliberately retain these image checks.

[Unchanged release preview](https://github.com/rambow-cloud/keycloak/actions/runs/40279952866) succeeded with only preparation running. Artifact scanning, plan freezing, Quay publication, catalog recording and audit were skipped. The preview did not create a Git tag, GitHub Release or image tag; `v26.8.1-r2` was only a candidate input to the read-only preview.

Documentation-only PRs retain Issue policy, static checks and the required aggregate. Their Trivy comments explicitly report that no image work was planned; skipped profiles are never described as clean scans.
