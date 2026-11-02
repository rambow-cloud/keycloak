# Image work and per-tag history

A reviewed new feature, repair naming explicit CVE IDs, or same-family distroless `runtime-update` with changed before/after pins and complete native paired evidence authorizes a new image revision. Ordinary bugs, builder/version/dependency maintenance and validation changes alone do not. Decisions remain independent for core/aws. Runtime updates explicitly report a no-observed-CVE-fix outcome when applicable; see [distroless update automation](distroless-updates.md). Architecture coverage extends an existing release while preserving its original children. See [release eligibility and architecture coverage](release-eligibility.md).

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

Use `fix` for reviewed CVE repairs, `feature` for new behavior, `runtime-update` for the bounded distroless exception, and `maintenance` for other routine updates. A runtime fragment declares explicit `runtime.from` per profile and `runtime.to`, with changed pins in the same reviewed family. Its native comparison, not its digest alone, determines any CVE repairs. Existing-version architecture expansion uses `release: false`. Summaries are substantive single-line English text. Empty lists, placeholders, absent Issue references and implicit profiles are rejected. Each local Issue follows its form and has a standalone `Closes #N` PR line. Reviewed runtime fragments are append-only. The generic updater owns `changes/upstream.json` and emits maintenance descriptions.

## Publication

Before CI lookup or dispatch, release preparation compares each profile's build-input fingerprint with its own last published baseline. Source Git labels, documentation and catalog commits do not count as new image bits. If neither profile changed, the Release is a successful no-op: no build dispatch, artifact download, scan, freeze, OIDC, Quay push or record PR. Notes and alias-only configuration cannot force unchanged-image publication. Aliases for unaffected profiles wait for a real profile update.

Changed profiles require applicable new feature/CVE/runtime fragments since their effective published baseline before CI artifact lookup or dispatch. Runtime pins must match the actual published/source runtime inputs. Other maintenance-only inputs are a publication no-op. Existing-version architecture events consume their applied source baseline so the same platform addition is not published as a new revision. Frozen plans retain nonempty reviewed changes and the runtime comparison hash when applicable; only selected profiles need release artifacts/scans/publication. Changed aliases inherit that profile's history. Frozen retries preserve notes and bytes; legacy recovery remains compatible.

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
