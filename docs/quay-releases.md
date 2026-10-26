# Formal Quay releases and release catalog

Images are distributed through [quay.io/rambow-cloud/keycloak](https://quay.io/repository/rambow-cloud/keycloak). Normal main and PR CI builds remain artifacts only. The `Quay release` workflow handles stable GitHub Release publication (including promotion to stable) and manual recovery. Both profiles remain Linux amd64, distroless and nonroot. This workflow does not add other registries, architectures, SBOMs or signatures.

## Version and tag contract

Use a GitHub Release tag such as `v26.8.1-r1`. Its Keycloak version must equal the tagged source's `images.lock.json`; the source must belong to protected main history. A later distroless/JDK or provider rebuild uses a higher image revision, such as `v26.8.1-r2`. Do not move a published Git tag to new code or reuse a formal image tag for different bytes.

The registry tags are `26.8.1-r1-core` and `26.8.1-r1-aws`. There is no `latest`, implicit default profile, or version-only moving tag. The workflow refuses to overwrite a formal tag whose digest differs. Deploy by digest; registry administrators must also preserve these bindings when performing out-of-band administration.

Aliases are explicitly reviewed in `releases/aliases.json`, initially empty. For example, a future Issue/PR could add:

```json
{
  "schemaVersion": 1,
  "aliases": [
    {"tag": "extention-v26.8.1", "profile": "aws", "keycloakVersion": "26.8.1"}
  ]
}
```

This example is not enabled. Aliases must specify both profile and Keycloak version, cannot be `latest` or reserved formal tags, and must be unique. After both formal images are published, matching aliases move to that release's profile digest. Previous and new digests are retained in JSON; unexpected out-of-band alias changes fail instead of being silently overwritten.

## Setup

1. Open the Quay repository **Settings** and confirm **Public** visibility. In the `rambow-cloud` organization create a dedicated Robot Account, for example `rambow-cloud+github_actions`, and grant it **Write** on this repository only. Do not use a personal password or organization-wide administrative credential.
2. Open [GitHub Environments](https://github.com/rambow-cloud/keycloak/settings/environments), select `quay-release`, and add `QUAY_USERNAME` and `QUAY_TOKEN` as Environment Secrets. Do not paste the token into chat, Issues or Git. Environment deployment policies allow main for manual recovery and `v*-r*` tags for formal publication.
3. Keep release creation restricted to trusted maintainers. The publisher validates main ancestry before its credential-bearing job; ordinary PR build and scan jobs have no Quay credentials. A separate trusted policy check may revoke unsafe catalog auto-merge.

The implementation's first release is `v26.8.1-r1` if the verified source still uses Keycloak 26.8.1 and that revision is unused. Create the tag/Release only after the publishing workflow is merged and the target main CI has passed. A Release created with the workflow token does not necessarily trigger another workflow: use a maintainer-published Release or the manual recovery entry point. Drafts and prereleases do not upload images.

## Execution and recovery

1. Resolve the real tagged commit, check main ancestry and version lock, and select the newest eligible CI for that exact commit. An existing failed/cancelled run is not replaced by an older success. If OCI artifacts are missing or expired before any publication is frozen, the workflow dispatches read-only CI for that tag and waits. Investigate failed CI before recovering; no blind failed-run retry is performed.
2. Verify both archive checksums, source locks, image labels, profiles and platform. Run current checksum-pinned Trivy with freshly downloaded databases against those exact images. Both gates must pass before any publishing credential is used.
3. Freeze `publication-plan.json` as a GitHub Release asset. It contains source Git/CI/artifact identities, expected image/archive digests, version/revision and alias bindings. A recovery must retain that plan. Expired frozen source artifacts require restoring the original artifacts or a new release revision; the workflow never substitutes a newly rebuilt image into a partially published version.
4. Use native Skopeo with `--preserve-digests` to upload both formal tags, then configured aliases. Exact existing digests are reused. A failure retains partial progress in the publication artifact and a `publication-attempt-<run>-<attempt>.json` Release asset when the audit job can run. Registry operations are not transactional; partial formal tags can exist until recovery completes. Cancelled runners may only leave the frozen plan and available logs/artifacts.
5. Save `publication-record.json` once both images and aliases are published. Open a template-compliant Maintenance Issue and bot PR adding only the JSON record and generated Markdown. Explicitly dispatch required CI/Issue policy and enable native auto-merge only after validating bot ownership, unchanged generated content, the actual diff allowlist and the published Release attachment. The required policy revokes auto-merge for edited/out-of-scope catalog PRs.
6. Wait for catalog merge, verify its contents on main, and attach `publication-complete.json`. Until then the workflow does not report overall success. If main advances or catalog CI fails, published images remain intact; manual recovery refreshes only an untouched bot PR or reports the needed intervention.

Open [Quay release Actions](https://github.com/rambow-cloud/keycloak/actions/workflows/release.yml), choose **Run workflow** on **main**, set `release_tag`, and leave `preview` false to recover an existing stable Release. If images already have a saved publication record, recovery skips downloads, scans and registry writes and only finishes Git recording. Duplicate events for a fully recorded release exit without work. Runs are serialized; after a replaced/cancelled queued event, use this same recovery entry point.

Enable **preview** to inspect and freshly scan an existing successful current-main CI without creating a Release, dispatching a build, freezing assets, accessing Quay Secrets, uploading images or creating catalog PRs. It reports what the selected version would publish; it does not certify registry credentials or write permissions.

## Catalog and queries

`releases/records/<release-tag>.json` is the source of truth for successful publication history. `releases/README.md` is generated from those records and includes profile tags/digests, aliases, timestamps, source/CI/publication links and digest pull commands. Existing records are immutable; failed attempts remain in Actions/Release evidence rather than being advertised as usable catalog entries. The initial directory has no published records.

```sh
node scripts/releases.mjs render
node scripts/releases.mjs render --check
node scripts/releases.mjs resolve 26.8.1-r1-aws
node scripts/releases.mjs history
# Once explicitly configured and published:
node scripts/releases.mjs resolve extention-v26.8.1 --release v26.8.1-r1
node scripts/releases.mjs history extention-v26.8.1
```

CI rejects malformed records, broken alias history, duplicate releases and stale Markdown. Generated-record auto-merge never includes alias configuration, workflow, code, image-lock or existing-record modifications. Human edits stop automatic maintenance rather than being overwritten. Quay credentials never enter the catalog job.

After publication, open the [Quay tag page](https://quay.io/repository/rambow-cloud/keycloak?tab=tags) and verify both formal tags and their displayed digests against the [catalog](../releases/README.md). Use its digest-pinned Podman pull commands on the target deployment network.
