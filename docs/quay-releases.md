# Formal Quay releases and release catalog

Images are distributed through [quay.io/rambow-cloud/keycloak](https://quay.io/repository/rambow-cloud/keycloak). Normal main and PR CI builds remain artifacts only. The `Quay release` workflow handles stable GitHub Release publication (including promotion to stable) and manual recovery. New revisions package Linux amd64/arm64 OCI indexes per profile; historical r1/r2 stay amd64-only. Both remain distroless and nonroot. See [architecture contracts and native validation](architectures.md). Other registries, SBOMs and signatures remain outside this workflow.

Publication is gated independently per profile by actual build-input changes and nonempty reviewed fix/feature notes. A release may publish only AWS while retaining core's previous tag. With no changed inputs, the workflow skips all image work before CI dispatch or credentials. See [image work and per-tag history](image-change-policy.md).

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

This example is not enabled. Aliases must specify both profile and Keycloak version, cannot be `latest` or reserved formal tags, and must be unique. After all selected formal images are published, their matching aliases move to the corresponding digest and record nonempty inherited changes. Aliases for unaffected profiles remain unchanged. Previous and new digests are retained in JSON; unexpected out-of-band alias changes fail instead of being silently overwritten.

## Setup

1. Open the Quay repository **Settings** and confirm **Public** visibility. Use the dedicated organization Robot Account `rambow-cloud+github_keycloak` and grant it **Write** on this repository only. Do not use a personal password or organization-wide administrative credential.
2. In **Organizations > rambow-cloud > Robot Accounts**, open the robot's **Set robot federation** menu and configure the exact values below. Do not use a main-branch subject: the publisher references the `quay-release` Environment, so GitHub includes that environment in its subject.

   | Field | Value |
   | --- | --- |
   | Issuer URL | `https://token.actions.githubusercontent.com` |
   | Subject | `repo:rambow-cloud@333554680/keycloak@1433566126:environment:quay-release` |
   | OIDC audience | `https://quay.io` |

   The prefix was obtained from this repository's GitHub OIDC configuration with immutable owner/repository IDs. Repository transfers, renames or OIDC claim changes require a reviewed update of both this binding and `scripts/lib/quay-auth.mjs`.
3. Open [GitHub Environments](https://github.com/rambow-cloud/keycloak/settings/environments), select `quay-release`, and add the **Environment variable** `QUAY_USERNAME=rambow-cloud+github_keycloak`. It is not a secret. Do not add `QUAY_TOKEN`: static-token fallback is disabled. Environment deployment policies allow main for manual recovery and `v*-r*` tags for formal publication; preserve those restrictions because the environment subject itself does not include the branch/tag.
4. Keep release creation restricted to trusted maintainers. Only the protected publisher has `id-token: write`. After all selected-profile scans, the frozen plan and local artifact verification, it explicitly requests `core.getIDToken('https://quay.io')`, validates the expected issuer/subject/audience/run context locally, and exchanges the signed token at `https://quay.io/oauth2/federation/robot/token`. Quay verifies the identity and returns a short-lived robot credential, used only in memory and the temporary Skopeo auth file (removed afterward). Both tokens are masked; they are never saved in GitHub outputs, environment files, publication artifacts or Release assets. Exchange errors/redirects stop publication with sanitized messages and no automatic token retries. Ordinary build, scan, preview and catalog jobs cannot request OIDC or receive Quay credentials.

See [Quay keyless authentication](https://developers.redhat.com/articles/2026/07/22/push-images-to-quay-without-a-password), [Quay audience validation](https://docs.projectquay.io/manage_quay.html#configuring-federation-audiences), and [GitHub OIDC subject rules](https://docs.github.com/en/actions/reference/security/oidc). The configured audience is an explicit project contract; GitHub's default audience is not used.

The implementation's first release is `v26.8.1-r1` if the verified source still uses Keycloak 26.8.1 and that revision is unused. Create the tag/Release only after the publishing workflow is merged and the target main CI has passed. A Release created with the workflow token does not necessarily trigger another workflow: use a maintainer-published Release or the manual recovery entry point. Drafts and prereleases do not upload images.

## Execution and recovery

1. Resolve the real tagged commit, check main ancestry/version lock, and compare each profile's inputs with its last publication. Exclude unchanged profiles; if none changed, stop successfully before CI/artifacts/scans/credentials. Changed profiles require reviewed nonempty fix/feature fragments. Then select the newest eligible exact-commit CI. Never replace a failed/cancelled source CI with an older success. Missing/expired unfrozen artifacts cause one read-only tag CI dispatch, which builds only affected profiles.
2. Verify every selected archive checksum, source lock, image label, profile and platform. Run current checksum-pinned Trivy with fresh databases against those exact images. All selected gates must pass before any publishing credential is used.
3. Freeze `publication-plan.json` as a Release asset. Schema 2 includes selected profile fingerprints and nonempty per-tag changes, in addition to Git/CI/artifact identities, expected digests, revision and aliases. Recovery retains the plan. Expired frozen inputs require restoring identical artifacts or a new revision; never substitute rebuilt bits into a partial publication.
4. Use Skopeo `--preserve-digests` for all selected formal tags, then their configured aliases. Exact existing digests are reused. Failed attempts retain partial state in the publication artifact and `publication-attempt-<run>-<attempt>.json` when audit can run. Registry operations are not transactional; recovery fills missing tags without replacing existing ones.
5. Save `publication-record.json` once all selected images and aliases are published. Open a compliant Maintenance Issue and bot PR adding only that JSON and generated Markdown. Metadata-only catalog CI skips container builds while required static/Issue/aggregate checks remain mandatory. Auto-merge requires unchanged bot ownership, the actual two-file allowlist and exact Release facts; human edits revoke it.
6. Wait for catalog merge, verify its contents on main, and attach `publication-complete.json`. Until then the workflow does not report overall success. If main advances or catalog CI fails, published images remain intact; manual recovery refreshes only an untouched bot PR or reports the needed intervention.

Open [Quay release Actions](https://github.com/rambow-cloud/keycloak/actions/workflows/release.yml), choose **Run workflow** on **main**, set `release_tag`, and leave `preview` false to recover an existing stable Release. If images already have a saved publication record, recovery skips downloads, scans and registry writes and only finishes Git recording. Duplicate events for a fully recorded release exit without work. Runs are serialized; after a replaced/cancelled queued event, use this same recovery entry point.

The catalog waiter follows the newest exact-head, same-repository, explicitly dispatched CI rather than automatic PR runs that GitHub might hold for approval. A failed explicit run still stops recovery. GitHub can require maintainer approval for the first automatic robot PR workflow; review the guarded generated diff before approving that run, and preserve required checks. If the catalog merged after an interrupted waiter, recovery validates the existing record and completes a missing `publication-complete.json` without rebuilding or registry access. A conflicting completion attachment fails closed.

Enable **preview** to inspect and freshly scan an existing successful current-main CI without creating a Release, dispatching a build, freezing assets, requesting OIDC, uploading images or creating catalog PRs. It reports what the selected version would publish; it does not certify federation configuration or write permissions.

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

CI rejects malformed records, missing per-tag changes, broken alias history, duplicate releases and stale Markdown. Generated-record auto-merge never includes alias configuration, workflow, code, image-lock or existing-record modifications. Human edits stop automatic maintenance rather than being overwritten. Quay credentials never enter the catalog job. Historical first-release notes supplement the old immutable record separately; new plans embed changes. Use `node scripts/releases.mjs changes <image-tag-or-alias>` to query each tag's updates.

The installed Codesmith App appends a description footer. The catalog guard can exclude only this bounded footer from the generated-body hash after GraphQL proves the exact current body/head, its latest editor is the pinned Codesmith Bot, and the complete edit history contains only the pinned GitHub Actions and Codesmith Bot identities. Human/unknown/deleted editors, incomplete history, extra content and generated-body/file changes still block automatic maintenance. The footer does not expand the two-file catalog allowlist or bypass required checks.

After publication, open the [Quay tag page](https://quay.io/repository/rambow-cloud/keycloak?tab=tags) and verify both formal tags and their displayed digests against the [catalog](../releases/README.md). Use its digest-pinned Podman pull commands on the target deployment network.
