# Automatic upstream updates

The [Upstream updates workflow](https://github.com/rambow-cloud/keycloak/actions/workflows/upstream-updates.yml) checks every hour at minute 17 UTC. It runs on GitHub, independently of a maintainer's computer. GitHub can delay scheduled jobs, and can disable schedules in public repositories after 60 days without repository activity; detection is not instantaneous. Check the Actions page if expected updates stop arriving. See [GitHub's schedule limitations](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

The updater selects the latest stable Keycloak release without downgrading, and resolves immutable digests for that release, the existing distroless nonroot Java/Debian family, and the existing Temurin JDK family. It preserves PostgreSQL test images, AWS JARs and the RDS CA lock. Java majors, Debian families, AWS dependencies and test-database upgrades require separate maintenance Issues and review.

An upstream update merge does not itself publish a registry image or create a GitHub Release. [Quay publication](quay-releases.md) accepts only formal Release `published`/`released` events or explicit recovery using an existing Release tag on main. There is no push, PR, schedule or upstream-update publication trigger. A builder digest change validates both profiles and changes their build-input fingerprints; a later deliberately created Release may therefore publish both with a new revision and frozen nonempty change history. A successful updater run or merge alone never starts that publication.

## Issue-first updates and merge policy

When inputs change, the workflow creates a complete Maintenance Issue before creating a branch or changing files. It opens one App-managed PR and refreshes that PR when more updates arrive. Writes use a short-lived, repository-scoped installation token for the private [Rambow Keycloak Updater](https://github.com/apps/rambow-keycloak-updater) App. Native PR events trigger CI and Issue policy; the updater does not additionally dispatch either workflow. This avoids approval-required runs created by `GITHUB_TOKEN` and duplicate image builds. See [GitHub's event/token behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/trigger-a-workflow#triggering-a-workflow-from-a-workflow).

- Digest updates within the reviewed image families and Keycloak patch updates within the same major/minor line enable GitHub's native squash auto-merge. Both required checks, `Issue policy` and `Build and verify`, must pass. The latter includes static compatibility checks and both core/aws image profiles. Branch protection remains enforced, including any future required reviews.
- Both image profiles also pass the [Trivy vulnerability gate](vulnerability-scanning.md): fixable HIGH/CRITICAL findings block auto-merge. All findings remain available in JSON artifacts and a maintained PR comment.
- Keycloak minor/major upgrades and candidates with compatibility warnings open as drafts and never enable auto-merge. A maintainer must complete the upgrade review, resolve checks and mark the PR ready before merging.
- A Java-major or family change requires review and an explicit lock/baseline change. The hourly updater does not switch those families automatically.

Auto-merge does not mean every patch is automatically safe: a patch that changes the startup script is blocked for review. No approval is fabricated and no required check is bypassed. The workflow disables a previous auto-merge request before refreshing a PR, then evaluates the new candidate again.

## Compatibility review

`config/upstream-compatibility.json` records the reviewed Keycloak startup-script hash and Java major. The updater never changes that baseline. CI fetches `kc.sh` and supported configurations from the exact candidate Keycloak tag, compares the startup hash, and checks that the locked Java is its latest supported LTS. Missing or unrecognized source information fails closed.

When compatibility changes:

1. Compare the candidate `kc.sh` with the reviewed tag, including JVM properties, module access, launcher class, memory defaults and signal handling. Update `config/java.options` or the Containerfile as needed.
2. Verify the latest supported LTS in the candidate's official documentation. If it changed, review the Temurin and distroless families together, then resolve new immutable digests. Do not infer support from the upstream container's default JDK.
3. Update the reviewed baseline hash/version/Java only after that review. Update associated documentation and the version comment in `config/java.options`.
4. Run both image profiles and verify startup, database TLS failures, token authentication and graceful shutdown before merging. Live RDS/PolarDB certification remains a separate staging task.

Editing a bot PR's commits, managed files, or generated description stops automatic refresh to preserve that work. Save any needed changes and close the PR to let the next run open a fresh candidate. A non-fast-forward concurrent push is rejected. Changes on main cause a fresh candidate commit and checks so strict branch protection can be satisfied.

A trailing Codesmith footer added by external automation is treated separately from the generated description only after a fresh GitHub snapshot verifies the exact PR head/body and complete edit history against the pinned updater App and Blacksmith bot identities. The footer must have the expected bounded envelope and repository/PR link; unknown editors, incomplete history, malformed footers and changes to the generated body, files or commits still block refresh. This does not install or execute Codesmith, alter auto-merge eligibility, or change image inputs.

## GitHub App setup and credential boundary

The organization-owned App is private, has no webhook subscriptions or OAuth user flow, and is installed only on `rambow-cloud/keycloak`. Grant repository Contents, Issues and Pull requests read/write plus mandatory Metadata read-only. Do not grant Actions, Checks, Administration, Workflows, Packages or organization permissions, and never add it to a branch-protection bypass list. Contents write is needed for branches and commits; GitHub groups Release APIs under that same permission, so the no-publication boundary also depends on reviewed updater code and the separate Release workflow, not a fictional branch-only permission.

Public App ID, Client ID, slug and exact bot login/numeric/node IDs are pinned in `updaterApp` in `scripts/lib/upstream.mjs`. They are not secrets. The workflow checks the minted token's App slug and the bot's full identity before any updater writes. Missing or mismatched configuration fails closed; it never falls back to `GITHUB_TOKEN` for writes or fabricates a workflow/PR review approval.

Create a GitHub Environment named `upstream-update` with a custom deployment branch policy allowing only the `main` branch (not all protected branches or tags). Store the App signing private key in its `UPSTREAM_APP_PRIVATE_KEY` Secret. Never store the key in a repository file, Issue, PR, log, output or artifact. The official checksum-pinned `actions/create-github-app-token` action requests only this repository and the three write permissions, and revokes the installation token at job completion. Tokens expire after one hour; the signing key is a separate persistent credential that maintainers must protect and rotate. No PAT or client secret is required.

Only trusted default-branch updater code requests this Environment or receives the App credential. Its ordinary `GITHUB_TOKEN` has Contents read-only. PR build/scanner workflows do not receive App credentials; Quay continues to use its separate protected OIDC publisher. `dry_run` does not mint an App token or require the signing key.

## Migration from legacy GitHub Actions PRs

An existing PR authored by `github-actions[bot]` is not silently adopted: changing its pusher does not change its author or reliably remove its approval-required workflow state. The App updater stops before modifying a foreign/legacy PR or branch.

After the App is installed, its Environment Secret is configured and this integration has passed review/checks on main, review the legacy PR and preserve its exact branch, commits and validation links. Close the legacy PR with a migration explanation without deleting its branch or merging unvalidated changes. Run the trusted updater on main to create a fresh App-owned Issue/branch/PR. Only after the replacement exists should the superseded legacy Issue be closed with cross-links; missing functionality is not completed work. Do not remove or change human edits to make a legacy candidate appear bot-owned.

Verify that the replacement PR has the configured App author, normal native CI/Issue policy runs without the `Approve workflows to run` prompt, and unchanged required merge gates. Check that the [Quay release workflow](https://github.com/rambow-cloud/keycloak/actions/workflows/release.yml) has no run triggered by creating or merging this update. Do not create a Release just to test authentication.

## Manual execution and recovery

Open the workflow's Actions page, choose **Run workflow**, select **main**, and optionally enable **dry_run**. A dry run reports detections and warnings without creating Issues, commits, PRs, dispatches or auto-merge requests. An authenticated `repository_dispatch` event with type `upstream-update` is also supported for future upstream notification integrations; no webhook subscription is installed by this project.

No-change runs create no Issues, commits or builds. An unchanged open candidate reuses its existing native check runs, including failures, instead of retrying them hourly. After investigating and fixing a missing/failed check, use the normal GitHub rerun controls, explicitly dispatch the existing recovery workflow, or push the reviewed fix. Do not approve a stale run to substitute for validation of a different head. Registry/source errors fail visibly in Actions; no floating-image fallback is used.

The repository must enable native auto-merge and install the dedicated App with the permissions above. The workflow runs trusted default-branch updater code, while CI runs with read-only permissions and the policy check loads trusted base/default-branch code. The separate GitHub Actions publication-record bot retains its existing authentication and guarded merge rules; this App migration does not broaden that exception.
