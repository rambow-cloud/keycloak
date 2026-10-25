# Automatic upstream updates

The [Upstream updates workflow](https://github.com/rambow-cloud/keycloak/actions/workflows/upstream-updates.yml) checks every hour at minute 17 UTC. It runs on GitHub, independently of a maintainer's computer. GitHub can delay scheduled jobs, and can disable schedules in public repositories after 60 days without repository activity; detection is not instantaneous. Check the Actions page if expected updates stop arriving. See [GitHub's schedule limitations](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

The updater selects the latest stable Keycloak release without downgrading, and resolves immutable digests for that release, the existing distroless nonroot Java/Debian family, and the existing Temurin JDK family. It preserves PostgreSQL test images, AWS JARs and the RDS CA lock. Java majors, Debian families, AWS dependencies and test-database upgrades require separate maintenance Issues and review.

## Issue-first updates and merge policy

When inputs change, the workflow creates a complete Maintenance Issue before creating a branch or changing files. It opens one bot-managed PR and refreshes that PR when more updates arrive. Each candidate explicitly starts both CI and Issue policy using the short-lived `GITHUB_TOKEN`. This avoids relying on token-created PR events, which can require workflow approval. No personal access token, GitHub App secret, Docker build tooling, registry publication or deployment is added.

- Digest updates within the reviewed image families and Keycloak patch updates within the same major/minor line enable GitHub's native squash auto-merge. Both required checks, `Issue policy` and `Build and verify`, must pass. The latter includes static compatibility checks and both core/aws image profiles. Branch protection remains enforced, including any future required reviews.
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

## Manual execution and recovery

Open the workflow's Actions page, choose **Run workflow**, select **main**, and optionally enable **dry_run**. A dry run reports detections and warnings without creating Issues, commits, PRs, dispatches or auto-merge requests. An authenticated `repository_dispatch` event with type `upstream-update` is also supported for future upstream notification integrations; no webhook subscription is installed by this project.

No-change runs create no Issues, commits or builds. An unchanged open candidate reuses its existing check runs, including failures, instead of retrying them hourly. If a dispatch was missing, the next run can create that missing run. After investigating and fixing a failed check, use the normal GitHub rerun controls or push the reviewed fix. Registry/source errors fail visibly in Actions; no floating-image fallback is used.

The repository must allow Actions to create pull requests and must enable native auto-merge. The workflow's permissions are limited to repository contents, Issues, PRs and workflow dispatch. It runs trusted default-branch updater code, while CI runs with read-only permissions and the policy check loads trusted base/default-branch code.
