# Working agreements

## Project purpose

Build Keycloak OCI images for Rambow Cloud. Prefer distroless Java, a non-root user, and an optimized PostgreSQL configuration. Build with open-source Buildah, run and verify with Podman, and inspect image metadata with Skopeo. Do not introduce Docker Engine, Docker CLI, Docker-in-Docker, or build steps that require Docker.

## Issue-driven development (humans and agents)

1. Before any feature, bug fix, dependency, security, documentation, or CI change, create or identify an issue in this repository. Use the corresponding form in `.github/ISSUE_TEMPLATE/`. Issues created through APIs or CLIs must preserve the form's title prefix and all required section headings, with substantive content.
2. Define scope, acceptance criteria, validation, and security/compatibility impact before implementation. Complete missing issue details first.
3. Use `feat/<issue>-<slug>`, `fix/<issue>-<slug>`, or `chore/<issue>-<slug>` branches. Reference `#<issue>` in commit messages.
4. Use the PR template. Include a standalone `Closes #<issue>` line for each issue. Only issues in this repository are accepted; a PR cannot substitute for an issue. CI checks that every referenced issue exists, is open, and conforms to its template.
5. Merge only after acceptance criteria, relevant checks, and review are complete. Let the merge close the issue. Do not push directly to main or bypass required checks.
6. After changing an issue's scope or body, rerun the PR's `Issue policy` check. Follow SECURITY.md for sensitive vulnerabilities; fixes may reference a sanitized maintenance issue without public exploit details.
7. The upstream updater may enable native auto-merge for patch/digest changes within reviewed image families after required checks, as authorized by the project owner. Larger upgrades and compatibility warnings require maintainer review. Do not broaden auto-merge eligibility or weaken checks. See `docs/upstream-updates.md`.
8. The project owner also authorizes native auto-merge for bot-owned Quay publication-record PRs limited to a new `releases/records/<release>.json` and generated `releases/README.md`. They must match the immutable Release attachment, pass the required guarded Issue policy and CI, and preserve human edits. Alias configuration, code, workflows and existing records are excluded. Never push catalog updates directly to main.

## Image requirements

- Use the latest LTS Java version explicitly supported by the selected Keycloak release for both build optimization and runtime. Verify against official Keycloak documentation on upgrades; do not infer the supported maximum from the upstream container's default JDK. Currently this is Java 25 for Keycloak 26.8.1. Record the major in `images.lock.json` and verify it in CI.
- `images.lock.json` is the source of truth for the Keycloak version and immutable base image digests. Do not use floating base images or publish a `latest` tag.
- Default to distroless nonroot with UID/GID 65532. The final image must have no shell, package manager, or build tool. Do not add a shell to fix startup.
- The direct Java entrypoint supports prebuilt `start --optimized`. On every Keycloak upgrade, compare JVM properties, module access options, and the launcher class against the matching upstream `kc.sh`, then verify graceful shutdown. Changes to build-time options, providers, or database vendor require a rebuild.
- Do not claim compatibility with `kc.sh`, `kcadm.sh`, `kcreg.sh`, `start-dev`, runtime reaugmentation, FIPS, additional architectures, or untested extensions.
- Inject credentials at runtime. Never put secrets into image layers, build arguments, issues, logs, or Git. Do not disable TLS verification or require privileged containers as the normal solution.
- Distroless reduces attack surface; it does not eliminate vulnerabilities. Update the base image, JVM, and Keycloak through issues.
- The hourly updater never changes `config/upstream-compatibility.json`. Review changed upstream `kc.sh` and supported Java LTS before updating that baseline; never update the hash simply to make CI pass.
- Build and scan only affected profiles with the checksum-pinned native Trivy. Keep static/Issue checks and a fail-closed required aggregate for intentional skips. Runtime/build/scanner validation changes still validate affected images. Fixable HIGH/CRITICAL vulnerabilities and scan/coverage errors fail the required check; intentional skips are never clean-scan claims. See `docs/image-change-policy.md`.
- Every actual image fix/feature needs a substantive Issue-linked fragment in `changes/`, with explicit profiles and type `fix` or `feature`; referenced Issues require standalone PR closing lines. Published tags and changed aliases need nonempty frozen change history. Compare per-profile input fingerprints with published baselines before release CI dispatch; skip unchanged profiles and fully unchanged publication. Never invent notes to force a rebuild or rewrite published facts/history.
- The PR comment reporter must execute only trusted default-branch code. Never run PR code or artifact content with a comment-writing token; validate run/head/profile/attempt associations and escape report data. See `docs/vulnerability-scanning.md`.
- Formal Quay publication uses `v<Keycloak>-r<N>` Releases and fixed core/aws tags. Freeze source artifacts/digests before pushing, freshly scan both profiles, never overwrite formal tag conflicts, and finish the Git JSON/Markdown record before marking publication complete. Only the protected publisher may request GitHub OIDC with audience `https://quay.io` for short-lived Quay robot authentication. Never add a long-lived-token fallback or persist transient credentials in outputs/artifacts. See `docs/quay-releases.md`.

## Validation and delivery

- Keep this file limited to durable working agreements. Record concrete Issues, temporary tasks, experiment branches, run identifiers and execution status in their Issues, PRs or evidence reports.
- Record security repairs and reviewed existing-image verifications in `docs/security/records.jsonl`, with explicit published tag/profile/digest, advisories or event IDs, local Issues/PRs, evidence and limitations. Preserve existing lines; append corrections with `supersedes`. Generate `docs/security/README.md` with `node docs/security/ledger.mjs render`; never hand-edit it or claim unpublished repairs as published. Evidence-only records do not justify rebuilding unchanged images. Keep isolated regression code on a dedicated retained branch when requested; store its exact branch, commit and run references in the report.

- Static checks: `node --test tests/*.test.cjs`, `node scripts/check-upstream-compatibility.mjs`, whitespace checks, and ShellCheck in CI.
- Linux image validation: `bash scripts/build.sh`, then `bash scripts/verify-image.sh`. CI uses Buildah/Podman on Ubuntu. On Windows, use an independent Linux/WSL environment without requiring Docker Desktop.
- Run each relevant verification once. Repeat only after a newly understood failure or a meaningful state change. Test behavior and boundaries; avoid tests that merely mirror implementation.
- If a result can be verified in a browser, provide the exact URL and checks instead of probing the page with curl or similar commands. For DNS, use server-side CloudFormation status and outputs; do not perform local DNS validation.
- Report the change, linked issue, validation results, and material limits. Identify checks that were not run. Do not claim vulnerability scanning or production compatibility without evidence.
- Use English for repository content, issues, PRs, comments, and workflow messages.
