# Working agreements

## Project purpose

Build Keycloak OCI images for Rambow Cloud. Prefer distroless Java, a non-root user, and an optimized PostgreSQL configuration. Build with open-source Buildah, run and verify with Podman, and inspect image metadata with Skopeo. Do not introduce Docker Engine, Docker CLI, Docker-in-Docker, or build steps that require Docker.

## Issue-driven development (humans and agents)

1. Before any feature, bug fix, dependency, security, documentation, or CI change, create or identify an issue in this repository. Use the corresponding form in `.github/ISSUE_TEMPLATE/`. Issues created through APIs or CLIs must preserve the form's title prefix and all required section headings, with substantive content.
2. Define scope, acceptance criteria, validation, and security/compatibility impact before implementation. Complete missing issue details first.
3. Use `feat/<issue>-<slug>`, `fix/<issue>-<slug>`, or `chore/<issue>-<slug>` branches. Reference `#<issue>` in commit messages.
4. Use the PR template. Include a standalone `Closes #<issue>` line for each issue. Only issues in this repository are accepted; a PR cannot substitute for an issue. CI checks that every referenced issue exists, is open, and conforms to its template.
5. Merge only after acceptance criteria, relevant checks, and review are complete. Let the merge close the issue. Do not push directly to main or bypass required checks. The only bootstrap exception is the initial setup tracked by issue #1; enable branch protection immediately afterward.
6. After changing an issue's scope or body, rerun the PR's `Issue policy` check. Follow SECURITY.md for sensitive vulnerabilities; fixes may reference a sanitized maintenance issue without public exploit details.

## Image requirements

- `images.lock.json` is the source of truth for the Keycloak version and immutable base image digests. Do not use floating base images or publish a `latest` tag.
- Default to distroless nonroot with UID/GID 65532. The final image must have no shell, package manager, or build tool. Do not add a shell to fix startup.
- The direct Java entrypoint supports prebuilt `start --optimized`. On every Keycloak upgrade, compare JVM properties, module access options, and the launcher class against the matching upstream `kc.sh`, then verify graceful shutdown. Changes to build-time options, providers, or database vendor require a rebuild.
- Do not claim compatibility with `kc.sh`, `kcadm.sh`, `kcreg.sh`, `start-dev`, runtime reaugmentation, FIPS, additional architectures, or untested extensions.
- Inject credentials at runtime. Never put secrets into image layers, build arguments, issues, logs, or Git. Do not disable TLS verification or require privileged containers as the normal solution.
- Distroless reduces attack surface; it does not eliminate vulnerabilities. Update the base image, JVM, and Keycloak through issues.

## Validation and delivery

- Static checks: `node --test tests/issue-policy.test.cjs`, `git diff --check`, and ShellCheck in CI.
- Linux image validation: `bash scripts/build.sh`, then `bash scripts/verify-image.sh`. CI uses Buildah/Podman on Ubuntu. On Windows, use an independent Linux/WSL environment without requiring Docker Desktop.
- Run each relevant verification once. Repeat only after a newly understood failure or a meaningful state change. Test behavior and boundaries; avoid tests that merely mirror implementation.
- If a result can be verified in a browser, provide the exact URL and checks instead of probing the page with curl or similar commands. For DNS, use server-side CloudFormation status and outputs; do not perform local DNS validation.
- Report the change, linked issue, validation results, and material limits. Identify checks that were not run. Do not claim vulnerability scanning or production compatibility without evidence.
- Use English for repository content, issues, PRs, comments, and workflow messages.
