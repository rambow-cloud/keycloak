# Contributing

This project uses issue-driven development. See [AGENTS.md](AGENTS.md) for the full working agreements. Use English for all contributions.

1. Choose Feature, Bug, or Maintenance from the [issue forms](https://github.com/rambow-cloud/keycloak/issues/new/choose). Dependency updates, base image refreshes, documentation, and CI changes also need maintenance issues.
2. Define acceptance criteria and a validation plan. API/CLI-created issues must contain the same required headings and substantive answers. Never include credentials, personal data, or undisclosed vulnerability details.
3. Create a branch containing the issue number, such as `feat/12-custom-provider`.
4. Make a complete, focused change and run relevant checks. To update upstream inputs, run `node scripts/lock-images.mjs <Keycloak-version>`, review the digest changes, and commit the lock file.
5. Use the PR template and include a standalone `Closes #12` line. Multiple local issues are allowed; each must be open and conform to its form.
6. After `Issue policy` and `Build and verify` pass, a maintainer reviews and squash-merges the PR. If the issue body changes, edit the PR body or rerun its policy check.

The policy workflow reads trusted rules from the default branch. It never executes PR code. PR image builds have no publication permissions. Do not weaken these checks through template or workflow changes.

Issue policy validates open PRs. Editing a closed or merged PR skips the policy job: its linked Issues may have correctly closed on merge. Manual candidate checks still require an open local PR at the exact dispatched head commit. Keep completed Issues closed when adding final validation details to merged PRs.

## Validation

```sh
node --test tests/issue-policy.test.cjs
git diff --check
bash scripts/build.sh
bash scripts/verify-image.sh
```

Image checks require Linux, Buildah, Podman, Skopeo, OpenSSL, and Node.js 22+. The verification script creates temporary PostgreSQL and Keycloak containers, checks the shell-free rootfs, non-root configuration, verified database TLS, startup on a read-only root filesystem, protocol authentication, and SIGTERM shutdown, then removes its resources. Set `BUILD_PROFILE=aws` for the AWS image; the default is `core`. Do not run the external verifier against production instances.
