# Hosted runners and Actions audit

All 13 jobs in the five active workflows use explicit `ubuntu-26.04` x64 hosted runners. GitHub announced [general availability](https://github.com/actions/runner-images/issues/14747) on September 17, 2026. Use an explicit label so changes to `ubuntu-latest` do not silently change the selected OS. Image architecture remains Linux amd64.

The Ubuntu host supplies Buildah, Podman, Skopeo and fixture tooling; the image's build/runtime Java versions and base images still come from immutable `images.lock.json` inputs. Changing the host runner does not change those pins, create a GitHub Release, or publish to Quay.

## Actions inventory reviewed October 29, 2026

Every referenced Action already matches its latest stable release. The audit resolved official release tag objects to actual commit SHAs, including the annotated github-script tag; no newer stable version or pin change was needed. There are no local composite Actions in this repository.

| Action | Latest stable release | Verified pinned commit |
| --- | --- | --- |
| actions/checkout | [v7.0.1](https://github.com/actions/checkout/releases/tag/v7.0.1) | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/github-script | [v9.0.0](https://github.com/actions/github-script/releases/tag/v9.0.0) | `3a2844b7e9c422d3c10d287c895573f7108da1b3` |
| actions/upload-artifact | [v7.0.2](https://github.com/actions/upload-artifact/releases/tag/v7.0.2) | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| actions/download-artifact | [v8.0.2](https://github.com/actions/download-artifact/releases/tag/v8.0.2) | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |
| actions/create-github-app-token | [v3.3.0](https://github.com/actions/create-github-app-token/releases/tag/v3.3.0) | `64ab729a6294000f5aa4a4bc0b73d1f32bc45510` |

There is no Action-major migration in this change. Existing inputs, immutable pins, artifact formats, trusted comment code and GitHub App/OIDC credential boundaries remain in place. Future Action updates follow the Maintenance Issue/PR process, including release-note review; automatic dependency PRs remain disabled in `.github/dependabot.yml`.

## Temporary storage and validation

Ubuntu 26.04 [defaults `/tmp` to tmpfs](https://github.com/ubuntu/ubuntu-release-notes/blob/main/docs/26.04/summary-for-lts-users.md). OCI-heavy build, release scan and publish jobs set `TMPDIR` to `runner.temp` on the work disk rather than changing mounts or security settings. CI logs the actual OS, temporary filesystem and installed Buildah/Podman/Skopeo versions. The [runner image software inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2604-Readme.md) describes the hosted environment; package versions may change between image deployments.

The runner migration must pass the existing core/aws builds, rootfs and optimized startup checks, PostgreSQL TLS/authentication/shutdown checks, AWS transport/offline signing checks, exported OCI contract, artifact upload and native Trivy gates. Passing the fixable HIGH/CRITICAL gate is not a zero-CVE claim.

The `pull_request_target` Issue policy and `workflow_run` comment reporter execute trusted base/main workflow code. Their new runner labels take effect after integration, when a trusted-main updater run and reporter run can be checked. Release preparation/publishing jobs also use the new label, but their registry-writing paths are not exercised by creating a test Release. Keep evidence and any unexecuted paths in the associated Issue/PR; do not claim a Quay push test from ordinary PR CI.
