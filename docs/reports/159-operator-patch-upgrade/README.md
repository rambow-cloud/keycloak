# Native Operator patch upgrade: 26.8.1 to 26.8.2

All four core/aws × amd64/arm64 cases passed an actual Keycloak **26.8.1 -> 26.8.2** Auto rolling upgrade on GitHub Actions. Imported realm data, client/user identifiers and a continuing refresh-token session survived the upgrade. No local tests, main merge, formal Release or registry push occurred.

**Subsequent stability finding:** the successful matrix below is a scoped historical run. A repeat in [run 43284141540](https://github.com/rambow-cloud/keycloak/actions/runs/43284141540) observed one amd64 core `socket hang up` exactly at old-Pod shutdown with default draining. Preserve [the failed runner result](default-drain-failure-amd64.json) and [traffic result](default-drain-failure-traffic.json); the earlier success does not establish reliable passthrough draining. The retained fixture now explicitly uses `shutdown-delay=30s`, `shutdown-timeout=10s` and a 120-second Pod grace period, following [official TLS passthrough guidance](https://www.keycloak.org/server/reverseproxy#_graceful_http_shutdown). Keepalive, strict failures and zero traffic retries remain unchanged. Exact follow-up run identities, matrix results and compact native evidence are retained in [Issue #159](https://github.com/rambow-cloud/keycloak/issues/159), so recording evidence there does not trigger another image rebuild. The original results and published facts below are not rewritten.

This result requires an explicit qualification: historical published images lack the Go launcher. The source fixture retains every original `v26.8.1-r5` layer and adds only the same static launcher plus the bounded entrypoint/config history. It is not the unmodified published image. The destination is the exact newly built and gated 26.8.2 image, including the current runtime/dependency inputs; this is not an experiment isolating only the Keycloak distribution change.

## Source and retained evidence

- [Issue #159](https://github.com/rambow-cloud/keycloak/issues/159), draft [PR #160](https://github.com/rambow-cloud/keycloak/pull/160); retain branch `feat/159-go-launcher`.
- Tested head: `98492c22cbc8c699f38b1ee2b5262063e2bf9da3`.
- Exact CI merge: `5a2732afbb6a40491e4170362a99357da591cc73`.
- [Successful CI run 43281045723, attempt 1](https://github.com/rambow-cloud/keycloak/actions/runs/43281045723); native [amd64 job](https://github.com/rambow-cloud/keycloak/actions/runs/43281045723/job/131404498132) and [arm64 job](https://github.com/rambow-cloud/keycloak/actions/runs/43281045723/job/131404498147).
- Unmodified runner results: [amd64.json](amd64.json), [arm64.json](arm64.json). These retain exact parent/fixture/destination OCI identities, configs, archives, native launcher metadata, scan summaries, runtime snapshot proofs, Pod UIDs, version checks, before/after data and traffic statistics.
- Reduced public compatibility Job snapshots: [amd64-jobs.json](amd64-jobs.json), [arm64-jobs.json](arm64-jobs.json). These retain the actual metadata/check images, commands, arguments, Job UIDs and completion conditions without environment/Secret data.
- Complete historical vulnerability finding lists reduced from runner reports: [amd64-historical-findings.json](amd64-historical-findings.json), [arm64-historical-findings.json](arm64-historical-findings.json). Full scanner inventories, CycloneDX output, database metadata, sanitized Kubernetes snapshots, rollout timelines and logs remain in the run's Operator artifacts for 30 days. Destination OCI/scanner artifacts retain the existing seven-day policy.

A subsequent documentation-only commit preserves this report. Its identity does not replace the tested implementation identity above. The previous [same-version report](../159-operator/README.md) remains a separate historical result.

## Test setup and immutable inputs

The official Keycloak/Operator 26.8.2 resources, kind 0.33.0, Kubernetes/kubectl 1.35.8 and PostgreSQL fixture retain the pins in `config/operator-tests.json` and `images.lock.json`. Each architecture ran natively, without emulation, using kind's explicit Podman provider and two Keycloak replicas on one disposable node. No Docker Engine/CLI was used.

The historical source was selected from the committed [v26.8.1-r5 publication record](../../../releases/records/v26.8.1-r5.json). Its Java 25 support and upstream launcher were checked on the runners: the reviewed startup SHA-256 was `5f68e52cc8f86336b4b674e48a465ca9249e27dd4ba5aafa126437b648020afe`, identical to the reviewed current startup source, with no compatibility warnings.

Go 1.27.4 was checksum-pinned with `CGO_ENABLED=0`; native tests/vet/build and static ELF/interpreter checks passed. The same native binary was used by both profiles, the destination and the historical source retrofit. The fixture used Buildah to generate one standalone launcher layer and Skopeo to retain the original compressed OCI blobs unchanged. All **36 original layers** were retained for each source; exactly one launcher layer was appended. Original environment and nonroot identity were preserved.

| Architecture | Static launcher SHA-256 |
| --- | --- |
| amd64 | `fd84cbec39d1c0c9bccd2f83c43760d55ef12e35ced2d6fa4696262ae910ddb2` |
| arm64 | `d889b85fa208fb721f88be628c907aa51ac29904eaad68627df93e813cc8743e` |

The initial [run 43279758191](https://github.com/rambow-cloud/keycloak/actions/runs/43279758191) failed historical-content preservation checks before running the Operator upgrade. That fixture construction was replaced with explicit append-only OCI composition; the checks were retained. The failed run is not positive upgrade evidence.

## Functional outcomes

| Profile | Architecture | API version transition | Old-version import | Auto upgrade | Compatibility exit codes | Minimum sampled ready replicas |
| --- | --- | --- | --- | --- | --- | --- |
| core | amd64 | `26.8.1 -> 26.8.2` | Passed, exit `0` | Passed | `0, 0` | 1 |
| aws | amd64 | `26.8.1 -> 26.8.2` | Passed, exit `0` | Passed | `0, 0` | 1 |
| core | arm64 | `26.8.1 -> 26.8.2` | Passed, exit `0` | Passed | `0, 0` | 1 |
| aws | arm64 | `26.8.1 -> 26.8.2` | Passed, exit `0` | Passed | `0, 0` | 1 |

All cases used stock Operator-generated server/import/update arguments, without command/args overrides. Before upgrading, both 26.8.1 servers became ready, verified HTTPS/admin and database TLS passed, a deleted Pod recovered, and Realm Import reached `Done` with authenticated API proof. A test user and client were created on that old database.

Before image replacement, `pg_dump --format=custom` created an ephemeral database backup and `pg_restore --list` confirmed table-data entries. The backup remained only inside the disposable database Pod. It was not restored; this is not rollback verification.

Each compatibility Job ran `update-compatibility metadata` with the **previous 26.8.1 fixture** in its `actual` init container and `update-compatibility check` with the **26.8.2 candidate** in its `desired` container. Both steps exited zero, the Job completed, and `RecreateUpdateUsed=false` confirmed the rolling strategy. Both old Pod UIDs were replaced; each new Pod's running config/rootfs identity matched the destination native artifact and each logged Keycloak 26.8.2 startup. Both replaced Pods logged graceful JVM shutdown.

After upgrade, authenticated server-info verified 26.8.2 and database TLS remained enabled. Realm UUID/name/display name, user UUID/username/email and client UUID/client identifier were identical before and after. The same existing credentials continued to authenticate. Exact values and both sets of Pod identities are preserved in the runner JSON.

## Session and availability observations

A separate traffic process sent fresh password logins, refreshed one continuing baseline session chain, and checked userinfo over verified TLS throughout image replacement. No retries concealed failures. All **2,013 HTTPS requests** succeeded.

| Profile | Architecture | Complete rounds | Login / refresh / userinfo | HTTPS requests | Failures | Maximum observed latency |
| --- | --- | --- | --- | --- | --- | --- |
| core | amd64 | 175 | `175 / 175 / 175` | 525 | 0 | 754 ms |
| aws | amd64 | 168 | `168 / 168 / 168` | 504 | 0 | 432 ms |
| core | arm64 | 169 | `169 / 169 / 169` | 507 | 0 | 393 ms |
| aws | arm64 | 159 | `159 / 159 / 159` | 477 | 0 | 547 ms |

Ready replica counts were sampled every two seconds and never dropped below one. Sampling and finite successful traffic do not certify the absence of shorter gaps, production HA or zero downtime under arbitrary load.

## Native image transitions

All fixture/candidate references were local to kind. These digests were not uploaded or bound to any published tag.

| Profile | Architecture | Historical launcher fixture digest | Exact gated 26.8.2 child digest |
| --- | --- | --- | --- |
| core | amd64 | `sha256:200de5b7f935019bd3d4758d3b58620a33b0e7b2a3f79abae2b1feeed6eb1fb8` | `sha256:b61be5eb279a4dd4e7a4029b496b4ff042d9791c09b19770f82866cd66b16f37` |
| aws | amd64 | `sha256:55c28e5f567b58db4201dc4b8a350735318070e53b96e2e03477221697cc8947` | `sha256:1422307235c8ac23e6e6f849b92d10c0bcb9ff9f9d3c9108a7673487ee0057ba` |
| core | arm64 | `sha256:70f69762f358764d4857e6d94dc5fa03138381d4f0c669b8851c7fd7fb6f7f51` | `sha256:596e2800c20e819497d223b1df3c81ca085ab26e40c60e2a92edcf1ce4fdc715` |
| aws | arm64 | `sha256:91a96c046f413d59b7d224302ba4e4aae2b00f24894424d3ec6e289963f346a3` | `sha256:7051e5fdbd543ca49e9f540b982a3530a9dc5e2060d88d8f50ec0aa36dd463a5` |

Exact original published child and config digests, retained layers, destination config/scan/archive associations and containerd snapshot chains are in the native JSON. The CRI's temporary import-index `imageID` is retained separately from the actual native child/config digest.

## Scanner results and limitations

All four destination builds passed the unchanged native runtime verification, complete Trivy scan and fixable HIGH/CRITICAL gate with **zero blocking findings**. Static checks, Issue policy, both native Go jobs, multiarchitecture packaging and the required aggregate also passed. This does not assert zero total destination CVEs.

Each historical source fixture completed its native Trivy OS/Java scan and reported **90 package/advisory findings**, including **two fixable HIGH findings**: `CVE-2026-76844` and `CVE-2026-85091` in Debian `zlib1g`. Historical fixtures are isolated, non-publishable representations of the old deployment, so those findings were reported rather than represented as release-candidate success. Scanner/coverage errors still fail the experiment. No destination, PR or release vulnerability gate was loosened. Counts are findings rather than unique CVEs; bounded summaries and complete reduced finding lists are preserved with their source identities. Different runtime/advisory feeds mean source/destination counts alone do not establish individual CVE repairs.

This result covers one forward patch pair, matching Operator 26.8.2, PostgreSQL, the project profiles and the tested native architectures. Official guidance supports patch rolling updates in one major.minor stream and requires checking compatibility: [Operator rolling updates](https://www.keycloak.org/operator/rolling-updates), [26.8.2 upgrading guide](https://www.keycloak.org/docs/26.8.2/upgrading/). This experiment does not validate minor/major upgrades, downgrade/restore, other Operators, multi-node topology, production load, full kc.sh semantics, FIPS or arbitrary extensions. The AWS wrapper used ordinary PostgreSQL with cloud plugins disabled; AWS IAM/RDS failover and PolarDB are not tested here.

The retained branch/PR remains draft and unmerged. Main, release records, aliases and published tags are unchanged by this work. No new release is justified by this evidence-only test.
