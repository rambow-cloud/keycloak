# Shell-free Go launcher: native Operator acceptance

The unmerged implementation passed all four profile/architecture cases on GitHub Actions. The official Keycloak 26.8.2 Operator started both replicas, completed Realm Import and performed an Auto image rolling replacement. No tests ran locally, no images were pushed, and no main merge or formal Release was performed.

## Retained source and evidence

- Feature [Issue #159](https://github.com/rambow-cloud/keycloak/issues/159), draft [PR #160](https://github.com/rambow-cloud/keycloak/pull/160).
- Retain branch `feat/159-go-launcher`; tested head `14f37e9ed920a0f6301cecd3fc80463e08140023`.
- Exact CI merge commit `1f6d9dd2dd5222b060735c5dd2abe7357a4c005e`; [successful CI run 43253050525, attempt 1](https://github.com/rambow-cloud/keycloak/actions/runs/43253050525).
- Native [amd64 Operator job](https://github.com/rambow-cloud/keycloak/actions/runs/43253050525/job/131306038819), [arm64 Operator job](https://github.com/rambow-cloud/keycloak/actions/runs/43253050525/job/131306038673).
- Unmodified runner result documents: [amd64.json](amd64.json), [arm64.json](arm64.json). They preserve exact OCI/config/archive/launcher digests, scan associations, arguments, old/new Pod UIDs, running-container snapshot proofs and traffic statistics. These files remain in Git after Actions artifact expiration.
- Run artifacts `operator-amd64-1` and `operator-arm64-1` additionally contain sanitized Kubernetes resources, conditions, events, compatibility/import logs, old-Pod shutdown logs and rollout timelines; their retention is 30 days. The same run retains source OCI and scanner artifacts under the existing seven-day policy.

The results below describe the tested commits above. A later documentation-only commit records this report; it does not replace the tested implementation identity.

## Compiler, images and cluster

Go **1.27.4**, the latest stable version verified during implementation, is checksum-pinned in `config/launcher.json`. Both native builds used `CGO_ENABLED=0`, `GOTOOLCHAIN=local`, disabled module downloads and no external Go dependencies. Go tests/vet/build, native ELF machine checks and rejection of a `PT_INTERP` segment passed on both native runners. Each architecture's binary was reused by core/aws. Binary SHA-256:

| Architecture | Static launcher SHA-256 |
| --- | --- |
| amd64 | `18bb9fb0d9b6cf5238f1709d6d44b9f161ce6dc1498bd23ca09d37646593511e` |
| arm64 | `0457fa58981138e240f2e227bd36189e07431acbe1438943f6984c13a670e791` |

All four Buildah builds, Podman runtime/launcher-integrity checks and native Trivy gates passed with zero blocking findings. This is not a claim of zero total CVEs. Both multiarchitecture packaging checks, static checks, Issue policy and the required aggregate passed. The final image remains shell-free and nonroot, with a root-owned native ELF at `/opt/keycloak/bin/kc.sh`; it contains no Go compiler or package manager.

The test uses matching Keycloak/Operator 26.8.2, pinned Operator resources `79ba77fd65bb05a8300cd1396d6be9806a0f290f`, kind 0.33.0 and Kubernetes/kubectl 1.35.8. Each native cluster has one node, two Keycloak replicas and ephemeral TLS-only PostgreSQL. Exact component pins are in both result documents. kind uses Podman explicitly; Docker Engine/CLI and emulation are not used.

## Functional results

| Profile | Architecture | Stock startup | Realm Import | Auto rolling update | Minimum sampled ready replicas | Import / compatibility exit codes |
| --- | --- | --- | --- | --- | --- | --- |
| core | amd64 | Passed | Passed | Passed | 1 | `0` / `0, 0` |
| aws | amd64 | Passed | Passed | Passed | 1 | `0` / `0, 0` |
| core | arm64 | Passed | Passed | Passed | 1 | `0` / `0, 0` |
| aws | arm64 | Passed | Passed | Passed | 1 | `0` / `0, 0` |

The server used the Operator's generated `-Djgroups.bind.address=$(POD_IP) --verbose start --optimized` arguments without command/args overrides. Verified HTTPS discovery, authenticated admin version checks, database TLS and recreation of a deleted server Pod passed for every case.

Realm Import invoked `/opt/keycloak/bin/kc.sh --verbose import --file=... --override=false` directly. The launcher enforced prebuilt mode without runtime augmentation. Each Job exited zero, the import resource reached `Done`, and an authenticated API lookup verified the imported realm and display name.

Each Auto test changed the CR image from `:candidate` to `:next`. Both compatibility steps exited zero, `RecreateUpdateUsed=false`, both original Pod UIDs were replaced, new running-container config/rootfs proofs matched the intended native artifact, and both replaced Pods logged graceful JVM shutdown. Pod readiness was sampled every two seconds; the minimum observed count was one. This sampling does not prove the absence of arbitrarily short readiness gaps.

## Authenticated traffic during image replacement

An independent process sampled fresh password login, a continuing refresh-token session and userinfo over verified TLS throughout each rollout. No retries concealed request errors. Every round included all three operations, and userinfo retained the expected user identity.

| Profile | Architecture | Complete rounds | HTTPS requests | Login / refresh / userinfo | Failures | Maximum observed request latency |
| --- | --- | --- | --- | --- | --- | --- |
| core | amd64 | 164 | 492 | `164 / 164 / 164` | 0 | 960 ms |
| aws | amd64 | 172 | 516 | `172 / 172 / 172` | 0 | 1,092 ms |
| core | arm64 | 164 | 492 | `164 / 164 / 164` | 0 | 845 ms |
| aws | arm64 | 167 | 501 | `167 / 167 / 167` | 0 | 699 ms |

These are successful sampled requests in this experiment, not a production zero-downtime guarantee.

## Exact native image transitions

These are local kind fixtures, not published registry references. The second image adds only `cloud.rambow.keycloak.operator-test-revision=2` to the image config. Its manifest/config digest changes while all filesystem layers, executable inputs, environment, entrypoint and command remain identical. This validates same-Keycloak-version Auto **image** replacement, not a Keycloak patch/minor upgrade.

| Profile | Architecture | Source child digest | Derived child digest |
| --- | --- | --- | --- |
| core | amd64 | `sha256:83b207f31824acb50e68686ec8590ac3cd7b29a72ffbfd0319f2acab07cc19fe` | `sha256:e395850988074d0c6a064794e816960367e6967b16f0edb21f2fe1304df13fe3` |
| aws | amd64 | `sha256:217f39bd88d90847ba4742849329b0a2daeadea708ae7d865ee855e538003670` | `sha256:9b917ead6333717aa87131b81a5627bf56b65d28bd75a3dc5375fbd8d43d5173` |
| core | arm64 | `sha256:6f936ed65c9da29b34978bbe2ca95ead52e4fe72ef1d39ba4cb81288a1322f08` | `sha256:7e63afaab57bf972d1120b384d849260fbbd43d7e30dbba41908e66e27a9615d` |
| aws | arm64 | `sha256:4993a6e3e296cc5095da74bb3f9482eb6b7f6ae1d4324ffc9d38f639ab24ddda` | `sha256:2c89cf74c90e7ce3f4a398c9479e2bf14ad97a3142a787c2a1ea8e988ca66358` |

containerd exposes temporary import-index aliases in Kubernetes `imageID`; those are not the native child digest. The harness therefore checks the exact local reference/config, hashes the stored native manifest/config and binds each running container's snapshot parent to the validated uncompressed OCI layer chain. Initial failed runs [43248751980](https://github.com/rambow-cloud/keycloak/actions/runs/43248751980) and [43250604688](https://github.com/rambow-cloud/keycloak/actions/runs/43250604688) diagnosed this identity-reporting issue; they are not positive acceptance evidence. No scanner, TLS or readiness gate was relaxed.

## Boundaries and next decision

Keycloak Pods used UID/GID 65532, read-only root filesystems, writable data/tmp volumes, fsGroup 65532, dropped capabilities and no privilege escalation. The test podTemplate supplied pull policy, mounts and security settings only. Private CA keys, credentials and kubeconfig were excluded from evidence; Secret resources were not collected. Only disposable nested kind nodes use Podman's cluster privileges.

The AWS profile used its bundled JDBC wrapper with cloud plugins disabled against ordinary PostgreSQL. This does not validate RDS IAM, AWS failover or any cloud service. Also untested: multiple Kubernetes nodes, production load/HA, cross-version upgrades, other Operators, full upstream shell-script behavior, FIPS and additional extensions. The launcher supports only optimized `start`, `import`, `update-compatibility metadata/check` and help/version, preserves JVM arguments as argv entries and replaces itself with Java. It does not implement shell-style `JAVA_OPTS` evaluation or runtime reaugmentation.

The feature remains on the retained branch and draft PR. Main, release records and published image tags remain unchanged by this work. A separate owner decision is required before review/merge/publication.
