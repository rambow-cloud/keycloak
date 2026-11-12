# Native launcher and Operator validation

This unmerged implementation targets the official Keycloak **26.8.2** Operator with the matching prebuilt distribution. Publication and main merge are outside the current authorization. All four native profile/architecture cases passed; see the [retained Actions acceptance report](reports/159-operator/README.md) for exact commits, digests, results and limits.

The entrypoint `/opt/keycloak/bin/kc.sh` is a static Go ELF executable. The build pins the current Go compiler and native archive checksums in `config/launcher.json`, sets `CGO_ENABLED=0`, disables module downloads and rejects a nonnative binary or ELF interpreter segment. Each native binary is tested and compiled once per CI run and reused by core/aws. No Go toolchain is copied into the image.

The bounded command contract accepts optimized `start`, `import`, and `update-compatibility metadata/check`, plus help/version. JVM `-D` arguments are retained as whole argv entries and placed before the existing Java main class. Prebuilt mode is enforced, including for the Operator's import invocation which omits `--optimized`. Unsupported commands and explicit attempts to disable optimized mode fail rather than causing runtime augmentation. The native process replaces itself with Java, retaining PID/exit/signal behavior. Standard `JAVA_TOOL_OPTIONS` remains available; shell-style JAVA_OPTS parsing is not implemented.

Runtime data is the writable nonroot subtree; distribution files and the launcher remain root-owned. The Kubernetes fixture additionally exercises a read-only root filesystem with writable data/tmp volumes and fsGroup 65532. Its podTemplate supplies only test pull policy, volumes and security settings, never command or args overrides. This allows stock Operator-generated server/import/update commands to exercise the actual image entrypoint contract.

## Actions-only acceptance

The user explicitly requested no local testing. Native Go tests/vet/build, static repository checks, Buildah/Podman image verification, pinned Trivy scans and kind/Podman integration all run on native GitHub-hosted amd64/arm64 runners.

Integration consumes the exact OCI artifacts from the successful build jobs in the same CI run and checks archive/manifest/config/scan/architecture associations. It imports images into disposable kind without pushing to a registry. For each profile, a second OCI image adds only a test revision label: it has a distinct config/manifest digest while retaining every rootfs layer, executable, environment variable, entrypoint and command. This exercises an actual Auto **image** replacement at the same Keycloak version. It does not certify a Keycloak version upgrade.

Each profile uses two server replicas and a separate TLS-only PostgreSQL database. Required positive checks are default Operator launch, verified HTTPS/admin/database TLS, Pod recreation, Realm Import `Done` plus authenticated realm lookup, and successful metadata/check Jobs followed by replacement of both original Pod UIDs. A separate traffic process samples fresh login, a continuing refresh-token session and userinfo throughout the image rollout, without retries that conceal errors. The evidence must show zero traffic failures, at least one ready replica, `RecreateUpdateUsed=false`, distinct old/new OCI digests and graceful shutdown logs for both replaced Pods.

Private CA keys, database/user/admin credentials and kubeconfig stay outside uploaded evidence. No Secret objects are collected. The runner's disposable kind node uses the Podman provider's nested-cluster privileges; Keycloak Pods have no privilege escalation or added capabilities. No Docker Engine/CLI, registry credential, publication or branch-protection bypass is needed.

Keycloak 26.8.2 enables rolling-updates:v2 by default. Passing this same-version image replacement experiment is not a claim of multi-node HA, production zero downtime, patch-version upgrade compatibility, RDS IAM/failover, other Operator versions, full kc.sh behavior, FIPS or untested extensions.
