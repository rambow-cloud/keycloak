# Native launcher and Operator validation

This implementation targets the official Keycloak **26.8.2** Operator with the matching prebuilt distribution. Check the [published per-tag history](../releases/README.md) for availability: older images without this feature retain their original behavior. All four native profile/architecture cases passed; see the [retained same-version acceptance report](reports/159-operator/README.md) and [final patch-upgrade evidence](https://github.com/rambow-cloud/keycloak/issues/159#issuecomment-6833669772) for exact commits, digests, results and limits. Statements about temporary branch-only authorization in historical reports describe their execution phase.

The entrypoint `/opt/keycloak/bin/kc.sh` is a static Go ELF executable. The build pins the current Go compiler and native archive checksums in `config/launcher.json`, sets `CGO_ENABLED=0`, disables module downloads and rejects a nonnative binary or ELF interpreter segment. Each native binary is tested and compiled once per CI run and reused by core/aws. No Go toolchain is copied into the image.

The bounded command contract accepts optimized `start`, `import`, and `update-compatibility metadata/check`, plus help/version. JVM `-D` arguments are retained as whole argv entries and placed before the existing Java main class. Prebuilt mode is enforced, including for the Operator's import invocation which omits `--optimized`. Unsupported commands and explicit attempts to disable optimized mode fail rather than causing runtime augmentation. The native process replaces itself with Java, retaining PID/exit/signal behavior. Standard `JAVA_TOOL_OPTIONS` remains available; shell-style JAVA_OPTS parsing is not implemented.

Runtime data is the writable nonroot subtree; distribution files and the launcher remain root-owned. The Kubernetes fixture additionally exercises a read-only root filesystem with writable data/tmp volumes and fsGroup 65532. Its podTemplate supplies only test pull policy, volumes and security settings, never command or args overrides. This allows stock Operator-generated server/import/update commands to exercise the actual image entrypoint contract.

## Actions-only acceptance

The user explicitly requested no local testing. Native Go tests/vet/build, static repository checks, Buildah/Podman image verification, pinned Trivy scans and kind/Podman integration all run on native GitHub-hosted amd64/arm64 runners.

Integration consumes the exact OCI artifacts from the successful build jobs in the same CI run and checks archive/manifest/config/scan/architecture associations. It imports images into disposable kind without pushing to a registry. The earlier same-version experiment added only a test revision label to a second OCI image, retaining every rootfs layer and executable input. Its frozen report remains separate. Current CI exercises the bounded cross-version patch pair described below.

Each profile uses two server replicas and a separate TLS-only PostgreSQL database. Required positive checks are default Operator launch, verified HTTPS/admin/database TLS, Pod recreation, Realm Import `Done` plus authenticated realm lookup, and successful metadata/check Jobs followed by replacement of both original Pod UIDs. A separate traffic process samples fresh login, a continuing refresh-token session and userinfo throughout the image rollout, without retries that conceal errors. The evidence must show zero traffic failures, at least one ready replica, `RecreateUpdateUsed=false`, distinct old/new OCI digests and graceful shutdown logs for both replaced Pods.

Private CA keys, database/user/admin credentials and kubeconfig stay outside uploaded evidence. No Secret objects are collected. The runner's disposable kind node uses the Podman provider's nested-cluster privileges; Keycloak Pods have no privilege escalation or added capabilities. No Docker Engine/CLI, registry credential, publication or branch-protection bypass is needed.

Keycloak 26.8.2 enables rolling-updates:v2 by default. Passing this same-version image replacement experiment is not a claim of multi-node HA, production zero downtime, patch-version upgrade compatibility, RDS IAM/failover, other Operator versions, full kc.sh behavior, FIPS or untested extensions.

## Cross-version follow-up

CI runs a bounded **26.8.1 -> 26.8.2** Auto patch-upgrade experiment, as supported by the [official patch rolling-update guidance](https://www.keycloak.org/operator/rolling-updates). The source is an immutable native child of this repository's published `v26.8.1-r5` record with only the same static Go launcher layer and entrypoint config added: those historical published images lack that launcher. Existing rootfs layers and environment must remain intact. This is an explicitly retrofitted historical fixture, not a claim that the unmodified old image supports the Operator. A future Keycloak/Operator version change requires reviewing this pinned version pair and its acceptance inputs.

The destination is the exact same-run 26.8.2 OCI artifact already passing the existing native image and vulnerability gates. Historical source fixtures receive current complete Trivy scans, with scan/coverage errors failing; historical CVEs are retained as non-publishable experiment findings, not hidden or treated as clean. Destination, PR and release gates remain unchanged. Experimental source fixtures are never published. Formal destination publication follows the normal protected Release, signing and catalog gates.

The test imports its realm on the old version, creates a client/user, takes and lists an ephemeral custom-format PostgreSQL backup, then runs the compatibility Job and actual two-replica rolling upgrade while sampling login, refresh and userinfo. It verifies unchanged realm/user/client identifiers and data, API-reported version transition, version-bearing startup logs from both new Pods, exact native config/rootfs identities, graceful shutdown and continuing sessions. A backup listing is a sanity check, not a restore test or rollback certification. All four cases passed: see the [separately bound cross-version report](reports/159-operator-patch-upgrade/README.md). The earlier same-version report is not cross-version evidence. Minor/major transitions remain outside this experiment.

The direct TLS NodePort fixture now explicitly sets `shutdown-delay=30s`, `shutdown-timeout=10s` and `terminationGracePeriodSeconds=120`, following the [TLS passthrough draining guidance](https://www.keycloak.org/server/reverseproxy#_graceful_http_shutdown). A subsequent run with the original defaults observed a socket reset at old-Pod shutdown, despite an earlier fully successful matrix. That failure is retained, not retried away. HTTP keepalive and the no-retry/zero-failure traffic gate remain enabled. These are deployment fixture settings, not new image defaults or proof that one successful run establishes production availability. Separately bound draining-configuration run evidence and current status are retained in [Issue #159](https://github.com/rambow-cloud/keycloak/issues/159); preserving those results in the Issue avoids triggering another image rebuild merely to record them.

## Deployment configuration fragment

Merge the following into an otherwise complete Keycloak CR with your reviewed image tag/digest, database credentials, hostname and TLS configuration. The fragment does not configure a database or issue certificates. Keep the Operator's generated command and args; do not add a shell or override the Java main class.

```yaml
spec:
  instances: 2
  startOptimized: true
  update:
    strategy: Auto
  additionalOptions:
    - name: shutdown-delay
      value: "30s"
    - name: shutdown-timeout
      value: "10s"
  unsupported:
    podTemplate:
      spec:
        terminationGracePeriodSeconds: 120
        securityContext:
          fsGroup: 65532
          fsGroupChangePolicy: OnRootMismatch
        containers:
          - name: keycloak
            securityContext:
              runAsNonRoot: true
              runAsUser: 65532
              runAsGroup: 65532
              readOnlyRootFilesystem: true
              allowPrivilegeEscalation: false
              capabilities:
                drop: [ALL]
            volumeMounts:
              - name: keycloak-data
                mountPath: /opt/keycloak/data
              - name: temporary
                mountPath: /tmp
        volumes:
          - name: keycloak-data
            emptyDir: {}
          - name: temporary
            emptyDir: {}
```

Preserve other required additional options, CA mounts and volumes in your CR. The test used this security/data/tmp configuration and separately mounted its database CA; it supplied `imagePullPolicy: Never` only for local kind fixtures, which is not appropriate for normal registry deployment. The Operator marks podTemplate unsupported; revalidate merged Pod and compatibility Job settings for your deployment. Data and configuration that must outlive Pods belong in PostgreSQL or separately managed storage, not these emptyDir volumes. Back up the database before upgrading. Adjust draining for the actual load balancer and keep the Pod grace period longer than delay plus timeout; these values are validated fixture settings rather than a universal production guarantee.
