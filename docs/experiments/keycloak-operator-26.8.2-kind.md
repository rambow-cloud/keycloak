# Keycloak 26.8.2 Operator compatibility experiment

The published `v26.8.2-r3` images are **not directly compatible with the default Operator launch configuration**. A bounded, upstream-unsupported podTemplate configuration starts both profiles and passes application/restart checks, but it does not establish full Operator compatibility: Realm Import cannot execute the absent `kc.sh`, and the tested podTemplate breaks Auto compatibility-check argument ordering.

## Retained evidence

- Issue: [#154](https://github.com/rambow-cloud/keycloak/issues/154); retained draft PR: [#155](https://github.com/rambow-cloud/keycloak/pull/155).
- Retained branch: `chore/154-operator-kind`. Do not delete it or merge this experimental harness into main as part of the investigation.
- Tested harness commit: [`7f827179ace83042b38a7b923bda2b9c2eca322e`](https://github.com/rambow-cloud/keycloak/tree/7f827179ace83042b38a7b923bda2b9c2eca322e/docs/experiments/operator-kind).
- Completed native run: [43180568273, attempt 1](https://github.com/rambow-cloud/keycloak/actions/runs/43180568273), 2026-11-12. Native amd64 and arm64 jobs both completed successfully.
- Raw sanitized workflow artifacts: `operator-kind-amd64-1` and `operator-kind-arm64-1` (30-day Actions retention). A successful experiment workflow means the positive checks passed and the compatibility failures below were actually observed; it does **not** mean default Operator compatibility passed.
- Original architecture-bound result files are retained in Git: [amd64](operator-kind-results/amd64.json), [arm64](operator-kind-results/arm64.json). Their SHA-256 values are respectively `9756bc97f1fdd624e1d5f10147a710b8a320ba211af4036c02a6fe7a052c252c` and `15222e6643658e01964df0e7e7a8c3ae6426ae3529e58fdacbd8864b00e21a2f`.
- Later report-only commits preserve these tested source/run references and do not alter the tested harness or rerun image work.

Interpretation correction (2026-11-12): the original results' Auto-check `limitation` text and the historical harness README incorrectly say that a preview rolling-updates feature was not enabled. In the tagged 26.8.2 source, `ROLLING_UPDATES_V2` is `Type.DEFAULT` and its family is essential. No extra preview flag is required. The observed failure occurred before the compatibility command ran, at Java main-class argument parsing; it did not demonstrate a disabled feature. Original result bytes/hashes and the executed harness are preserved. See the [append-only correction](operator-kind-results/correction-2026-11-12.json) and [tagged feature definitions](https://github.com/keycloak/keycloak/blob/26.8.2/common/src/main/java/org/keycloak/common/Profile.java).

## Inputs and platform

Both runs used Ubuntu 26.04 native GitHub-hosted runners, kind **0.33.0** with its explicit **Podman** provider, Kubernetes **1.35.8**, the official **26.8.2** Operator, and the already published **26.8.2-r3** core/aws images. The Operator resources commit is `79ba77fd65bb05a8300cd1396d6be9806a0f290f`. Tool checksums, node index and Operator index/children are frozen in [inputs.json](operator-kind/inputs.json). Node architecture and actual running Operator/Keycloak child image IDs were verified against these inputs.

| Profile | Published index digest | Tested amd64 child | Tested arm64 child |
| --- | --- | --- | --- |
| core | `sha256:3d1fd81d9f001a611b825667b39de2a537cda2debc6862d465651dc04b15daec` | `sha256:8f8770b717bc46e61b7a3c44846b46b0f815841faf4c64e5c89d5261a28bb643` | `sha256:7c5019e4f79f696e6cbb32ea92698500e4bc2d717bacae1ed2a80c99395c99c0` |
| aws | `sha256:0d2471cce148a0007251d352717f7e0f418d31643086e547b88f1d4da6c13758` | `sha256:eb767a01fe9ad791db59c5f00f216ee9a3c432ad13eb717d009a40f1431a3327` | `sha256:b235e6ca6dfb382e0508deb768808313679cd0770b81341fbae3a899ae6818d4` |

No production image was rebuilt, retagged, signed or pushed by this experiment. Main, production image inputs and release eligibility were unchanged. No Docker Engine or CLI was used.

## Observed outcomes

| Scenario | amd64 | arm64 | Scope |
| --- | --- | --- | --- |
| Default Operator custom-image startup | Failed | Failed | core and aws; exit 2, unknown JVM argument at the application CLI |
| Direct-Java podTemplate plus writable data volume | Ready | Ready | core and aws; exact published child verified |
| Verified HTTPS discovery and issuer | Passed | Passed | Both profiles, before and after Pod recreation; test CA and hostname verified |
| Admin token and authenticated server version | Passed | Passed | Both profiles, before and after recreation; version 26.8.2 |
| Actual database TLS | Passed | Passed | Both profiles; TLS-only PostgreSQL fixture and `pg_stat_ssl` proof |
| Operator/StatefulSet Pod recreation | Passed | Passed | Both profiles; a new Pod UID became ready and application checks were repeated |
| KeycloakRealmImport | Failed | Failed | Both profiles; absent `/opt/keycloak/bin/kc.sh`, exit 128 |
| Auto update-compatibility Job | Failed | Failed | **core only**; the workaround's Java argument layout is incompatible with the Operator's Job rewrite |

### Default startup: JVM flags reach the application CLI

The Operator preserves the custom image entrypoint and supplies these args:

```text
-Djgroups.bind.address=$(POD_IP) --verbose start --optimized
```

The image entrypoint has already selected the Java main class. These appended args therefore reach Keycloak's application CLI instead of the JVM. All four default profile/architecture cases returned exit 2:

```text
Unknown option: '-Djgroups.bind.address'
```

The absence of a shell script is not sufficient by itself to explain this server-startup failure. The missing launcher behavior is the handling of Operator-added JVM options before starting the Java application.

### Bounded startup workaround and writable data

The tested unsupported podTemplate separates the JVM invocation from its application args:

```yaml
unsupported:
  podTemplate:
    spec:
      securityContext:
        fsGroup: 65532
        fsGroupChangePolicy: OnRootMismatch
      containers:
        - name: keycloak
          command: ["/usr/bin/java", "@/opt/keycloak/java.options"]
          args:
            - -cp
            - /opt/keycloak/lib/quarkus-run.jar
            - io.quarkus.bootstrap.runner.QuarkusEntryPoint
            - --verbose
            - start
          volumeMounts:
            - name: keycloak-data
              mountPath: /opt/keycloak/data
      volumes:
        - name: keycloak-data
          emptyDir: {}
```

This is a focused excerpt, not a complete deployable CR: the actual test also configured the pinned image, database Secret references, verified database CA and HTTPS certificate Secret. See [the tested generator](operator-kind/model.mjs) and the workload snapshots in the run artifacts.

The Operator inserts its `-D` option before the classpath/main-class args and appends `--optimized`; this makes server startup work. Keycloak still runs as UID/GID 65532 without privilege escalation or added capabilities. The experiment retains Kubernetes CA autodiscovery and mounts writable data rather than disabling trust discovery or weakening TLS verification.

An earlier [native run](https://github.com/rambow-cloud/keycloak/actions/runs/43179966272) tested the Java command change without the data volume. Both **core** architectures failed while saving the Kubernetes-CA truststore:

```text
Failed to save truststore: /opt/keycloak/data/keycloak-truststore.p12
java.io.FileNotFoundException: /opt/keycloak/data/keycloak-truststore.p12 (Permission denied)
```

Kubernetes does not initialize image-declared volumes as the existing standalone Podman test does. The final workaround mounts an `emptyDir` with the matching filesystem group. The earlier no-volume failure was observed on core; aws was not separately run without the volume.

### Realm Import: the controller explicitly requires the missing path

After the server was ready and authenticated application checks passed, each native profile received a real `KeycloakRealmImport` CR. The Operator-created Job explicitly replaced the server command with:

```text
/opt/keycloak/bin/kc.sh --verbose import --file=/mnt/realm-import/operator-<profile>-realm.json --override=false
```

All four Job Pods failed to execute with exit 128 and the recorded container-runtime error:

```text
exec: "/opt/keycloak/bin/kc.sh": stat /opt/keycloak/bin/kc.sh: no such file or directory
```

Changing the server podTemplate cannot fix this controller's hardcoded command. The generated import command also omits `--optimized`; restoring a script filename alone would not prove compatibility with the project's no-runtime-reaugmentation contract. No import succeeded and no import compatibility is claimed.

### Auto check: the startup workaround is insufficient

For core on each architecture, changing a CR option with `update.strategy: Auto` produced a real compatibility Job. It inherited the Java command from the workaround, but the Operator prepended its update subcommand **before** the classpath/main-class args:

```text
command: /usr/bin/java @/opt/keycloak/java.options
args: update-compatibility metadata --file <workdir>/updates.json -Djgroups.bind.address=$(POD_IP) -cp <jar> <main-class> --verbose --optimized
```

Java treated `update-compatibility` as its main class. Both init containers exited 1:

```text
Error: Could not find or load main class update-compatibility
Caused by: java.lang.ClassNotFoundException: update-compatibility
```

This is a limitation of the tested podTemplate workaround. The test does not show that every shell-free launcher must fail Auto checks. No automatic rolling upgrade was demonstrated and aws Auto was not exercised. Keycloak 26.8.2 enables `rolling-updates:v2` by default; the failed Java invocation did not reach that feature or the compatibility logic.

## Interpretation and remaining work

The current image is usable for the tested single-instance Operator-managed server only with explicit unsupported CR adaptation. It must not be advertised as an out-of-the-box or fully Operator-compatible image. Full support would need a reviewed launcher contract covering JVM options, the import executable path and optimized-import behavior, update-compatibility invocation, writable runtime data, and actual multi-replica rolling-update validation. This investigation does not implement that adapter or add a shell.

The aws profile used its existing AWS JDBC wrapper with plugins disabled against local TLS-only PostgreSQL. No RDS IAM, AWS API, Aurora/PolarDB failover, Kubernetes HA, multi-node behavior, OpenShift, FIPS, runtime reaugmentation or new vulnerability scan was tested. HTTPS used a private test CA with normal hostname/certificate verification. No test credentials, private keys, kubeconfig, Secret objects or JWTs are retained in the result files; downloaded sanitized artifacts were checked for private-key material, Secret resources and JWTs before retaining the JSON summaries.

## Primary sources

- [Operator custom-image contract](https://www.keycloak.org/operator/customizing-keycloak) and [unsupported podTemplate scope](https://www.keycloak.org/operator/advanced-configuration).
- [26.8.2 server controller](https://github.com/keycloak/keycloak/blob/26.8.2/operator/src/main/java/org/keycloak/operator/controllers/KeycloakDeploymentDependentResource.java).
- [26.8.2 Realm Import controller](https://github.com/keycloak/keycloak/blob/26.8.2/operator/src/main/java/org/keycloak/operator/controllers/KeycloakRealmImportJobDependentResource.java).
- [26.8.2 update Job rewrite](https://github.com/keycloak/keycloak/blob/26.8.2/operator/src/main/java/org/keycloak/operator/controllers/KeycloakUpdateJobDependentResource.java).
- [Pinned Operator resources](https://github.com/keycloak/keycloak-k8s-resources/tree/79ba77fd65bb05a8300cd1396d6be9806a0f290f/kubernetes) and [kind release/node checksums](https://github.com/kubernetes-sigs/kind/releases/tag/v0.33.0).
