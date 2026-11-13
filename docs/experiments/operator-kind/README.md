# Published-image Operator experiment

This retained branch investigates the published `v26.8.2-r3` images with the official **26.8.2** Keycloak Operator. It changes no production image, tag, lock or release authorization. The standalone GitHub Actions workflow uses native Ubuntu amd64/arm64 runners, checksum-pinned kind and kubectl, the **Podman** provider, a digest-pinned Kubernetes 1.35.8 node, an exact upstream Operator resources commit and native Operator/image child digests. Normal CI intentionally skips image builds for this experiment.

The first push of the experiment code starts both architecture jobs. Later source changes trigger another bounded run. Once GitHub registers the workflow, it also supports branch workflow dispatch. Do not merge this experimental harness to main as part of the investigation.

Each disposable single-node cluster installs one namespaced Operator and a local TLS-only PostgreSQL fixture. It tests the two profiles sequentially using separate databases. The test CA, database password, server private keys, bootstrap admin credentials and kubeconfig stay in a private temporary directory or in memory, outside uploaded evidence. HTTPS client checks verify the test CA and hostname. PostgreSQL rejects non-TLS network connections; `pg_stat_ssl` confirms actual Keycloak connections use TLS. The `aws` profile exercises the AWS JDBC wrapper with plugins disabled against local PostgreSQL, not AWS APIs, RDS IAM or failover.

## Scenarios

1. A normal custom-image Keycloak CR, with no command override, records the actual Operator-generated args and readiness/failure. Unexpected infrastructure failures fail the experiment rather than becoming compatibility results.
2. If normal startup fails at the launcher boundary, try the upstream **unsupported podTemplate** hook: use `/usr/bin/java @/opt/keycloak/java.options` as the command, and move the classpath/main class into args. This permits Operator-inserted `-D` arguments to precede the Java main class. Mount an `emptyDir` at `/opt/keycloak/data` with `fsGroup: 65532` for the generated Kubernetes-CA truststore; Kubernetes does not initialize the image's declared `VOLUME` like the standalone Podman fixture. This is a limited experimental workaround, not an image change or compatibility promise.
3. Verify HTTPS discovery, token issuance, authenticated server version and database TLS. Delete the server Pod, let the Operator/StatefulSet recreate it, and repeat application checks.
4. Create a `KeycloakRealmImport` and retain its actual Job/Pod command, status and execution error or completion independently of server readiness.
5. For `core`, request an `Auto` compatibility check through a CR configuration change and retain the resulting Job/Pod observations. Neither a Job result nor a recreate fallback establishes a successful rolling upgrade; the published images were not built with the preview rolling-updates feature enabled.

The ephemeral kind node requires the Podman provider's nested-Kubernetes privileges on the hosted runner. Keycloak Pods explicitly run as UID/GID 65532 without privilege escalation or capabilities. No Docker Engine/CLI, registry write credential, cloud credential or shell is introduced into the Keycloak image.

## Evidence and limits

Each artifact contains `results.json`, `summary.md`, sanitized namespaced workload/event snapshots and bounded container logs. The report identifies branch, exact test commit, run/attempt, inputs and published native image digests. No Secret resources or private fixture directory are uploaded. Keep the branch and record its final commit/run in the report after execution.

This is a version-specific, single-node Kubernetes experiment. It does not certify production/HA, OpenShift, cloud databases, realm-import behavior, automatic rolling upgrades, other versions, other architectures, runtime reaugmentation, or vulnerabilities beyond the individually recorded observations. Compatibility gaps are experiment findings; infrastructure failures or missing positive evidence fail the job.

Sources: [custom images](https://www.keycloak.org/operator/customizing-keycloak), [podTemplate limitations](https://www.keycloak.org/operator/advanced-configuration), [tagged server controller](https://github.com/keycloak/keycloak/blob/26.8.2/operator/src/main/java/org/keycloak/operator/controllers/KeycloakDeploymentDependentResource.java), [tagged Realm Import controller](https://github.com/keycloak/keycloak/blob/26.8.2/operator/src/main/java/org/keycloak/operator/controllers/KeycloakRealmImportJobDependentResource.java), [tagged update Job controller](https://github.com/keycloak/keycloak/blob/26.8.2/operator/src/main/java/org/keycloak/operator/controllers/KeycloakUpdateJobDependentResource.java), [kind Podman provider](https://kind.sigs.k8s.io/docs/user/quick-start/).
