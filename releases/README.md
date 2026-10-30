# Published images

<!-- Generated from release JSON records. Do not edit by hand. -->

Registry: `quay.io/rambow-cloud/keycloak`. Formal releases only; no `latest` tag. Use digest-pinned references for deployments.

| Release | Keycloak | Profile | Image tag | Digest | Aliases | Published (UTC) |
| --- | --- | --- | --- | --- | --- | --- |
| [v26.8.1-r4](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r4) | 26.8.1 | core | `26.8.1-r4-core` | `sha256:f44c94db4c96807f8c6c8b1a9eb3d63d94209a1b233ac26a4465c46ee3a8e055` | — | 2026-10-30T00:07:51.026Z |
| [v26.8.1-r4](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r4) | 26.8.1 | aws | `26.8.1-r4-aws` | `sha256:60cf8cf84de4b33cf33c6251ef3e4e5631f0fe8b11fcb29519046e81c170368a` | — | 2026-10-30T00:07:51.026Z |
| [v26.8.1-r3](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r3) | 26.8.1 | core | `26.8.1-r3-core` | `sha256:0546c047c8f4536ced6a0f90335e00f57b943915db53acbcadbfab6db497cbf6` | — | 2026-10-29T18:48:42.337Z |
| [v26.8.1-r3](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r3) | 26.8.1 | aws | `26.8.1-r3-aws` | `sha256:50835d238bbcdc886c033d27c91aee4270dcde59905304597af430480bc5ce0e` | — | 2026-10-29T18:48:42.337Z |
| [v26.8.1-r2](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r2) | 26.8.1 | core | `26.8.1-r2-core` | `sha256:9f36c090c07e12f0fdd9dd171bd102a50c25edfb7b6c54e691da918200908438` | — | 2026-10-28T20:08:15.664Z |
| [v26.8.1-r2](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r2) | 26.8.1 | aws | `26.8.1-r2-aws` | `sha256:ee73b535798351bd007d72e1db6522e6fccacb2368005c7659bc171b88c19d23` | — | 2026-10-28T20:08:15.664Z |
| [v26.8.1-r1](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r1) | 26.8.1 | core | `26.8.1-r1-core` | `sha256:e0975379e3f2080cc4b9a4e852ce3341c54041e8a733a529b01cca2922beaa32` | — | 2026-10-26T02:41:36.090Z |
| [v26.8.1-r1](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r1) | 26.8.1 | aws | `26.8.1-r1-aws` | `sha256:0771ae5db0bc40e057ce51d2609d50a56a0d867a66411e411179ecf12f9608a7` | — | 2026-10-26T02:41:36.090Z |

## v26.8.1-r4

[Source commit](https://github.com/rambow-cloud/keycloak/commit/309369edbfd43e4dd2c577fe700b1db0dc0c1439) · [Source CI](https://github.com/rambow-cloud/keycloak/actions/runs/40976533454) · [Publication and fresh scans](https://github.com/rambow-cloud/keycloak/actions/runs/40977310522)

### `26.8.1-r4-core` (core)

- **fix:** Repair excessive CPU consumption while parsing W3C tracestate headers by aligning the existing OpenTelemetry core cohort to official 1.67.0 artifacts before Keycloak optimization. ([#79](https://github.com/rambow-cloud/keycloak/issues/79))

Architectures: `linux/amd64` (`sha256:50bf02f80d85000543e191eefa935d149460534300550996791ddbdef603734f`), `linux/arm64` (`sha256:603adc44ed194f8c33c6760daca2d3bbd1ee1b65dd21b1e5f87ee0dd49117f02`). The tag and pull reference select the OCI index.

```sh
podman pull quay.io/rambow-cloud/keycloak@sha256:f44c94db4c96807f8c6c8b1a9eb3d63d94209a1b233ac26a4465c46ee3a8e055
```

### `26.8.1-r4-aws` (aws)

- **fix:** Repair excessive CPU consumption while parsing W3C tracestate headers by aligning the existing OpenTelemetry core cohort to official 1.67.0 artifacts before Keycloak optimization. ([#79](https://github.com/rambow-cloud/keycloak/issues/79))

Architectures: `linux/amd64` (`sha256:203dc685cd222347d80efbfc2b1162867ff2910983cda4be140b7c83ebd5df05`), `linux/arm64` (`sha256:ba1b49cf56b4c1a219155af1fbbc01c401bf054b097116539fdb0117672db2d0`). The tag and pull reference select the OCI index.

```sh
podman pull quay.io/rambow-cloud/keycloak@sha256:60cf8cf84de4b33cf33c6251ef3e4e5631f0fe8b11fcb29519046e81c170368a
```


## v26.8.1-r3

[Source commit](https://github.com/rambow-cloud/keycloak/commit/1293dd22485e4196e556f3428037cec0a64acc35) · [Source CI](https://github.com/rambow-cloud/keycloak/actions/runs/40932528395) · [Publication and fresh scans](https://github.com/rambow-cloud/keycloak/actions/runs/40933529546)

### `26.8.1-r3-core` (core)

- **feature:** Add native Linux arm64 alongside amd64, with per-architecture runtime and vulnerability checks and digest-preserving multi-architecture OCI release indexes. ([#64](https://github.com/rambow-cloud/keycloak/issues/64))
- **fix:** Refresh builder digest from ba0f0e1a33864105 to a9c5ddd386f62951. ([#54](https://github.com/rambow-cloud/keycloak/issues/54))

Architectures: `linux/amd64` (`sha256:8c0e8bdc700b70e4ab1e9867f63f87a359e7e9c64a4165205255a9503c564bdd`), `linux/arm64` (`sha256:3e51ea9c9425d66171fea155f2f83cebb6fc96e650ababf6ab48107005b5250e`). The tag and pull reference select the OCI index.

```sh
podman pull quay.io/rambow-cloud/keycloak@sha256:0546c047c8f4536ced6a0f90335e00f57b943915db53acbcadbfab6db497cbf6
```

### `26.8.1-r3-aws` (aws)

- **feature:** Add native Linux arm64 alongside amd64, with per-architecture runtime and vulnerability checks and digest-preserving multi-architecture OCI release indexes. ([#64](https://github.com/rambow-cloud/keycloak/issues/64))
- **fix:** Refresh builder digest from ba0f0e1a33864105 to a9c5ddd386f62951. ([#54](https://github.com/rambow-cloud/keycloak/issues/54))

Architectures: `linux/amd64` (`sha256:d876bee68d6dac8c571fe8d5663cf0bb3e38d25a1485d2582d853ad9973a1bba`), `linux/arm64` (`sha256:adee8450c8750e22249a3cf250e02fa303de7e4637bcafd78f3e69cc01bbe2d7`). The tag and pull reference select the OCI index.

```sh
podman pull quay.io/rambow-cloud/keycloak@sha256:50835d238bbcdc886c033d27c91aee4270dcde59905304597af430480bc5ce0e
```


## v26.8.1-r2

[Source commit](https://github.com/rambow-cloud/keycloak/commit/da29c6005420d0971589877dab10ec4ad335dc58) · [Source CI](https://github.com/rambow-cloud/keycloak/actions/runs/40759307054) · [Publication and fresh scans](https://github.com/rambow-cloud/keycloak/actions/runs/40760118301)

### `26.8.1-r2-core` (core)

- **fix:** Replace Keycloak's Guava 33.6.0-jre payload with checksum-locked 33.7.2-jre before optimization to remediate CVE-2026-102554 in both image profiles. ([#44](https://github.com/rambow-cloud/keycloak/issues/44))

```sh
podman pull quay.io/rambow-cloud/keycloak@sha256:9f36c090c07e12f0fdd9dd171bd102a50c25edfb7b6c54e691da918200908438
```

### `26.8.1-r2-aws` (aws)

- **fix:** Replace Keycloak's Guava 33.6.0-jre payload with checksum-locked 33.7.2-jre before optimization to remediate CVE-2026-102554 in both image profiles. ([#44](https://github.com/rambow-cloud/keycloak/issues/44))

```sh
podman pull quay.io/rambow-cloud/keycloak@sha256:ee73b535798351bd007d72e1db6522e6fccacb2368005c7659bc171b88c19d23
```


## v26.8.1-r1

[Source commit](https://github.com/rambow-cloud/keycloak/commit/a6bca23dd39652b70c38db10953a2e2a18ac3360) · [Source CI](https://github.com/rambow-cloud/keycloak/actions/runs/40259705547) · [Publication and fresh scans](https://github.com/rambow-cloud/keycloak/actions/runs/40260151709)

### `26.8.1-r1-core` (core)

- **feature:** Introduce optimized PostgreSQL Keycloak 26.8.1 on distroless Java 25 with nonroot execution and native OCI builds. ([#1](https://github.com/rambow-cloud/keycloak/issues/1), [#3](https://github.com/rambow-cloud/keycloak/issues/3))

```sh
podman pull quay.io/rambow-cloud/keycloak@sha256:e0975379e3f2080cc4b9a4e852ce3341c54041e8a733a529b01cca2922beaa32
```

### `26.8.1-r1-aws` (aws)

- **feature:** Add the AWS Advanced JDBC Wrapper, RDS PostgreSQL password and task-role IAM authentication, and a pinned RDS CA bundle. ([#5](https://github.com/rambow-cloud/keycloak/issues/5))
- **fix:** Remediate vulnerable HTTPComponents dependencies with locked httpclient5 5.6.4 and httpcore5 5.4.4 before the first publication. ([#13](https://github.com/rambow-cloud/keycloak/issues/13))

```sh
podman pull quay.io/rambow-cloud/keycloak@sha256:0771ae5db0bc40e057ce51d2609d50a56a0d867a66411e411179ecf12f9608a7
```
