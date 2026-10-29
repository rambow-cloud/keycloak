# Published images

<!-- Generated from release JSON records. Do not edit by hand. -->

Registry: `quay.io/rambow-cloud/keycloak`. Formal releases only; no `latest` tag. Use digest-pinned references for deployments.

| Release | Keycloak | Profile | Image tag | Digest | Aliases | Published (UTC) |
| --- | --- | --- | --- | --- | --- | --- |
| [v26.8.1-r2](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r2) | 26.8.1 | core | `26.8.1-r2-core` | `sha256:53d85ad1f5ed2838d300c0475b93b386388ea73636adf4537fc792dd14c0d09a` | — | 2026-10-28T20:08:15.664Z |
| [v26.8.1-r2](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r2) | 26.8.1 | aws | `26.8.1-r2-aws` | `sha256:2cea43c26ef0676d922f68de30504a6d9355a420c4c9544cda40aa10ab166129` | — | 2026-10-28T20:08:15.664Z |
| [v26.8.1-r1](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r1) | 26.8.1 | core | `26.8.1-r1-core` | `sha256:e0975379e3f2080cc4b9a4e852ce3341c54041e8a733a529b01cca2922beaa32` | — | 2026-10-26T02:41:36.090Z |
| [v26.8.1-r1](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r1) | 26.8.1 | aws | `26.8.1-r1-aws` | `sha256:0771ae5db0bc40e057ce51d2609d50a56a0d867a66411e411179ecf12f9608a7` | — | 2026-10-26T02:41:36.090Z |

## v26.8.1-r2

[Source commit](https://github.com/rambow-cloud/keycloak/commit/da29c6005420d0971589877dab10ec4ad335dc58) · [Source CI](https://github.com/rambow-cloud/keycloak/actions/runs/40759307054) · [Publication and fresh scans](https://github.com/rambow-cloud/keycloak/actions/runs/40760118301)

### `26.8.1-r2-core` (core)

- **fix:** Replace Keycloak's Guava 33.6.0-jre payload with checksum-locked 33.7.2-jre before optimization to remediate CVE-2026-102554 in both image profiles. ([#44](https://github.com/rambow-cloud/keycloak/issues/44))

Architecture expansion: [verification and publication](https://github.com/rambow-cloud/keycloak/actions/runs/40967675486). Original amd64 manifest retained; tag now selects the OCI index. See [append-only binding history](events.jsonl).

Architectures: `linux/amd64` (`sha256:9f36c090c07e12f0fdd9dd171bd102a50c25edfb7b6c54e691da918200908438`), `linux/arm64` (`sha256:5a4cf66e50a7542a3cb40548f3532357c5d40b68b2fa404eed27e98075a9422f`). The tag and pull reference select the OCI index.

```sh
podman pull quay.io/rambow-cloud/keycloak@sha256:53d85ad1f5ed2838d300c0475b93b386388ea73636adf4537fc792dd14c0d09a
```

### `26.8.1-r2-aws` (aws)

- **fix:** Replace Keycloak's Guava 33.6.0-jre payload with checksum-locked 33.7.2-jre before optimization to remediate CVE-2026-102554 in both image profiles. ([#44](https://github.com/rambow-cloud/keycloak/issues/44))

Architecture expansion: [verification and publication](https://github.com/rambow-cloud/keycloak/actions/runs/40967675486). Original amd64 manifest retained; tag now selects the OCI index. See [append-only binding history](events.jsonl).

Architectures: `linux/amd64` (`sha256:ee73b535798351bd007d72e1db6522e6fccacb2368005c7659bc171b88c19d23`), `linux/arm64` (`sha256:925fb6b8a04e349a64f1adbdcb4606d04dd520d2e18527741ee19b52161f1baa`). The tag and pull reference select the OCI index.

```sh
podman pull quay.io/rambow-cloud/keycloak@sha256:2cea43c26ef0676d922f68de30504a6d9355a420c4c9544cda40aa10ab166129
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


## Withdrawn releases

- `v26.8.1-r3` withdrawn at `2026-10-29T22:47:31.733Z` at the owner's request ([#70](https://github.com/rambow-cloud/keycloak/issues/70)). [Original publication facts](records/v26.8.1-r3.json) remain archived; these tags are no longer active.
