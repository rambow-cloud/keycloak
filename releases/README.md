# Published images

<!-- Generated from release JSON records. Do not edit by hand. -->

Registry: `quay.io/rambow-cloud/keycloak`. Formal releases only; no `latest` tag. Use digest-pinned references for deployments.

| Release | Keycloak | Profile | Image tag | Digest | Aliases | Published (UTC) |
| --- | --- | --- | --- | --- | --- | --- |
| [v26.8.1-r1](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r1) | 26.8.1 | core | `26.8.1-r1-core` | `sha256:e0975379e3f2080cc4b9a4e852ce3341c54041e8a733a529b01cca2922beaa32` | — | 2026-10-26T02:41:36.090Z |
| [v26.8.1-r1](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r1) | 26.8.1 | aws | `26.8.1-r1-aws` | `sha256:0771ae5db0bc40e057ce51d2609d50a56a0d867a66411e411179ecf12f9608a7` | — | 2026-10-26T02:41:36.090Z |

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
