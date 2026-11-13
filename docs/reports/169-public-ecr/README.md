# Public ECR delivery verification

Validation date: **2026-11-13 (Asia/Shanghai)**. Delivery Issue: [#169](https://github.com/rambow-cloud/keycloak/issues/169).

## Result

`public.ecr.aws/j2a6d6e3/keycloak` distributes the existing **v26.8.2-r4** images with **two tags**, each selecting native Linux **amd64/arm64**. Both OCI indexes and all four children retain their original Quay digests. No image was rebuilt, no revision was created, and no `latest`, architecture-specific tags or aliases were added.

| Profile | Public ECR tag | Index digest |
| --- | --- | --- |
| core | `26.8.2-r4-core` | `sha256:1ad8160dd0071659b740d97a99a1e42966dc36efc999ee7b42a96b571d13d026` |
| aws | `26.8.2-r4-aws` | `sha256:c6d175aaef490ee36ec7dc8db56bccc212c0f47d65c265824ad69c7b8fc8960d` |

Both tags preserve the original nonempty change history: the shell-free Go launcher and bounded Keycloak Operator behavior from [#159](https://github.com/rambow-cloud/keycloak/issues/159). See the [source Git publication record](../../../releases/records/v26.8.2-r4.json) and the frozen mirror plan's per-profile `changes`. Distribution alone is not a new feature or CVE repair in these image bytes.

## Native anonymous pulls

Successful publication and recording: [run 43346938461](https://github.com/rambow-cloud/keycloak/actions/runs/43346938461), attempt 1, workflow source `769b10ac684abbb89e549b61a3a425277d0a06e1`.

Both native runners used empty registry auth and received no AWS credentials or OIDC permission. They pulled each Public ECR index and checked its exact Linux architecture, child/config digest, source commit and profile. Image source remains `afc78df2fa453ecb097ed703b0316ca03502165e`.

| Profile | Architecture | Verified child digest | Verified config digest |
| --- | --- | --- | --- |
| core | amd64 | `sha256:bf94d502bd0872dd1eba5f8019eb0bba2316c74dc9b67f6eb6a582d640754484` | `sha256:cef931768a7fc28cef13cb6f0b5adc43a645f948396dc650241fc7bfc237224f` |
| core | arm64 | `sha256:80f882cb5977b4d694b2d9ce2b67add0e6eed09c6e0604229ee4f1339d8f019b` | `sha256:538ed0bb9a0acc96615d9f98ff9e5e759f657989b9e8b541b792d1a3d2260c06` |
| aws | amd64 | `sha256:46580fe5ad1a9679e2d6f31d10a58f0ecbeb689f071ddbdcd63277f7813ada03` | `sha256:9b1a05147afdc626404e5b35c1b8a7a72334c7e6cedf662a0cac0895686b6b01` |
| aws | arm64 | `sha256:bbbe70a150fcc3bd7d06ab2d9ed377c9d06556ebd4ac291f0ef19e2f41a44bfe` | `sha256:26d715a51dbde27635436f763909317d4d5c146081eb845c848877f1aabaffa9` |

Native job evidence: [amd64](https://github.com/rambow-cloud/keycloak/actions/runs/43346938461/job/131629219282), [arm64](https://github.com/rambow-cloud/keycloak/actions/runs/43346938461/job/131629219309). Short-lived Actions artifacts contain the original reports; the immutable Release record embeds them for durable retention.

## Immutable evidence and retry

The [source Release](https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.2-r4) retains these supplemental assets:

- [ecr-public-mirror-plan.json](https://github.com/rambow-cloud/keycloak/releases/download/v26.8.2-r4/ecr-public-mirror-plan.json): fixed source/target, source change history, index/child digests and frozen SBOM descriptors; SHA-256 `8167a9df9008a7887ccc929719e29cc2bd2ce89b901645917e6962e8df7f52e7`.
- [ecr-public-mirror-record.json](https://github.com/rambow-cloud/keycloak/releases/download/v26.8.2-r4/ecr-public-mirror-record.json): completed publication, six source signature verifications, four exact frozen CycloneDX attestation verifications and both native pull reports; SHA-256 `7c10e07ef243e17e335424713f544f29294ba189bb8974da94e83b7239de7c87`.
- [ecr-public-mirror-complete.json](https://github.com/rambow-cloud/keycloak/releases/download/v26.8.2-r4/ecr-public-mirror-complete.json): completion bound to the immutable record hash.

[Completed retry 43347346209](https://github.com/rambow-cloud/keycloak/actions/runs/43347346209) succeeded with only `prepare`; `publish`, `pull` and `record` were skipped. It requested no AWS publisher credentials and repeated no upload or image construction. This is idempotence evidence, not a new scan or pull result.

## AWS configuration and retained failure history

The existing public repository is in account `060065238923`. Stack `Rambow-keycloak-public-ecr-oidc-v2` in `ap-southeast-2` created the GitHub provider and bounded publisher, reaching `CREATE_COMPLETE` at 09:19:11. GitHub Environment `ecr-public-release` permits main branches and formal `v*-r*` tags; the workflow separately checks exact caller/tag/immutable OIDC claims. STS sessions last 15 minutes. No static AWS keys were configured.

The first stack, `Rambow-keycloak-public-ecr-oidc`, reached `ROLLBACK_COMPLETE` at 08:44:23 because the account's pre-activation SCP explicitly denied IAM provider creation. It is retained as an empty historical stack. AWS Settings subsequently displayed successful advanced-feature activation; the unchanged reviewed template then succeeded using the original restricted executor. No organization policy was bypassed or relaxed by this work.

[First mirror 43344300965](https://github.com/rambow-cloud/keycloak/actions/runs/43344300965) verified source signing and assumed the OIDC role but failed at ECR login, before uploads. [Diagnostic recovery 43345191348](https://github.com/rambow-cloud/keycloak/actions/runs/43345191348) identified `sts:GetServiceBearerToken` denied by its identity policy. [#170 / PR #171](https://github.com/rambow-cloud/keycloak/pull/171) added allowlisted error facts without exposing arbitrary authentication responses or credentials.

ECR Public omits the bearer `sts:AWSServiceName` key, matching [the AWS roadmap report](https://github.com/aws/containers-roadmap/issues/2896). The owner approved [#172 / PR #173](https://github.com/rambow-cloud/keycloak/pull/173): change only `StringEquals` to `StringEqualsIfExists`. A supplied value must still equal `ecr-public.amazonaws.com`; a missing key is allowed. No other service authentication API was granted. Change set `keycloak-ecr-bearer-context-172/1377879a-528d-4895-9d89-e37f8ba4031f` modified only `PublisherRole`, without replacement; the stack reached `UPDATE_COMPLETE` at 09:40:47. [The infrastructure guide](../../ecr-public.md) records this limitation.

Implementation: [PR #168](https://github.com/rambow-cloud/keycloak/pull/168). Final publisher-source main CI: [43346857445](https://github.com/rambow-cloud/keycloak/actions/runs/43346857445). CI passed 174 tests and required static/Issue checks; distribution changes intentionally skipped image construction. No local tests or container runs were performed.

## Pull commands and limits

```sh
podman pull public.ecr.aws/j2a6d6e3/keycloak:26.8.2-r4-core
podman pull public.ecr.aws/j2a6d6e3/keycloak:26.8.2-r4-aws

podman pull public.ecr.aws/j2a6d6e3/keycloak@sha256:1ad8160dd0071659b740d97a99a1e42966dc36efc999ee7b42a96b571d13d026
podman pull public.ecr.aws/j2a6d6e3/keycloak@sha256:c6d175aaef490ee36ec7dc8db56bccc212c0f47d65c265824ad69c7b8fc8960d
```

Open [the Public ECR gallery](https://gallery.ecr.aws/j2a6d6e3/keycloak) and check the two r4 profile tags. Untagged child manifests are the architecture members of those indexes, not additional profile tags.

Quay remains the signature/attestation location; registry signatures/referrers were not copied to ECR. The source GitHub Release retains the per-child CycloneDX assets. Mirroring preserved verified image bytes and original scan evidence; it was not a fresh CVE scan, rebuilt security release or repeated runtime/Operator regression.
