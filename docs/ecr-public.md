# Amazon ECR Public distribution

Amazon ECR Public is an additional distribution endpoint for completed Quay publications. The repository is `public.ecr.aws/j2a6d6e3/keycloak` ([gallery](https://gallery.ecr.aws/j2a6d6e3/keycloak)). Activation is controlled by reviewed `config/ecr-public.json`; creating the repository alone does not mean its images have been published.

## Publication and recovery

After a formal Quay Release has completed its catalog PR, the release workflow calls `ecr-public.yml`. Ordinary main pushes, PRs, builder updates and documentation changes do not publish images. A maintainer can run **Public ECR distribution** from **main**, supplying the exact existing formal Release tag, to populate or recover that Release without rerunning Quay builds/scans. There is one serialized publisher across automatic and manual paths.

The workflow checks the stable Release, main ancestry, active Git catalog, immutable source plan/record/completion and supply-chain attachment. It anonymously verifies all source signatures and each child's exact frozen CycloneDX attestation with checksum-pinned Cosign before obtaining AWS credentials. Skopeo copies each selected profile with `--all --preserve-digests`. There are no new revisions, architecture-specific public tags, aliases or `latest`; unchanged source history remains attached to each tag.

Before requesting AWS access, the workflow freezes `ecr-public-mirror-plan.json` on the source GitHub Release. An existing equal target tag is reused; a different digest fails. Partial progress is retained as an Actions artifact. Recovery uses the same frozen source digests, never another build. ECR's tag write API does not provide an atomic compare-and-swap guarantee: keep repository write access limited to this role and do not mutate tags outside the serialized workflow.

Separate native amd64 and arm64 runners anonymously pull each mirrored index using an empty registry auth file. They verify the exact selected child and config, Linux architecture, source commit and profile. Only after both runners pass are `ecr-public-mirror-record.json` and `ecr-public-mirror-complete.json` frozen on the Release. A completed retry does not request AWS credentials or repeat validation. A lost completion attachment can be recovered from the immutable mirror record. These supplemental assets do not rewrite Quay publication facts or broaden catalog-bot auto-merge permissions.

## Authentication and infrastructure

The reviewed CloudFormation template is [infra/ecr-public/iam-stack.json](../infra/ecr-public/iam-stack.json). It creates only a GitHub OIDC provider and the `RambowKeycloakPublicEcrPublisher` role in account `060065238923`; the existing public repository is outside this stack. If the account already has the GitHub provider, pass its ARN as `ExistingGitHubProviderArn` and ensure its audience includes `sts.amazonaws.com`.

The account's Role Manager console requires a CloudFormation execution role. Use the dedicated `RambowKeycloakOidcStackExecutor`, trusted only by `cloudformation.amazonaws.com`, with [the bounded stack executor policy](../infra/ecr-public/stack-executor-policy.json). It manages only the named publisher role and GitHub OIDC provider, including rollback actions. Reject the console's default automatic permissions, which grant access to most AWS services. The executor is infrastructure administration, cannot be assumed by GitHub, and is not the image publisher. Restrict who can pass it or update its stack, because it can manage the publisher's trust and inline policy.

Trust requires issuer `https://token.actions.githubusercontent.com`, audience `sts.amazonaws.com` and exact subject `repo:rambow-cloud@333554680/keycloak@1433566126:environment:ecr-public-release`. The immutable owner/repository IDs prevent name-reuse trust. GitHub Environment `ecr-public-release` permits main and formal `v*-r*` tags only. Workflow guards also require main/manual or the formal release caller. PR refs cannot access this publisher.

The role allows layer upload, PutImage and DescribeImages only for `arn:aws:ecr-public::060065238923:repository/keycloak`. ECR authorization and the STS bearer-token permission use the global resource required by AWS. No repository creation/deletion, IAM management, static AWS access keys, long-lived Quay fallback or AWS secrets are used. Actions requests a 15-minute role session. OIDC, STS and registry credentials remain in memory/private temporary files, are masked, and are removed before the job ends; none enter outputs or artifacts. ECR Public API calls use `us-east-1`, independently of the CloudFormation stack region.

ECR Public currently omits `sts:AWSServiceName` when requesting its STS bearer token; a strict `StringEquals` caused our first login to fail. The [AWS roadmap report](https://github.com/aws/containers-roadmap/issues/2896) describes the same limitation. The policy uses `StringEqualsIfExists`: an explicitly supplied value must be `ecr-public.amazonaws.com`, while an absent key is allowed. This is a missing-key exception, not a claim that every STS bearer request is unconditionally bound to ECR. No other service's authentication API is granted. [AWS documents GetServiceBearerToken as permission-only](https://docs.aws.amazon.com/service-authorization/latest/reference/list_sts.html); it cannot be invoked directly. Do not add other service token APIs without reviewing this allowance.

## Pulling and verification

After the matching Release has `ecr-public-mirror-complete.json`, pull a profile using its original tag, for example:

```sh
podman pull public.ecr.aws/j2a6d6e3/keycloak:26.8.2-r4-core
podman pull public.ecr.aws/j2a6d6e3/keycloak:26.8.2-r4-aws
```

The index automatically selects Linux amd64 or arm64. For reproducible pulls use `public.ecr.aws/j2a6d6e3/keycloak@sha256:<index digest>` from the Release mirror record. The digest is identical to Quay's, including every child. Source feature/fix history is in [the Git release catalog](../releases/README.md) and frozen source publication attachments.

Signatures and SBOM attestations remain anchored in Quay; this mirror does **not** claim to copy registry signatures/referrers into ECR. Verify the identical digest against the exact Quay release identity as described in [supply-chain.md](supply-chain.md), and obtain the frozen per-child CycloneDX assets from the GitHub Release. Mirroring is distribution validation, not a fresh CVE scan or a rebuilt security fix.
