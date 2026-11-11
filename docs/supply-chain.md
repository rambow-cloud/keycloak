# Signatures and software inventories

New formal releases freeze a signing contract in `publication-plan.json`. It contains the checksum-pinned Cosign version and a CycloneDX JSON asset descriptor for each selected profile and architecture. The publisher signs each profile's OCI index and its amd64/arm64 child digests. Each child also receives a signed in-toto CycloneDX attestation. With both profiles selected this produces six image signatures and four SBOM attestations.

SBOMs describe the exact image child. The inventory uses every identified package in the complete Trivy report, including duplicate JAR locations. On the reviewed AL2023 runtime, the original checksum-bound RPM components are retained. Java package coordinates come from the existing native image analysis. The generator checks inventory equality, architecture, image config, manifest digest and component references. Inventory generation requires no additional build, image execution or database download.

The document records package inventory at publication. Its dependency edges group included components under the image and operating system. It does not reconstruct Maven's transitive dependency graph. Existing scanner coverage limits in [vulnerability scanning](vulnerability-scanning.md) also apply to the inventory.

The previous Syft experiment discovered Java coordinate differences in this optimized distribution. This release path uses the package coordinates already validated by the project's scanner and checks the exported PURL set against its complete report. The raw scanner evidence remains available in the publication run.

## Publisher identity

Cosign uses ephemeral keyless signing through GitHub Actions OIDC, Fulcio and Rekor. The protected `quay-release` publisher requests the Sigstore token with audience `sigstore`. Quay registry authentication separately requests audience `https://quay.io` and exchanges it for the short-lived repository robot credential.

The accepted issuer is `https://token.actions.githubusercontent.com`. The certificate identity must be exactly one of the following for the corresponding release.

- `https://github.com/rambow-cloud/keycloak/.github/workflows/release.yml@refs/tags/<release-tag>`
- `https://github.com/rambow-cloud/keycloak/.github/workflows/release.yml@refs/heads/main`

The main identity supports manual recovery. The verifier constrains the tag alternative to that release's exact tag. Signing is limited to the trusted protected workflow and happens after the selected images pass the current vulnerability gates. Signatures and attestations are stored alongside their subject digests through Cosign's OCI referrers support in Quay.

See [Sigstore OIDC identity](https://docs.sigstore.dev/certificate_authority/oidc-in-fulcio/) and [registry support](https://docs.sigstore.dev/cosign/system_config/registry_support/).

## Verify a release

Use the release's `publication-plan.json` and `supply-chain-verification.json` attachments to identify its index digest, child digest and accepted signer identities. The following commands use placeholders. Select the exact tag identity for initial publication or the exact main identity for a signature added during recovery.

```sh
IDENTITY='https://github.com/rambow-cloud/keycloak/.github/workflows/release.yml@refs/tags/<release-tag>'
ISSUER='https://token.actions.githubusercontent.com'
INDEX_DIGEST='sha256:<index-digest>'
CHILD_DIGEST='sha256:<architecture-child-digest>'
IMAGE='quay.io/rambow-cloud/keycloak'

cosign verify "$IMAGE@$INDEX_DIGEST" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"

cosign verify "$IMAGE@$CHILD_DIGEST" \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"

cosign verify-attestation "$IMAGE@$CHILD_DIGEST" \
  --type cyclonedx \
  --certificate-identity "$IDENTITY" \
  --certificate-oidc-issuer "$ISSUER"
```

The publisher performs these checks with an empty registry credential configuration. It also decodes the verified attestation, verifies its subject digest and compares the complete predicate with the frozen SBOM. This ensures that an otherwise valid attestation containing a different inventory cannot satisfy publication.

Download `sbom-core-amd64.cdx.json`, `sbom-core-arm64.cdx.json`, `sbom-aws-amd64.cdx.json` and `sbom-aws-arm64.cdx.json` from the corresponding GitHub Release. A release that selects only one changed profile includes only that profile's files. Their SHA-256 values are recorded in the frozen plan. The signed registry attestation provides publisher authentication for the inventory. Raw anonymous verification output is retained in the publication run's `signatures/` artifact directory.

## Completion and recovery

The publisher uploads every selected formal image tag, signs and anonymously verifies all selected digests and SBOM attestations, and then updates configured aliases. It records successful signature verification in the protected Release attachment and the publication JSON. The existing guarded catalog PR must merge before publication is marked complete.

An interrupted signing attempt preserves uploaded images and saves partial verification state in the publication artifact. Manual recovery uses the frozen SBOM assets and source OCI artifacts, verifies existing signatures and matching attestations, and uploads the missing metadata. Frozen SBOM checksums and identities are checked before registry credentials are requested. Recovery cannot substitute newly generated inventory for a frozen SBOM.

Historical release plans without `supplyChain` continue to use their original publication contract. Their records describe the original publication facts. Adding supply-chain support alone is maintenance and does not authorize a new image revision. Real Quay keyless signing and anonymous verification require execution of the protected publisher after review.
