# Security remediation ledger

<!-- Generated from records.jsonl by ledger.mjs. Do not edit by hand. -->

Git-backed JSONL records; no database service. This page documents reviewed repairs and verification events. It is not a complete current vulnerability inventory or a continuous scan dashboard.

[Security release notes](README.md) · [Published images](../../releases/README.md) · [Scan policy](../vulnerability-scanning.md) · [Text records](records.jsonl)

## Repair and verification history

| Record | Advisories / event | Result | Published image tags | Issues |
| --- | --- | --- | --- | --- |
| [SEC-2026-001](#sec-2026-001) | CVE-2026-54399, CVE-2026-54428, CVE-2026-64607 | Fixed before first publication | `26.8.1-r1-aws` | [#13](https://github.com/rambow-cloud/keycloak/issues/13), [#36](https://github.com/rambow-cloud/keycloak/issues/36) |
| [SEC-2026-002](#sec-2026-002) | EMUDHRA-2026-10 | Existing images verified | `26.8.1-r1-core`, `26.8.1-r1-aws` | [#36](https://github.com/rambow-cloud/keycloak/issues/36), [#37](https://github.com/rambow-cloud/keycloak/issues/37) |
| [SEC-2026-003](#sec-2026-003) | CVE-2026-102554, GHSA-xxph-c9ww-hj94 | Fix pending publication; listed images are affected | `26.8.1-r1-core`, `26.8.1-r1-aws` | [#44](https://github.com/rambow-cloud/keycloak/issues/44) |
| [SEC-2026-004](#sec-2026-004) | CVE-2026-102554, GHSA-xxph-c9ww-hj94 | Fixed before first publication | `26.8.1-r2-core`, `26.8.1-r2-aws` | [#44](https://github.com/rambow-cloud/keycloak/issues/44), [#48](https://github.com/rambow-cloud/keycloak/issues/48) |

## CVE and security event index

- **CVE-2026-102554**: [SEC-2026-003](#sec-2026-003), [SEC-2026-004](#sec-2026-004)
- **CVE-2026-54399**: [SEC-2026-001](#sec-2026-001)
- **CVE-2026-54428**: [SEC-2026-001](#sec-2026-001)
- **CVE-2026-64607**: [SEC-2026-001](#sec-2026-001)
- **EMUDHRA-2026-10**: [SEC-2026-002](#sec-2026-002)
- **GHSA-xxph-c9ww-hj94**: [SEC-2026-003](#sec-2026-003), [SEC-2026-004](#sec-2026-004)

## SEC-2026-001

Remediate AWS HTTPComponents vulnerabilities before the first formal image publication.

Recorded (UTC): `2026-10-26T11:59:58.054Z`. Result: **Fixed before first publication**.

- CVE-2026-54399: httpcore5 was upgraded from 5.4.2 to 5.4.4.
- CVE-2026-54428: httpcore5-h2 was upgraded from 5.4 to 5.4.4.
- CVE-2026-64607: httpclient5 was upgraded from 5.6.1 to 5.6.4.
- The affected dependency graph existed in development. No affected formal release is claimed: 26.8.1-r1-aws was first published with the repaired versions.
- Issue #13 records the reviewed Maven graph, Apache HTTP transport checks and passing core/aws Trivy gates in CI run 40245012866. This historical record is not a fresh vulnerability scan.

| Profile | Published tag | Digest |
| --- | --- | --- |
| aws | `26.8.1-r1-aws` | `sha256:0771ae5db0bc40e057ce51d2609d50a56a0d867a66411e411179ecf12f9608a7` |

Issues: [#13](https://github.com/rambow-cloud/keycloak/issues/13), [#36](https://github.com/rambow-cloud/keycloak/issues/36).

Reference PRs: [#12](https://github.com/rambow-cloud/keycloak/pull/12).

Evidence and sources:

- [Reviewed repair and validation, Issue #13](<https://github.com/rambow-cloud/keycloak/issues/13>)
- [Merged remediation PR #12](<https://github.com/rambow-cloud/keycloak/pull/12>)
- [Original passing validation run](<https://github.com/rambow-cloud/keycloak/actions/runs/40245012866>)

## SEC-2026-002

Verify that existing formal core/aws images reject the compromised eMudhra certificate chains.

Recorded (UTC): `2026-10-26T11:59:58.054Z`. Result: **Existing images verified**.

- Actual published Linux amd64 image JVMs ran on GitHub Ubuntu runners with Podman: Eclipse Adoptium Java 25.0.5+8-LTS, 148 default trust anchors. No image was rebuilt or published.
- Both profiles rejected all 14 incident chains, including emSign, AAA cross-signed and no-CT paths. Only trust-path construction failures were accepted as expected rejections.
- Both profiles accepted all 14 identical incident chains after only emSign ECC Root CA - G3 and AAA Certificate Services were restored to in-memory control anchors. No formal image or trust store was modified.
- A normal verified github.com certificate chain succeeded with the unchanged default image trust anchors for each profile. Signatures and certificate-validity checks remained active.
- Incident validation time was fixed at 2026-10-26T12:00:00Z; each normal control used its captured validation time. Revocation checks and AIA downloads were disabled to isolate trust-anchor removal; image validation ran without network access.
- Retained regression branch: chore/37-emudhra-regression. Exact code commit: 4c997af311311f1c756f10076ca8c580934cee62. Actions run: 40318536019, attempt 1. Draft PR #38 must remain unmerged and its branch undeleted.
- The default Java trust store resolved to /etc/ssl/certs/java/cacerts, SHA-256 7a7149229e983ea47f601ddcae16e09a3846ad8e66817e4ce65b14c0fdf7d3b8, in both profiles.
- Scope: offline PKIX certificate-path validation, not a complete live Keycloak outbound HTTPS integration test. Runtime-mounted custom trust stores and alternate trust providers are outside this result. Reports preserve the public fixtures, hashes and all individual outcomes in Git.

| Profile | Published tag | Digest |
| --- | --- | --- |
| core | `26.8.1-r1-core` | `sha256:e0975379e3f2080cc4b9a4e852ce3341c54041e8a733a529b01cca2922beaa32` |
| aws | `26.8.1-r1-aws` | `sha256:0771ae5db0bc40e057ce51d2609d50a56a0d867a66411e411179ecf12f9608a7` |

Issues: [#36](https://github.com/rambow-cloud/keycloak/issues/36), [#37](https://github.com/rambow-cloud/keycloak/issues/37).

Reference PRs: [#38](https://github.com/rambow-cloud/keycloak/pull/38).

Evidence and sources:

- [Incident description and public certificate chains](<https://emudhra.we-have-a-problem.com/>)
- [Camunda trust-store remediation #686](<https://github.com/camunda/keycloak/pull/686>)
- [Retained regression branch](<https://github.com/rambow-cloud/keycloak/tree/chore/37-emudhra-regression>)
- [Exact regression source commit](<https://github.com/rambow-cloud/keycloak/tree/4c997af311311f1c756f10076ca8c580934cee62>)
- [Passing actual-image regression run](<https://github.com/rambow-cloud/keycloak/actions/runs/40318536019>)
- [core runner regression report, complete public fixtures and controls](evidence/emudhra-core.json) — SHA-256 `f805e971a655ebc467b5f8de5a90b43106d0457a0bf5b03aa6d13001078d5113`
- [aws runner regression report, complete public fixtures and controls](evidence/emudhra-aws.json) — SHA-256 `0517563ed1f685d16a5f10e21f01503ae17f8cb7d39aca048cb8a80dc9519349`

## SEC-2026-003

Remediate the shared Guava dependency in core/aws; formal publication is pending.

Recorded (UTC): `2026-10-28T19:51:12.239Z`. Result: **Fix pending publication; listed images are affected**.

**Later corrections:** [SEC-2026-004](#sec-2026-004). Read these before relying on this historical conclusion.

- The listed r1 image tags are the existing published scope and are not repaired by a source-only change. Keycloak 26.8.1 supplies Guava 33.6.0-jre in both profiles.
- Candidate CI 40753028959 reports one fixable HIGH Guava finding per profile with the database updated 2026-10-28T13:01:10.618103814Z. This is a scan of the candidate, not a fresh scan of the published r1 digests.
- Issue #44 locks the official Maven Central Guava 33.7.2-jre payload and original upstream checksum, applies replacement before both optimization builds, and retains the Quarkus dependency filename while changing actual Maven metadata.
- No severity exception or finding suppression is used. Original source drift and Keycloak upgrades require explicit override review or removal. Runner runtime and fresh scan outcomes are recorded in the remediation PR.
- Append a correction containing the exact repaired tags/digests and successful publication evidence after a new formal revision is published; do not overwrite this pending event or any r1 publication facts.

| Profile | Published tag | Digest |
| --- | --- | --- |
| core | `26.8.1-r1-core` | `sha256:e0975379e3f2080cc4b9a4e852ce3341c54041e8a733a529b01cca2922beaa32` |
| aws | `26.8.1-r1-aws` | `sha256:0771ae5db0bc40e057ce51d2609d50a56a0d867a66411e411179ecf12f9608a7` |

Issues: [#44](https://github.com/rambow-cloud/keycloak/issues/44).

Evidence and sources:

- [Official patched Guava release](<https://github.com/google/guava/releases/tag/v33.7.2>)
- [Official public advisory](<https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94>)
- [Remediation and validation Issue](<https://github.com/rambow-cloud/keycloak/issues/44>)
- [Blocked candidate scan](<https://github.com/rambow-cloud/keycloak/actions/runs/40753028959>)

## SEC-2026-004

Publish the Guava repair in new core/aws r2 tags and complete the pending security event.

Recorded (UTC): `2026-10-28T20:14:41.112Z`. Result: **Fixed before first publication**.

Corrects [SEC-2026-003](#sec-2026-003). The earlier record remains visible.

- Both listed r2 tags were first published with Guava 33.7.2-jre, SHA-256 b530942257fb935f8b2cfaa5f8eb5bd59c555fd8e8d01b8ce98912e077ea606c. Existing r1 tags and their digests remain unchanged and are not repaired by this release.
- The repaired payload replaces the original checksum-verified 33.6.0-jre JAR before both optimization builds. The Quarkus filename remains com.google.guava.guava-33.6.0-jre.jar; actual Maven metadata and Trivy identify version 33.7.2-jre. Final rootfs validation verifies one exact repaired payload.
- Keycloak deliberately excludes Guava transitive dependencies; this repair preserves that graph and adds no failureaccess. The build probe covers collections, splitting, weak-key maps and normal serialization. Linux core/aws runtime CI covers verified database TLS and failure cases, schema/authentication, shutdown, and AWS transport/offline IAM signing.
- Source commit da29c6005420d0971589877dab10ec4ad335dc58 passed exact-commit CI 40759307054. Publication run 40760118301 freshly scanned the same OCI artifacts, froze their digests, uploaded with digest preservation and completed the Git catalog through PR #47.
- Each publication-time scan reports Guava 33.7.2-jre, no CVE-2026-102554 finding and zero blocking findings. Each retains 64 findings: 4 HIGH without available fixes, 38 MEDIUM, 20 LOW and 2 UNKNOWN. This is not a zero-CVE, exploitability, live cloud or custom-extension certification.
- Immutable publication-record.json on the Release and the Git catalog contain the exact source CI, artifact identities, profile tags/digests and nonempty Issue-linked fix history. The native auto-merge request on catalog PR #47 did not execute promptly; after reviewing its exact two-file diff and passing required checks, it was merged normally without bypassing protection.
- This append-only correction completes SEC-2026-003; its earlier pending-publication record remains visible. Future Keycloak or source-JAR changes fail closed until the temporary override is reviewed or removed.

| Profile | Published tag | Digest |
| --- | --- | --- |
| core | `26.8.1-r2-core` | `sha256:9f36c090c07e12f0fdd9dd171bd102a50c25edfb7b6c54e691da918200908438` |
| aws | `26.8.1-r2-aws` | `sha256:ee73b535798351bd007d72e1db6522e6fccacb2368005c7659bc171b88c19d23` |

Issues: [#44](https://github.com/rambow-cloud/keycloak/issues/44), [#48](https://github.com/rambow-cloud/keycloak/issues/48).

Reference PRs: [#45](https://github.com/rambow-cloud/keycloak/pull/45), [#47](https://github.com/rambow-cloud/keycloak/pull/47).

Evidence and sources:

- [Official repaired Guava release](<https://github.com/google/guava/releases/tag/v33.7.2>)
- [Official public advisory](<https://github.com/google/guava/security/advisories/GHSA-xxph-c9ww-hj94>)
- [Reviewed remediation PR](<https://github.com/rambow-cloud/keycloak/pull/45>)
- [Exact published source CI](<https://github.com/rambow-cloud/keycloak/actions/runs/40759307054>)
- [Publication and fresh scans](<https://github.com/rambow-cloud/keycloak/actions/runs/40760118301>)
- [Formal Release and immutable attachments](<https://github.com/rambow-cloud/keycloak/releases/tag/v26.8.1-r2>)
- [Publication catalog PR](<https://github.com/rambow-cloud/keycloak/pull/47>)
- [Publication facts at the catalog commit](<https://github.com/rambow-cloud/keycloak/blob/6089fc6c0e6c42f55da04dce6dfd580a658d13bd/releases/records/v26.8.1-r2.json>)
- [Exact reviewed payload lock](<https://github.com/rambow-cloud/keycloak/blob/da29c6005420d0971589877dab10ec4ad335dc58/dependencies/keycloak/overrides.lock.json>)

## Maintain and query

Append one complete JSON object per line to `records.jsonl`; retain existing lines, apart from Git newline conversion. Corrections use `kind: "correction"` and `supersedes` with the earlier record ID. Existing publication records and image digests are never rewritten.

Every repair PR must include a ledger record or reference its existing record and explain why no new event is needed. Use `pending-publication` for a candidate fix; its listed tags identify affected published images, not repaired images. After publication, append a correction with the exact repaired tag/profile/digest and publication evidence. Evidence-only verification records do not justify rebuilding or publishing an unchanged image. Both the text ledger and generated page are reviewed through the normal Issue/PR process.

From the repository root:

```sh
node docs/security/ledger.mjs render
node docs/security/ledger.mjs render --check
node docs/security/ledger.mjs show CVE-2026-54399
node docs/security/ledger.mjs show EMUDHRA-2026-10
node docs/security/ledger.mjs show 26.8.1-r1-aws
node docs/security/ledger.mjs append-check origin/main
```

Concise publication wording lives in `release-notes.json`: reference a completed repair record and its exact published Release, and list each CVE with a short problem/component-version sentence. Notes are reviewed through the normal Issue/PR process; rendering validates their published scope and generates both pages. Verification-only, pending and superseded records do not become release fixes.

The retained regression branch is `chore/37-emudhra-regression` ([closed, unmerged PR #38](https://github.com/rambow-cloud/keycloak/pull/38)). Its test code/workflow stays outside main. Reports above include the exact code commit and Actions run, all public chain fixtures and checksums, JVM/trust-store identity, controls and limits; expiring Actions artifacts are supplemental evidence. No scheduled rescan or automatic triage is implemented by this ledger.
