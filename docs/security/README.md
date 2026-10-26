# Security remediation ledger

<!-- Generated from records.jsonl by ledger.mjs. Do not edit by hand. -->

Git-backed JSONL records; no database service. This page documents reviewed repairs and verification events. It is not a complete current vulnerability inventory or a continuous scan dashboard.

[Published images](../../releases/README.md) · [Scan policy](../vulnerability-scanning.md) · [Text records](records.jsonl)

## Repair and verification history

| Record | Advisories / event | Result | Published image tags | Issues |
| --- | --- | --- | --- | --- |
| [SEC-2026-001](#sec-2026-001) | CVE-2026-54399, CVE-2026-54428, CVE-2026-64607 | Fixed before first publication | `26.8.1-r1-aws` | [#13](https://github.com/rambow-cloud/keycloak/issues/13), [#36](https://github.com/rambow-cloud/keycloak/issues/36) |
| [SEC-2026-002](#sec-2026-002) | EMUDHRA-2026-10 | Existing images verified | `26.8.1-r1-core`, `26.8.1-r1-aws` | [#36](https://github.com/rambow-cloud/keycloak/issues/36), [#37](https://github.com/rambow-cloud/keycloak/issues/37) |

## CVE and security event index

- **CVE-2026-54399**: [SEC-2026-001](#sec-2026-001)
- **CVE-2026-54428**: [SEC-2026-001](#sec-2026-001)
- **CVE-2026-64607**: [SEC-2026-001](#sec-2026-001)
- **EMUDHRA-2026-10**: [SEC-2026-002](#sec-2026-002)

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

## Maintain and query

Append one complete JSON object per line to `records.jsonl`; retain existing lines, apart from Git newline conversion. Corrections use `kind: "correction"` and `supersedes` with the earlier record ID. Existing publication records and image digests are never rewritten.

Every repair PR must include a ledger record or reference its existing record and explain why no new event is needed. Evidence-only verification records do not justify rebuilding or publishing an unchanged image. Both the text ledger and generated page are reviewed through the normal Issue/PR process.

From the repository root:

```sh
node docs/security/ledger.mjs render
node docs/security/ledger.mjs render --check
node docs/security/ledger.mjs show CVE-2026-54399
node docs/security/ledger.mjs show EMUDHRA-2026-10
node docs/security/ledger.mjs show 26.8.1-r1-aws
node docs/security/ledger.mjs append-check origin/main
```

The retained regression branch is `chore/37-emudhra-regression` ([draft PR #38](https://github.com/rambow-cloud/keycloak/pull/38)). Its test code/workflow stays outside main. Reports above include the exact code commit and Actions run, all public chain fixtures and checksums, JVM/trust-store identity, controls and limits; expiring Actions artifacts are supplemental evidence. No scheduled rescan or automatic triage is implemented by this ledger.
