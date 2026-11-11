# Security release notes

<!-- Generated from records.jsonl and release-notes.json by ledger.mjs. Do not edit by hand. -->

[Detailed history and evidence](history.md) · [Image tags and digests](../../releases/README.md)

## v26.8.2-r1

<a id="sec-2026-007"></a>

- **[CVE-2026-92358](history.md#sec-2026-007)** (`aws`, `core`): Invalidate fallback proofs after account linking.
- **[CVE-2026-105305](history.md#sec-2026-007)** (`aws`, `core`): Apply client ACR requirements to device authorization.
- **[CVE-2026-107623](history.md#sec-2026-007)** (`aws`, `core`): Preserve logout revocation settings during client registration updates.
- **[CVE-2026-107889](history.md#sec-2026-007)** (`aws`, `core`): Correct login-page HTML sanitization.
- **[CVE-2026-111497](history.md#sec-2026-007)** (`aws`, `core`): Correct bundled Brotli decoder memory safety.
- **[CVE-2026-112208](history.md#sec-2026-007)** (`aws`, `core`): Discard stale authentication state during organization login.
- **[CVE-2026-107123](history.md#sec-2026-007)** (`aws`, `core`): Harden SAML request processing against denial of service.
- **[CVE-2026-107124](history.md#sec-2026-007)** (`aws`, `core`): Validate logout hints against the intended session.
- **[CVE-2026-107602](history.md#sec-2026-007)** (`aws`, `core`): Bound SAML key-information parsing work.
- **[CVE-2026-110931](history.md#sec-2026-007)** (`aws`, `core`): Bound SAML authority parsing memory usage.
- **[CVE-2026-97367](history.md#sec-2026-007)** (`aws`, `core`): Protect session claims from client-registration mapper substitution.
- **[CVE-2026-97174](history.md#sec-2026-007)** (`aws`, `core`): Validate CIBA subject parameters before issuing tokens.
- **[CVE-2026-114232](history.md#sec-2026-007)** (`aws`, `core`): Enforce resource ownership in UMA permission requests.
- **[CVE-2026-97847](history.md#sec-2026-007)** (`aws`, `core`): Protect token principals from delegated client-manager changes.
- **[CVE-2026-96547](history.md#sec-2026-007)** (`aws`, `core`): Prevent attribute mappers from fabricating realm roles.
- **[CVE-2026-96457](history.md#sec-2026-007)** (`aws`, `core`): Preserve group permission denials during group moves.
- **[CVE-2026-96460](history.md#sec-2026-007)** (`aws`, `core`): Enforce expiration limits on exchanged tokens.
- **[CVE-2026-97848](history.md#sec-2026-007)** (`aws`, `core`): Protect resource-role claims from JSON mapper injection.
- **[CVE-2026-109081](history.md#sec-2026-007)** (`aws`, `core`): Restrict default-role changes by client creators.
- **[CVE-2026-92857](history.md#sec-2026-007)** (`aws`, `core`): Protect reserved subject and audience claims from mappers.
- **[CVE-2026-103112](history.md#sec-2026-007)** (`aws`, `core`): Close the authentication account-takeover race.
- **[CVE-2026-97175](history.md#sec-2026-007)** (`aws`, `core`): Require verified identity-provider email before automatic account linking.
- **[CVE-2026-96447](history.md#sec-2026-007)** (`aws`, `core`): Prevent identity rebinding after client recreation.
- **[CVE-2026-82965](history.md#sec-2026-007)** (`aws`, `core`): Bound XML processing at SAML resolution endpoints.
- **[CVE-2026-96448](history.md#sec-2026-007)** (`aws`, `core`): Apply delegated role permissions to composite roles.
- **[CVE-2026-92855](history.md#sec-2026-007)** (`aws`, `core`): Require proof for SAML holder-of-key assertions.
- **[CVE-2026-92856](history.md#sec-2026-007)** (`aws`, `core`): Honor SAML proxy restrictions during identity brokering.
- **[CVE-2026-19688](history.md#sec-2026-007)** (`aws`, `core`): Enforce audience validation for administrative API tokens.
- **[CVE-2026-117691](history.md#sec-2026-007)** (`aws`, `core`): Validate encoded SAML redirect parameter signatures.

## v26.8.1-r4

<a id="sec-2026-006"></a>

- **[CVE-2026-118259](history.md#sec-2026-006)** (`aws`, `core`): Fix excessive CPU consumption in W3C tracestate parsing by upgrading OpenTelemetry core from 1.62.0 to 1.67.0.

## v26.8.1-r2

<a id="sec-2026-004"></a>

- **[CVE-2026-102554](history.md#sec-2026-004)** (`aws`, `core`): Fix the Guava vulnerability by upgrading 33.6.0-jre to 33.7.2-jre.

## v26.8.1-r1

<a id="sec-2026-001"></a>

- **[CVE-2026-54399](history.md#sec-2026-001)** (`aws`): Fix the HTTP Core vulnerability by upgrading httpcore5 from 5.4.2 to 5.4.4.
- **[CVE-2026-54428](history.md#sec-2026-001)** (`aws`): Fix the HTTP/2 vulnerability by upgrading httpcore5-h2 from 5.4 to 5.4.4.
- **[CVE-2026-64607](history.md#sec-2026-001)** (`aws`): Fix the HTTP Client vulnerability by upgrading httpclient5 from 5.6.1 to 5.6.4.

<details>
<summary>Earlier record links</summary>

<a id="sec-2026-002"></a>

[SEC-2026-002 — historical record](history.md#sec-2026-002)

<a id="sec-2026-003"></a>

[SEC-2026-003 — historical record](history.md#sec-2026-003)

<a id="sec-2026-005"></a>

[SEC-2026-005 — historical record](history.md#sec-2026-005)

<a id="sec-2026-008"></a>

[SEC-2026-008 — historical record](history.md#sec-2026-008)

</details>
