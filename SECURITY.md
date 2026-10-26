# Security policy

Reviewed repairs and verification events are recorded in the [text security ledger](docs/security/README.md). Its JSONL source, generated CVE/event index and durable evidence are kept in Git. It is not a complete vulnerability inventory; current scan reports and limitations remain documented below.

Report vulnerabilities through [private vulnerability reporting](https://github.com/rambow-cloud/keycloak/security/advisories/new). Do not publish exploit details, credentials, or real user data in public issues. If private reporting is unavailable, contact an organization maintainer to establish a private channel first.

Only the image combination pinned on main is maintained. Older releases receive no automatic backports. Upgrades, CVE remediation, and exceptions require issues. A security fix may reference a sanitized maintenance issue while sensitive details remain in the private report.

Distroless, UID 65532, a shell-free runtime, and least privilege reduce attack surface. They do not replace vulnerability scanning, access controls, backups, or secure configuration. This initial project makes no FIPS certification or zero-vulnerability claim.

CI uses Trivy to scan both built image profiles and reports public CVE findings in PR comments and JSON artifacts. Fixable HIGH/CRITICAL findings, scanner failures and EOL OS results fail the required check. Unfixed findings remain visible. See [scan policy and limits](docs/vulnerability-scanning.md). Scanner upgrades, remediation and policy exceptions require reviewed Issues; do not silently suppress findings to pass CI.

Production deployments must use external PostgreSQL, HTTPS or a trusted TLS-terminating proxy, runtime secrets, an explicit hostname, container memory limits, and a read-only root filesystem. Expose management port 9000 only to the monitoring network.
