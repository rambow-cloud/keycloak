# Alibaba Cloud PolarDB for PostgreSQL (experimental)

Use the **core** image and the PostgreSQL JDBC driver already bundled with Keycloak. Alibaba documents standard PostgreSQL JDBC connectivity for this engine. This is a compatibility configuration, not a claim that PolarDB appears in Keycloak's officially supported database matrix. Live PolarDB schema, migration, and authentication tests have not been run.

This guide targets the centralized PostgreSQL edition, initially using PostgreSQL 17 where available. MySQL, Oracle-compatible, distributed, global-database, and automatic read/write-splitting deployments need separate validation. The Oracle-compatible product's `com.aliyun:polardb` driver and dialect instructions must not be applied to this PostgreSQL profile.

References: [PolarDB PostgreSQL connections](https://www.alibabacloud.com/help/en/polardb/polardb-for-postgresql/connect-to-polardb/), [Keycloak supported databases](https://www.keycloak.org/server/db).

## Endpoint and network

Start from [polardb-postgresql.env.example](../examples/polardb-postgresql.env.example). Select the **private primary endpoint** and actual port in the PolarDB console; do not infer the endpoint type from its hostname. The primary endpoint routes reads and writes to the primary node and follows primary failover.

Alibaba recommends cluster endpoints for general workloads, but those endpoints can split reads and writes across nodes. Keycloak uses multiple pooled connections, so session consistency on one connection does not establish cross-connection read-after-write behavior. Using the primary endpoint is this project's conservative default, not an Alibaba requirement. Do not route this profile to a reader endpoint or add SQL hints/transaction-splitting settings to Keycloak's queries.

Place the workload on a network that can reach the private endpoint, and configure the cluster IP allowlist/security groups for the actual workload egress addresses. Prefer private connectivity over a public endpoint. No local DNS checks are needed for this configuration review; use cloud-side endpoint status and the application integration results.

References: [endpoint types](https://www.alibabacloud.com/help/en/polardb/polardb-for-postgresql/view-or-apply-for-an-endpoint), [consistency levels](https://www.alibabacloud.com/help/en/polardb/polardb-for-postgresql/consistency-levels).

## TLS and credentials

1. Enable TLS for the chosen PolarDB endpoint and obtain the correct database CA bundle from the cluster's SSL configuration.
2. Mount the PEM CA file read-only at `/run/certs/polardb-ca.pem`, readable by UID 65532.
3. Set `KC_DB_TLS_MODE=verify-server` and `KC_DB_TLS_TRUST_STORE_FILE=/run/certs/polardb-ca.pem`. Keycloak maps these native options to the PostgreSQL driver's certificate and hostname verification settings.
4. Inject the dedicated application's `KC_DB_PASSWORD` through the runtime secret mechanism. Do not commit passwords or place them in `KC_DB_URL`. No Alibaba RAM access keys, SDKs, or AWS wrapper plugins are needed for this password-based PostgreSQL connection.

Do not use `sslmode=disable`, `require`, non-validating SSL factories, or hostname-verification bypasses to resolve a certificate error. Confirm that the selected endpoint is covered by the server certificate. Do not copy the older JDBC driver versions or insecure sample TLS choices from introductory examples; use Keycloak's pinned bundled driver.

For CA rotation, prepare the replacement bundle (including overlap certificates when provided), update the read-only mount, and roll the task/container so new connections use it. Test the replacement in staging before changing production. Database CA trust is separate from the application's public HTTPS certificate.

If the cluster requires **client certificates**, additionally mount a PostgreSQL-compatible PKCS#12 client keystore, with private-key alias `user`, and configure `KC_DB_MTLS_KEY_STORE_FILE`, `KC_DB_MTLS_KEY_STORE_TYPE=PKCS12`, and runtime-injected `KC_DB_MTLS_KEY_STORE_PASSWORD`. Generate/convert keys outside the production image. Client-certificate support is configuration guidance pending live mTLS validation.

References: [PolarDB PostgreSQL TLS](https://www.alibabacloud.com/help/zh/polardb/polardb-for-postgresql/ssl-connect-to-the-polardb), [Keycloak TLS/mTLS options](https://www.keycloak.org/server/db).

## Database permissions and connections

- Use a dedicated database/schema and application user. Make that user the owner or grant the DDL/DML privileges needed to create and migrate Keycloak tables, indexes, sequences, and migration-lock objects. A DML-only read/write account cannot initialize or upgrade the schema.
- `KC_DB_SCHEMA` selects the intended schema; ensure its ownership and search-path permissions are correct. Do not use the system `postgres` database for application data.
- Budget `number of tasks * KC_DB_POOL_MAX_SIZE` plus migration/administrative headroom against the cluster connection limit. The sample maximum of 20 is a starting point, not a capacity guarantee.
- Keep `KC_DB_CONNECT_TIMEOUT=10s` initially. Set `KC_DB_POOL_MAX_LIFETIME` below an enforced proxy/server idle lifetime if one exists, based on the actual deployment; there is no universal PolarDB timeout to hardcode.
- Retain the existing Keycloak database when changing images. Realm export/import is not a full database backup or an equivalent upgrade path.

## External staging verification

Deploy the core image against a dedicated PolarDB staging database using the example settings, then follow [external staging verification](rds-postgresql.md#external-staging-verification). Leave IAM refresh mode unset. The verifier creates an isolated realm, performs writes, validates signed client-credentials tokens, and removes its test realm. It runs outside the production image against an existing HTTPS service and provisions no cloud resources.

Acceptance before declaring this PolarDB configuration production-validated:

- An empty application schema initializes successfully with the application account.
- Realm/client/user creation and signed tokens pass the external verifier across pooled connections.
- Wrong CA and hostname fail; verified TLS succeeds with the cluster's real certificates.
- A supported previous Keycloak image's database upgrades to the candidate image after a staging snapshot, with existing user IDs and realms preserved; migrations and authentication complete successfully.
- After a controlled primary failover, connections recover through the primary endpoint and authentication resumes. This does not promise transparent transaction replay or a recovery-time SLA.
- If client certificates are required, test both valid and rejected client credentials separately.

In a browser, open `https://YOUR_HOST/realms/YOUR_REALM/.well-known/openid-configuration` and verify issuer/endpoint URLs, then open `https://YOUR_HOST/admin/` and verify login/redirects. Record the actual PolarDB engine version, image digest, endpoint type, and results in the linked Issue. Until these cloud checks are recorded, compatibility remains **experimental**.
