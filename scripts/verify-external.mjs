// Run against an existing dedicated staging Keycloak deployment; never provisions cloud resources.
import { verifyKeycloak } from '../tests/keycloak-protocol.mjs';

if (process.env.VERIFY_ALLOW_MUTATION !== 'dedicated-staging') throw new Error('Set VERIFY_ALLOW_MUTATION=dedicated-staging: verification creates and removes a test realm.');
const baseUrl = process.env.VERIFY_BASE_URL;
if (!baseUrl || !process.env.VERIFY_ADMIN_USERNAME || !process.env.VERIFY_ADMIN_PASSWORD) throw new Error('Set VERIFY_BASE_URL, VERIFY_ADMIN_USERNAME, and VERIFY_ADMIN_PASSWORD.');
const url = new URL(baseUrl);
if (url.username || url.password || url.search || url.hash) throw new Error('Base URL must not contain credentials, query parameters, or fragments.');
if (url.protocol !== 'https:') throw new Error('External verification requires an HTTPS base URL.');
const refresh = process.env.VERIFY_IAM_REFRESH === 'true';
const durationSeconds = Number(process.env.VERIFY_DURATION_SECONDS ?? (refresh ? '960' : '0'));
if (!Number.isSafeInteger(durationSeconds) || durationSeconds < 0 || (refresh && durationSeconds < 960)) throw new Error('Duration must be a nonnegative integer; IAM refresh verification needs at least 960 seconds.');
await verifyKeycloak({ baseUrl, username: process.env.VERIFY_ADMIN_USERNAME, password: process.env.VERIFY_ADMIN_PASSWORD, durationSeconds });
if (refresh) console.log('Long-running protocol checks passed. Confirm fresh database connections and task-role credential refresh in staging telemetry; duration alone is not certification.');
