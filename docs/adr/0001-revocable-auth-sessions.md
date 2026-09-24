# ADR 0001: Revocable Server-Side Authentication Sessions

## Status

Accepted for the account authentication foundation. The registration decision below — that local registration creates active, unverified users behind a development-only flag — is superseded by ADR 0008, which adds email verification and enables registration by default. The rest of this ADR stands.

## Context

Open Remote Code needs browser authentication before device pairing and authenticated relay admission can be implemented. Authentication does not establish end-to-end device trust, and the server must not turn an account login into implicit connector authorization.

The primary threats for this phase are database disclosure, password guessing, account enumeration, refresh-token theft or replay, cross-site requests, accidental credential logging, and resource exhaustion from expensive password hashing.

## Decision

- GORM `v1.31.2` and its PostgreSQL driver define and apply the identity schema with transactional `AutoMigrate` at startup.
- Users have explicit `pending`, `active`, and `disabled` states. Local registration currently creates active, unverified users because email delivery is not implemented. The route is disabled unless the process explicitly enables development registration under `APP_ENV=development`.
- Passwords use Argon2id with RFC 9106's 64 MiB option: three passes and four lanes, a random 16-byte salt, and a 32-byte result.
- At most four Argon2 operations execute concurrently in one server process, bounding configured hashing memory near 256 MiB.
- Login failures do not distinguish missing users, wrong passwords, or inactive accounts. Missing-user attempts run against a startup-generated dummy hash.
- Access credentials are random opaque 256-bit values with a 15-minute lifetime. PostgreSQL stores only their SHA-256 hashes.
- Browser refresh credentials are random opaque 256-bit values with a fixed 30-day session-family expiry. PostgreSQL stores only their SHA-256 hashes.
- Refresh credentials rotate on every use. GORM transactions lock both the credential and session rows with `FOR UPDATE` before changing state.
- Reuse of a consumed refresh credential revokes the entire auth session and appends a security audit event.
- Refresh credentials use HTTP-only, SameSite Strict cookies. Secure deployments use the `__Host-` prefix with a root path so sibling domains cannot inject a competing cookie. Compose explicitly permits a separately named insecure loopback development cookie.
- State-changing browser endpoints enforce an exact origin allowlist and reject cross-site Fetch Metadata requests without an Origin header.
- Registration, login, and refresh have separate bounded in-memory rate limits keyed by the direct peer address. Forwarded addresses are considered only when the direct peer is in an explicit trusted-proxy CIDR.
- Authentication request bodies, token values, password hashes, authorization headers, and cookies are never logged.

## Consequences

Database disclosure does not directly disclose passwords or live credential values. A stolen refresh credential remains useful until it rotates, expires, is reused, or is revoked. A stolen access credential remains a bearer credential until its short expiry or session revocation.

Refresh reuse detection deliberately treats concurrent use as possible theft. Two tabs rotating the same credential, or retrying after a lost successful response, will revoke that session family. Browser and native clients must single-flight refresh operations and return to login when rotation outcome is uncertain.

The current rate limits are suitable for the single-process phase but reset on restart. A production edge must use `TRUSTED_PROXY_CIDRS` to establish an authenticated client-address boundary or provide a shared limiter before horizontal deployment.

GORM AutoMigrate is additive and does not replace deployment-time schema review. Destructive schema changes require a separately reviewed migration strategy rather than relying on AutoMigrate to remove columns or constraints.

Email verification, password recovery, multi-factor authentication, device trust, relay tickets, and authenticated relay admission remain outside this decision. The development relay remains loopback-only and unauthenticated.
