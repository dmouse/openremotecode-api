# Open Remote Code Server

This directory contains the Go modular monolith. It provides account authentication, connector/device pairing, persistent trust, relay-ticket issuance, and an account-isolated opaque WebSocket relay.

## Startup Flow

The entry point follows a **thin composition root** / **step-down** style. Start at
`cmd/server/main.go`: `main()` initializes logging and calls `start()`, which reads
top to bottom as:

```text
LoadConfig()
SetupDatabase()
SetupServices()
RegisterRoutes()
Run()
```

Each step has one place to follow for its details:

| Step | File | Responsibility |
| --- | --- | --- |
| `LoadConfig` | `cmd/server/config.go` | Load environment settings with Viper and validate TLS, pairing metadata, proxy CIDRs, and development switches before opening the database. |
| `SetupDatabase` | `cmd/server/setup.go` | Open the PostgreSQL pool and run identity and connector migrations under a startup timeout. |
| `SetupServices` | `cmd/server/setup.go` | Wire repositories, services, and cross-module authorization callbacks. |
| `RegisterRoutes` | `cmd/server/routes.go` | Build the Gin router and register health, identity, connectors, and relay endpoints. |
| `Run` | `cmd/server/transport.go` | Serve HTTP/TLS with bounded timeouts and drain HTTP requests on SIGINT/SIGTERM. |

Resources are owned by `start()`: relay connections close before the database
pool when startup fails or the server exits. Concrete dependencies are passed
explicitly; application services remain independent of Gin and Viper.

Gin routing policy lives in `internal/platform/httpserver/router.go`. Identity,
connectors, and health each expose `RegisterRoutes`; HTTP helpers retain their
strict JSON decoding, origin checks, cookie handling, and rate limits. The Gin
adapter transfers named route parameters to `http.Request.PathValue`. JSON GET
endpoints also register HEAD for existing health checks and clients. Relay
upgrades accept GET only. Unknown routes return 404, unsupported methods return
405, and automatic path/trailing-slash redirects are disabled.

Viper uses a fresh instance per load and returns a typed configuration snapshot.
Existing environment variable names and development defaults remain supported;
empty values fall back to defaults. Configuration files are not automatically
discovered. Invalid boolean values fail startup instead of being coerced to
false, and production cannot enable insecure development features.

See [the Gin/Viper architecture decision](docs/adr/0007-gin-viper-startup.md)
for routing, logging, and trust-boundary details.

## Docker Development

From the repository root, start the Go server and PostgreSQL:

```sh
docker compose up --build
```

The development server is available only on the loopback interface at `http://127.0.0.1:8080`. PostgreSQL is available at `127.0.0.1:5432`. Connect with the [native mobile client](../mobile/README.md#local-android-development).

Air watches `server/**/*.go`, `go.mod`, and `go.sum` through the bind-mounted source directory. Saving a Go source change rebuilds `./cmd/server`, gracefully interrupts the previous process, and starts the replacement without rebuilding the container image.

Useful commands:

```sh
docker compose logs -f server
docker compose down
docker compose down --volumes
```

`docker compose down` preserves the PostgreSQL and Go cache volumes. Use `--volumes` only when intentionally resetting all local database state and build caches.

Override host ports when the defaults are occupied:

```sh
SERVER_PORT=18080 POSTGRES_PORT=15432 docker compose up --build
```

## Authentication

The versioned API contract is in `api/openapi.yaml`. GORM models own the PostgreSQL schema and run `AutoMigrate` transactionally when the server starts.

The current API includes:

- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `POST /v1/auth/google`
- `POST /v1/auth/verify-email`
- `POST /v1/auth/resend-verification`
- `POST /v1/auth/refresh`
- `POST /v1/auth/logout`
- `GET /v1/account`
- `POST /v1/connector-pairings/challenge`
- `POST /v1/connector-pairings`
- `POST /v1/devices/challenge`
- `POST /v1/connector-pairings/claim`
- `POST /v1/connector-pairings/{pairingId}/confirm`
- `POST /v1/connector-pairings/{pairingId}/poll`
- `GET /v1/connectors`
- `GET /v1/connectors/self` (connector ID and original linking date, authenticated by its own credential)
- `POST /v1/connectors/self/revoke` (connector bearer credential only)
- `POST /v1/devices/self/rotate` (account session + device ID + current device cookie)
- `POST /v1/devices/self/rotate/activate` (authenticated by the pending device cookie; commits the rotation)
- `POST /v1/connectors/self/rotate` (connector bearer credential only; issues a replacement the caller must activate)
- `POST /v1/connectors/self/rotate/activate` (authenticated by the pending credential; commits the rotation)
- `POST /v1/relay/tickets`
- `GET /v1/relay` (WebSocket upgrade)

Registration creates a `pending` account and mails it a six-digit code; only `POST /v1/auth/verify-email` activates the account and issues a session. Until then the account holds an unauthenticated verification ticket scoped to verify-email and resend-verification alone, so a pending account reaches no authenticated route, cannot pair a device, and cannot obtain relay admission. Registering an address that already exists is answered identically to a new registration, and the address owner is notified by mail instead, so the endpoint cannot be used to discover whether an account exists. See [the email-verified registration decision](docs/adr/0008-email-verified-registration.md).

Passwords use Argon2id with the RFC 9106 low-memory recommendation. Access credentials are opaque, short lived, and kept out of cookies. Refresh credentials are hashed in PostgreSQL, rotate on every use, and use the existing HTTP-only, SameSite Strict cookie contract. The native client extracts the credential into secure storage and forwards it explicitly to the same server; it does not use a browser cookie jar. Reusing a rotated refresh credential revokes the entire auth session.

Pairing challenges are single use. Pairing secrets, human codes, mobile device credentials, connector credentials, and relay tickets are stored only as hashes. Both mobile and connector identities prove possession with standard P-256 ECDSA/SHA-256 signatures. The connector must poll and observe the stable transcript before confirmation. Confirmation idempotently creates the account-scoped trust edge and installs both durable credentials in one transaction.

A connector renews its 90-day credential without re-pairing. Rotation issues a replacement that grants nothing until the connector activates it, so a plugin that never persists or never activates the new value keeps working on its current one; connecting on the current credential instead cancels the pending rotation, and an unactivated rotation lapses after fifteen minutes without invalidating anything. The renewed lifetime starts at activation. Rotation is not revocation and does not close a live relay connection, since admission resolves the connector by ID rather than by credential value. Device credentials rotate the same way, with the same provisional-until-activated semantics; the
replacement is returned in the body and only becomes a cookie once activated, so the credential the
client still needs is never overwritten. Device rotation is authenticated by the account session,
the device ID and the current device cookie together, exactly as relay-ticket issuance is.

`DEVICE_CREDENTIAL_KEY` derives device credentials and is separate from `PAIRING_CODE_KEY`, which
hashes user codes; it is seeded from `PAIRING_CODE_KEY` when unset, so an existing deployment keeps
its devices. The split exists so either key can be rotated without disturbing what the other derives. Only
pairing confirmation derives a device credential; every authentication path resolves a device by the
stored hash of the credential presented, so rotating `DEVICE_CREDENTIAL_KEY` leaves already-paired
devices working. The only casualty is the re-confirmation of a pairing completed under the previous
key, and a pairing lives ten minutes. See [ADR 0012](docs/adr/0012-connector-credential-rotation.md)
and [ADR 0013](docs/adr/0013-device-credential-rotation.md).

Compose explicitly enables insecure cookies and the legacy unauthenticated relay under `APP_ENV=development`. It leaves `SMTP_HOST` unset, which selects the development mailer that writes verification codes to the server log rather than sending them — read the code from `docker compose logs server`. Mobile and plugin connections use the authenticated `/v1/relay` path. Launch the local plugin with `OPENCODE_REMOTE_ALLOW_INSECURE_LOOPBACK=true opencode` to opt into the development stack's HTTP/WS transport. Outside this development stack, development features are disabled and cookies default to `Secure` host-bound names. Production startup requires a secret `PAIRING_CODE_KEY`, stable `SERVICE_ID`, HTTPS `PAIRING_VERIFICATION_URI`, working SMTP settings as described below, and valid TLS certificate files. Trust only forwarding proxies that sanitize and append headers.

Registration is enabled by default in every environment. `REGISTRATION_ENABLED=false` is an operational kill switch, not a security control; a malformed value stops startup rather than silently closing the route. It governs the mailed-code flow only and does not affect Google sign-in.

## Google Sign-In

`POST /v1/auth/google` exchanges a Google-issued OpenID Connect ID token for a session, and both signs in and registers. It is **off unless configured**: set `GOOGLE_OAUTH_AUDIENCES` to a comma-separated list of the OAuth client IDs a token may be addressed to, and leave it unset to have the route report `503 google_signin_unavailable`. Client IDs are public identifiers; this design has no OAuth client secret on either side.

```
GOOGLE_OAUTH_AUDIENCES=111111111111-web.apps.googleusercontent.com,222222222222-ios.apps.googleusercontent.com
```

Verification uses `google.golang.org/api/idtoken` for the signature, audience, and expiry, plus this server's own checks on the issuer, the subject, the address, and Google's `email_verified` claim. An empty audience list is rejected at startup rather than defaulted, because `idtoken` skips the audience check entirely when given an empty string.

Accounts are resolved by the token's subject first, then by address. An address no account holds produces a new active, already-verified account with no password. An existing account is linked only when its address has been proved — either already verified, or still pending, in which case Google's assertion completes the verification. **An active account whose address was never verified is refused with `409 account_link_required`**, and the user signs in with their password instead; linking it would hand the account to whoever controls that address today. Accounts created before [ADR 0008](docs/adr/0008-email-verified-registration.md) are all in that state. See [the federated sign-in decision](docs/adr/0009-google-federated-sign-in.md).

`users.password_hash` is nullable so a federated account can have no password. A password sign-in against such an account is refused as ordinary invalid credentials.

### Registering the OAuth clients

In the Google Cloud console, under **APIs & Services → Credentials**, create OAuth 2.0 client IDs for the platforms you ship:

- **Web application** — the `serverClientId` both mobile platforms request their ID token for. Its client ID must appear in `GOOGLE_OAUTH_AUDIENCES`.
- **Android** — package name `com.openremotecode.app` plus the SHA-1 of the signing certificate (one per debug and release key).
- **iOS** — the app's bundle identifier. Its client ID must also appear in `GOOGLE_OAUTH_AUDIENCES`, and its reversed form becomes a URL scheme in the app; see the mobile README.

Configure the OAuth consent screen before the clients will issue tokens to anyone outside your test users.

## Mail

Verification codes are delivered over SMTP or Mailgun's HTTPS API — configure exactly one; `setupMailer` prefers Mailgun when `MAILGUN_API_KEY` is set and falls back to SMTP. Production requires one of them fully configured. See [ADR 0010](docs/adr/0010-mailgun-http-mailer.md) for why there are two.

**SMTP** uses the Go standard library, with no third-party dependency. Configure `SMTP_HOST`, `SMTP_PORT` (default `587`), `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_ADDRESS`, and `SMTP_TLS_MODE` (`starttls` by default, or `tls` for providers requiring implicit TLS on port 465). Production requires `SMTP_HOST` and `SMTP_FROM_ADDRESS` and rejects `SMTP_TLS_MODE=none`. Sends carry a ten-second deadline on both the dial and the session, so an unresponsive mail host cannot hang a request.

**Mailgun** talks to `api.mailgun.net` (or `api.eu.mailgun.net` with `MAILGUN_REGION=eu`) over HTTPS instead of SMTP, so it isn't affected by a host or network that blocks outbound SMTP ports — a common cloud-provider default. Configure `MAILGUN_API_KEY` (the private API key from Mailgun → Settings → API Keys, not an SMTP credential), `MAILGUN_DOMAIN` (a sending domain verified in Mailgun), and `MAILGUN_FROM_ADDRESS`. A partially set Mailgun configuration fails startup in every environment rather than silently falling through to SMTP or the logging mailer.

Mail is sent after the account is committed, so a delivery failure still returns a usable verification challenge; the user recovers by requesting a new code or signing in again. A permanent per-recipient rejection records `emailBounced` on the account for diagnostics only — it never blocks a resend or any other operation, and a later successful send clears it. **This only happens over SMTP.** The Mailgun mailer never sets it: Mailgun's messages endpoint has no synchronous per-recipient rejection the way an SMTP `RCPT TO` reply does, so every failure it reports is treated as transient (see ADR 0010). In development, leaving both unset logs the code instead of sending it; this is the one deliberate exception to never logging credentials, and the configuration loader rejects it outside development.

The browser testing client has been removed. `BROWSER_ORIGINS` defaults to an empty
allowlist; native requests do not send an Origin header. Origin and Fetch Metadata
checks remain active. `PAIRING_VERIFICATION_URI` remains required metadata in the
existing contract (the local API origin in development), not a hosted pairing
screen or a mobile deep link. Pairing is completed in the mobile app using the
short code. See [the mobile-only client decision](docs/adr/0006-mobile-only-client.md).

Relay tickets are short lived and atomically consumed before upgrade. Existing sockets have a maximum five-minute authorization lease, capped by session and durable-credential expiry. Clients reconnect with a fresh ticket, which rechecks active account, session, device, connector, and trust state.

Connectors can revoke their own authorization from OpenCode's `/remote` dialog. Revocation immediately prevents new tickets and use of unconsumed tickets. Active connector sockets also revalidate authorization every second, with a one-second check timeout, so idle sockets close after revocation. See `docs/adr/0003-connector-self-revocation.md` for failure behavior and the threat analysis.

## Production TLS

Outside `APP_ENV=development`, the API serves HTTPS/WSS and requires both `TLS_CERT_FILE` and `TLS_KEY_FILE`. They must point to a PEM certificate chain and matching PEM private key. Missing, partial, or unreadable TLS configuration stops startup before database access or listener creation. The minimum TLS version is 1.2. There is no HTTP fallback or API redirect listener.

For a reverse proxy on the same host, keep the Go listener private:

```sh
export HTTP_ADDR=127.0.0.1:8443
export TLS_CERT_FILE=/run/secrets/api-cert.pem
export TLS_KEY_FILE=/run/secrets/api-key.pem
```

Supply the remaining production settings above and start the server. `HTTP_ADDR` is the listener address for either transport and defaults to `127.0.0.1:8080`. Container deployments can explicitly bind an internal interface, but must restrict access to the proxy with network policy or firewall rules.

Configure the edge to expose HTTPS/WSS only, send Strict-Transport-Security, support WebSocket upgrades, and use **HTTPS for its upstream connection to Go**. The upstream certificate must match the proxy's configured server name and chain to a CA it trusts. Configure that CA explicitly for private certificates; keep certificate and hostname verification enabled. Redact authorization, cookies, tickets, and WebSocket subprotocol headers from proxy logs. Protect the key file with restricted permissions. Certificates are loaded at startup; restart the server after rotation.

`APP_ENV=development` permits HTTP when both certificate settings are absent; Compose already sets this and publishes ports on loopback only. If either certificate setting is supplied, valid TLS configuration is required even in development. This server setting and the plugin's `OPENCODE_REMOTE_ALLOW_INSECURE_LOOPBACK` flag are independent and must be set in their respective processes.

See the [transport security ADR](../packages/agents/opencode/docs/adr/0004-transport-security.md) for the threat analysis and test coverage. Certificate issuance, proxy configuration, and verification of a deployed endpoint are deployment responsibilities.

## Client Access Tag

Every request from the plugin and mobile client carries an `X-Orc-Access` header. Set `CLIENT_ACCESS_TAG` to the value your release of those clients sends and the server rejects any request missing or mismatching it, before it reaches auth or business logic; leave it unset (the default) to disable the check. `/health/live` and `/health/ready` are always exempt, since container and edge health probes call them directly without application headers.

This is **not** an authentication or authorization control and must never be treated as one: the expected value ships in this project's open-source plugin source and in the compiled mobile app, so anyone can read or extract it. It only reduces log noise from automated scanners and bots that don't bother sending it. Real access control is unchanged — it still comes entirely from account, device, connector, and session credentials. Because the value is embedded in shipped clients rather than issued per device, rotating it requires a new plugin/mobile release; older clients are rejected until they update.

## Health

- `GET /health/live` reports whether the HTTP process is running.
- `GET /health/ready` reports whether the authenticated PostgreSQL connection can execute a ping.
- `GET /dev/relay` upgrades local development clients and connectors to the opaque WebSocket relay.
- `GET /v1/relay` consumes an account-bound ticket from the WebSocket subprotocol header before upgrading.

Readiness returns a generic failure response and does not expose dependency details.

## Relay Protocol Version

Both relay endpoints speak relay protocol version 2 and reject other versions explicitly.
Version 2 added the per-connection `nonce` on each hello and the `epoch` on each envelope,
which together stop an envelope captured in one connection from being replayed into
another. The relay forwards nonces unchanged and validates only the shape of both fields;
peers enforce freshness. Connector and device identities are versioned separately and stay
at version 1, so a relay protocol revision never invalidates a stored identity or forces
re-pairing. See [ADR 0011](docs/adr/0011-relay-connection-epochs.md).

## Development Only

The Compose defaults use known local secrets and bind published ports to `127.0.0.1`. `/dev/relay` has no account authentication or pairing and exists only for the real-OpenCode test harness. It must not be exposed publicly or reused as production configuration.

## Server Checks

With the development stack running, execute checks inside its Go container:

```sh
docker compose exec -T server go vet ./...
docker compose exec -T -e CGO_ENABLED=1 server go test -race ./...
docker compose exec -T -e CGO_ENABLED=1 server sh -c 'DATABASE_TEST_URL="$DATABASE_URL" go test -race -tags=integration ./...'
```

PostgreSQL integration tests use isolated temporary schemas and remove them at
the end. They cover authentication/refresh rotation, account isolation, pairing,
single-use tickets, and a real WebSocket upgrade and revocation through Gin.
The development image includes GCC and musl headers for Go's race detector;
rebuild it with `docker compose up --build -d server` after updating the Dockerfile.
