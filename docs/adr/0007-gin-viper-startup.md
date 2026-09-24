# ADR 0007: Gin routing, Viper configuration, and a thin composition root

Status: Accepted

## Context

The server entry point mixed environment parsing, migrations, dependency wiring,
route registration, and listener lifecycle in one function. The desired reading
order is a high-level startup flow with named functions for each step. Introducing
Gin and Viper also requires preserving the existing transport trust boundaries.

## Decision

`cmd/server/main.go` owns a sequential composition root:
`LoadConfig → SetupDatabase → SetupServices → RegisterRoutes → Run`.
The caller owns cleanup; migration failures close the opened pool, and normal
shutdown closes the relay before the database. HTTP shutdown has a ten-second
deadline and forcibly closes remaining HTTP connections after that deadline.

Viper loads the existing environment names and defaults into a typed snapshot.
There is no global Viper registry, environment lookup inside a service, automatic
configuration-file discovery, or live configuration reload. TLS certificates and
all security-sensitive settings are validated before database initialization.

Gin owns HTTP routing. Feature transports register their routes on one engine;
domain/application services have no framework dependency. Existing net/http
handlers retain JSON validation, origin/Fetch Metadata checks, rate limits,
credential handling, and error mapping. A narrow adapter transfers Gin parameters
to `Request.PathValue` for pairing and connector operations. WebSocket handlers
use Gin's net/http adapter, which retains response hijacking support.

## Threat analysis

- **Configuration coercion:** Viper's boolean getters can silently turn malformed
  input into false. Development switches use strict `strconv.ParseBool` and reject
  malformed values with key-only errors. They remain forbidden outside explicit
  `APP_ENV=development`. Empty settings retain the previous fallback behavior.
- **Transport downgrade:** Production still requires valid TLS certificate and
  key files, a pairing secret of at least 32 bytes, a service ID, and an HTTPS
  verification URI. Certificate errors never fall back to HTTP.
- **Proxy spoofing:** Gin's default trust-all proxy behavior is disabled. Existing
  rate-limit helpers continue to interpret forwarding headers only for configured
  trusted CIDRs; registering Gin routes does not change the principal or client
  address used by authorization and rate limiting.
- **Route confusion:** Routes are explicit, case-sensitive, and method-scoped.
  Automatic path correction and trailing-slash redirects are disabled. Unsupported
  methods return 405; absent paths return 404. Standard JSON GET routes retain HEAD
  support; the relay accepts GET upgrades only. Named IDs still pass through the
  same service-level ownership and credential checks. Noncanonical paths are not
  public compatibility aliases.
- **Sensitive diagnostics:** The engine uses neither Gin's default request logger
  nor its request-dumping recovery middleware. Custom recovery logs only the
  static `HTTP handler panic` category and emits a generic 500. It never logs
  request URLs, headers, bodies, panic values, or stack dumps. If a response has
  already started, it aborts using `http.ErrAbortHandler` rather than writing a
  second response or allowing net/http to log the panic content.
- **Relay isolation:** The router never derives sender/account identity or inspects
  ciphertext. Ticket consumption, account isolation, authorization expiry,
  revocation, queues, and encrypted-frame handling remain in the relay and
  connector services. Relay sockets are explicitly closed by the composition root
  because HTTP shutdown does not close hijacked connections.

## Verification

- Viper tests cover development defaults, environment overrides, snapshot
  isolation, malformed security settings, secure production startup, and rejected
  production development flags.
- Gin tests cover method and path boundaries, named parameters, cache/security
  headers, proxy spoofing, and secret-free panic recovery.
- Existing HTTP authentication and connector contract tests run through Gin,
  including cross-origin rejection, rate limiting, cookies, and scoped operations.
- TLS tests exercise HTTPS and WSS through Gin and reject plaintext and old TLS.
- PostgreSQL integration tests use isolated schemas and include the authentication
  lifecycle, pairing, single-use tickets, account isolation, and a Gin WebSocket
  connection closed after connector revocation. Run these and the server suite
  with the race detector.

## Consequences

Startup is readable top to bottom, and concrete wiring remains at the entry point.
Gin and Viper add pinned dependencies but remain outside domain/service logic.
The OpenAPI operation paths and encrypted relay protocol are unchanged. Canonical
routes are required; framework-specific default 404/405 response text is not an
API contract. Configuration-file support can be added later as an explicit policy
rather than making startup depend on files found in the working directory.
