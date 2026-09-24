# Mobile-Only Client

## Decision

The browser application was a testing client and is retired. The supported user
interface is the Flutter mobile app. Remove the browser source, workspace package,
build/test commands, Compose service, and browser-only dependency graph. The public
website is a landing page; the other planned host is the HTTPS API/WSS relay.

OpenCode pairing instructions direct users to **Add connection** in the mobile
app. The `verificationUri` field remains in pairing responses and stored plugin
state for contract compatibility. In development it identifies the local API
origin; it does not promise a hosted pairing screen. Production still requires
an explicitly configured HTTPS URI. No deep-link handler is introduced.

## Security and Compatibility

Removing the UI must not invalidate native sessions or trust. The mobile client
already extracts refresh/device credentials from Set-Cookie responses into native
secure storage and sends them explicitly to the same origin. Keep the API routes,
cookie names, identity formats, crypto contexts, and account-isolation rules.

Remove the implicit development browser-origin allowlist. Native HTTP and relay
requests do not send Origin; authenticated browser-origin requests remain denied
unless explicitly allowlisted. Existing Fetch Metadata checks remain in place.
Retain negative origin/CSRF tests: a malicious browser can still target the API
even though the product no longer serves a browser bundle. No authorization check
is relaxed and no credentials or private keys are migrated or logged.

The mobile app currently has login rather than account registration UI. Existing
accounts remain usable; development accounts can be created via the existing
registration API when explicitly enabled. Mobile registration UI is separate work.

Earlier ADRs describe the browser-based testing phase. Their authentication,
pairing, and encryption decisions remain applicable, but browser UI/distribution
assumptions are superseded by this decision.

## Verification

Validate the remaining workspace build/tests and Compose configuration. Run Go
HTTP/authentication/relay tests, including native requests and hostile origins,
and the OpenCode integration tests for encrypted relay and persistent pairing.
The mobile client continues to use the same API and protocol contracts.
