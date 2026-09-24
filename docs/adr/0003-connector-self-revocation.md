# Connector self-revocation from OpenCode

## Decision

The local `/remote` dialog opens token details when the user selects **Active token**. The details screen shows the service, connector, and expiration, with **Back** and **Revoke remote access** actions. Revocation asks for confirmation; cancellation returns to the details screen. This revokes the connector authorization, not an OpenCode conversation or the user's browser login. The credential itself is never displayed.

`POST /v1/connectors/self/revoke` accepts only the connector's bearer credential. The service hashes the credential, locks the matching connector, records `revoked_at`, and appends one `connector.revoked` audit event in the same transaction. It accepts no target identifier. Repeated calls with the same revoked credential return 204, allowing retries after a lost response. The retained hash cannot authorize relay access. Expired, unknown, and non-connector credentials cannot initiate revocation. An otherwise valid connector can revoke itself even if its account is disabled: reducing access must remain possible.

New relay tickets and consumption of previously issued tickets reject revoked connectors. Active connector sockets revalidate persisted account, identity, credential expiry, and revocation immediately and every second. Each check has a one-second deadline; failure closes the socket. This bounds revocation for idle sockets and sockets admitted concurrently with revocation to approximately two seconds under normal scheduling. Browser sockets retain their existing lease and other connectors remain independent. (Client sockets are now revalidated too; see [ADR 0017](0017-account-device-revocation.md). The per-second check is replaced by closing sockets when the revocation commits, with a 30-second safety check; see [ADR 0021](0021-event-driven-relay-revocation.md).)

Only after the remote service confirms success does the TUI remove pending pairing state, the revoked connector key, and local authorization. The server plugin monitors local authorization every 250 milliseconds and stops its relay, pending admission, and reconnect timer when authorization is removed, changed, unreadable, or expired. Deleting the old key allows restarting OpenCode to create a fresh identity and pair again; a revoked identity cannot silently regain trust. Revocation does not initiate pairing automatically.

This ordering is superseded by [ADR 0015](0015-local-first-connector-revocation.md): the TUI now clears local pairing state, the connector key, and authorization before calling the endpoint, queuing the credential for a retried call so a slow, offline, or hostile server can no longer keep the local relay running past a revoke request. The endpoint's own contract, the dialog flow, and idle-socket revalidation described here are unchanged.

## Threat analysis and failure behavior

- A caller cannot select a different account or connector to revoke. Possession of a connector credential permits only revoking that connector. A stolen credential gains denial-of-service power but no additional access.
- Browser Origin and cross-site requests are rejected and the endpoint is rate limited. Credentials travel in headers to the stored, validated service origin; the plugin rejects redirects for revocation.
- The TUI reads local 0600 state and keeps credentials out of dialog text, model prompts, URLs, and logs. API failure text is replaced with a fixed retry message. Audits contain only opaque account/connector IDs, event type, and time.
- Cancelling confirmation sends no request. A stale dialog checks authorization before making any change. A successful server revocation remains effective if the TUI crashes before cleanup; retries are idempotent. (Superseded by [ADR 0015](0015-local-first-connector-revocation.md): local cleanup no longer waits on the server call, and a failed call leaves the credential queued for a retry rather than restoring the authorization the user asked to revoke.)
- Removing local files alone cannot invalidate a copied credential; server revocation is required. A malicious server or compromised local host remains outside the protection provided by this action. Existing in-flight work is not rolled back; remote operations remain read-only in this release.
- Instances sharing `OPENCODE_REMOTE_DATA_DIR` share one connector identity and are revoked together. Separate connector identities require separate data directories, as before.

## Verification

Plugin tests cover confirmation/cancellation, duplicate confirmation, stale state, safe failure messages, credential retention, local cleanup, and monitor shutdown. An integration test runs the real plugin and TUI against an HTTP/WebSocket simulator and verifies that revocation stops the running relay without a restart. Server tests cover credential/account isolation, idempotency, audit rollback, the HTTP contract, and idle socket revocation. PostgreSQL integration exercises pairing, the revocation endpoint, live socket closure, unused-ticket rejection, credential redelivery rejection, inventory filtering, and the single audit record.
