# ADR 0002: Persistent Pairing and Relay Admission

## Status

Accepted for the read-only MVP.

## Context

The development relay required a browser public identity to be copied into the OpenCode launch command. The browser identity disappeared on reload, relay admission was not account scoped, and a durable credential would have been exposed if placed in a WebSocket URL.

Account login cannot itself establish end-to-end device trust. The server delivers the browser bundle and stores public trust metadata, so a pairing flow must detect accidental or malicious public-key substitution through an independent human comparison.

## Decision

- Connector and browser identities use P-256 for HPKE Auth and standard ECDSA/SHA-256 proof of possession. Each side signs a short-lived random server challenge. Challenges are account-bound where applicable, hashed at rest, locked during use, and single use.
- The safety transcript is a canonical JSON array containing a domain separator, protocol version, service ID, pairing ID, and the complete role-ordered connector and device public identities.
- Both clients SHA-256 hash that transcript and display the first 96 bits as six four-hexadecimal-digit groups. This safety code is an equivalent to a word phrase; it is not a secret. Pairing completes only after deliberate browser confirmation that the independently displayed codes match.
- Browser encryption and proof private keys are non-exportable `CryptoKey` objects persisted through IndexedDB structured cloning. The browser locally pins the connector identity.
- The plugin stores its HPKE identity, pending pairing authorization, and completed connector authorization in separate permission-restricted files. The pending file allows interrupted setup to resume and is deleted after completion or expiry. Completed authorization stores the connector credential and trusted browser public identity, never browser private material.
- Browser device credentials use host-bound, HTTP-only, SameSite Strict cookies. Connector credentials use opaque bearer tokens. The server stores only SHA-256 credential hashes.
- Every connection attempt obtains a 30-second, single-use relay ticket. Browser ticket issuance requires a valid account session, device ID, and device cookie. Connector ticket issuance requires its connector credential.
- The ticket is carried in the WebSocket subprotocol header alongside the static `opencode-remote.v1` protocol, not in a URL. The server atomically consumes it before upgrade and derives account, role, subject, key, and trusted peers from persisted state.
- Relay hello identity is compared with admission state rather than trusted as authentication. Routing requires the same account, opposite roles, and reciprocal active trust metadata. Relay frames remain live-only opaque ciphertext.
- Pairing confirmation requires the connector to have polled the safety transcript. It derives an idempotent browser credential and atomically installs connector authorization with the trust edge, so concurrent or retried confirmation cannot leave either client with a losing credential.
- Relay admission has a five-minute maximum authorization lease, capped by the authorizing access, device, or connector credential. Reconnection consumes a fresh ticket and rechecks account, browser session, device, connector, and trust state.
- An incomplete pairing can be cancelled only with its private pairing secret. Cancellation expires the record atomically and releases the connector key's one-active-pairing constraint; completed pairings cannot be cancelled through this operation.
- The `/remote` command is a native local TUI plugin, separate from the server plugin target. It reads the permission-restricted pending state and can request cancellation, while the server plugin remains responsible for creating replacement pairings, polling, credential installation, and relay startup. Pairing material is never submitted as a model prompt.

## Threat Analysis

Proof signatures prevent an attacker from registering another party's public key without controlling its private scalar. The account-bound device challenge prevents moving a browser proof between accounts. Row locks and conditional single-use state prevent concurrent challenge, pairing, and ticket reuse.

The safety code protects against server or network substitution only when the user compares the plugin and browser displays through independent surfaces. A user who confirms without comparing receives no such protection. Ninety-six displayed bits make an accidental match or online substitution impractical while keeping comparison manageable.

Pairing codes and pairing secrets authorize only a short-lived state machine. They are absent from paths, query strings, logs, and database plaintext. A stolen pairing secret before expiry can poll authorization state, so TLS and endpoint log redaction remain mandatory.

The same secret can cancel its incomplete pairing. This adds denial-of-service power but no account access or trust-establishment power; the connector supervisor issues a replacement code. The TUI displays only the human code and verification URI, never the pairing secret. A local process able to read the permission-restricted pairing file already falls within the documented host-compromise limitation.

The server can deny service, suppress presence, or route no frames. It cannot decrypt HPKE payloads or impersonate a proved and pinned peer. A malicious web bundle can read browser plaintext and use its non-exportable keys, so signed native clients remain a stronger trust boundary.

The plugin file credential is protected by filesystem permissions rather than an OS keychain in this MVP. Host compromise remains out of scope. Connector credentials do not yet rotate automatically. Connector self-revocation from `/remote` is defined in [ADR 0003](0003-connector-self-revocation.md).

Account/session changes take effect on an existing socket no later than its five-minute authorization lease. Connector sockets additionally revalidate account and connector authorization every second with a one-second timeout, as defined in ADR 0003. Browser logout also closes its socket before revoking the account session. (Superseded for client sockets by [ADR 0017](0017-account-device-revocation.md), and the per-second checks by [ADR 0021](0021-event-driven-relay-revocation.md): revocations now close sockets when they commit, with a 30-second safety check.)

Envelope replay tracking is complete as of [ADR 0011](0011-relay-connection-epochs.md), which defines connection epochs and per-epoch sequence windows. Bounded request journals and uncertain-outcome behavior are implemented in the plugin dispatcher, and mutating chat operations are enabled.

## Consequences

After one verified pairing, reloading the browser and restarting OpenCode restore local trust and require no copied launch configuration. Loss of IndexedDB, the plugin authorization file, or either private identity requires pairing again. Database loss also requires re-pairing because the server intentionally stores no recoverable durable secret.
