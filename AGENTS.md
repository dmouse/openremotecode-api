# Server Architecture

## Scope

This directory contains the multi-user Go service for Open Remote Code. It authenticates users and devices, coordinates connector pairing, issues relay admission tickets, routes live encrypted frames, and records security audit metadata.

The server is an untrusted relay with respect to conversation content. It must function without decrypting OpenCode prompts, responses, permissions, tool output, or session metadata carried inside the end-to-end encrypted protocol.

The root `AGENTS.md` defines product-wide constraints and takes precedence over this document.

## Architectural Style

Use a modular monolith with explicit feature ownership. Begin with one deployable Go service and one PostgreSQL database. Do not split modules into network services until operational evidence demonstrates that separate scaling or ownership is necessary.

The initial modules are:

- Identity: users, normalized email identities, password verification, auth sessions, refresh rotation, logout, and account status.
- Connectors: local OpenCode connector identities, client devices, public keys, pairing authorization, trust relationships, naming, and revocation.
- Relay: WebSocket tickets, authenticated connections, presence, routing, heartbeats, queue limits, and disconnect handling.
- Audit: append-oriented security events for authentication, pairing, trust changes, and revocation without recording message content.
- Platform: configuration, HTTP server lifecycle, PostgreSQL access, migrations, clocks, identifiers, logging, metrics, and other narrow infrastructure concerns.

Pairing is initially part of the connector domain because it exists to establish connector and device trust. It should become a separate module only if its lifecycle grows independently.

## Dependency Rules

- Transport handlers depend on application services, not directly on database implementations.
- Application services own use-case orchestration and transaction boundaries.
- Domain rules do not depend on HTTP, WebSockets, PostgreSQL, or framework types.
- Repository interfaces belong to the module that consumes them.
- PostgreSQL adapters implement module-owned persistence contracts.
- Modules communicate through narrow service interfaces, not by reading each other's tables.
- Service composition and concrete dependency wiring occur at the application entry point.
- Avoid generic repositories, global mutable registries, and a shared service-locator package.
- Keep related behavior together when splitting it would create ceremonial layers without a real boundary.

## Identity and Session Model

Users authenticate with email and password, or with a Google identity assertion. Passwords use a current Argon2id policy with per-password salts. Login errors must not reveal whether an account exists.

A federated account has no password at all, so `users.password_hash` is nullable and only `User.HasPassword` may test for one. A provider identity is bound to a local account by the provider's immutable subject, never by address, and is linked to an existing account only where the address has already been proved — see the account resolution order in ADR 0009. A provider assertion must be verified for signature, issuer, audience, and expiry behind the module's own verifier interface; no transport dependency belongs in the domain.

Use revocable server-side sessions rather than treating long-lived self-contained tokens as permanent authorization. Access credentials are short lived. Refresh credentials rotate on use, have explicit expiry and client identity, and are stored only as secure hashes on the server.

The native client extracts refresh/device credentials from the existing cookie-based API contract and persists them in native secure storage, with explicit credential forwarding only to the paired server. Plugin credentials remain in local secure storage. All credentials are sent only over TLS. Refresh reuse is treated as a security event and revokes the affected token family.

Registration, login, pairing, refresh, and relay-ticket issuance require separate rate limits. Production account activation and email verification should be represented as explicit account states even if local development initially bypasses mail delivery.

## Device and Connector Model

A user may own multiple client devices and multiple OpenCode connectors.

- A client device represents a mobile installation with its own public identity.
- A connector represents a local OpenCode plugin identity and its public keys.
- A live connector connection represents one active plugin process and may include an opaque endpoint identifier for a particular OpenCode workspace.
- Device and connector private keys never enter server storage.
- Revocation is independent for each auth session, client device, and connector.
- Route identifiers are random or keyed opaque identifiers. Filesystem paths and project names belong inside encrypted messages.

The server persists trust metadata and public keys but does not silently make every account session an end-to-end trusted device. Additional client devices require an explicit trust flow.

## Pairing

Pairing follows a short-lived device authorization flow:

1. An unpaired connector submits its public identity and proof of possession.
2. The server returns a private device authorization secret, a human-readable user code, an expiry, and a verification location.
3. An authenticated user reviews and approves the connector in a trusted client.
4. Connector and client independently derive and display a safety phrase from the pairing transcript and public keys.
5. User confirmation completes the trust relationship.
6. The connector receives revocable credentials bound to its identity.

Pairing records are single use, short lived, rate limited, and state-machine driven. Invalid state transitions fail closed. Human-readable codes do not serve as long-term secrets.

## Relay

Both connectors and clients establish outbound authenticated WebSocket connections. Relay admission uses a short-lived, single-use ticket obtained over the HTTPS API. Durable credentials must not appear in WebSocket URLs.

The relay authenticates the connection, derives its account and device identity, validates the outer envelope, verifies recipient ownership, and routes opaque ciphertext. It must not trust sender identifiers supplied in the frame.

Each hello carries the sending peer's connection nonce, which the relay forwards unchanged so both peers can derive the shared connection epoch that binds their envelopes. The relay validates the shape of the `nonce` and `epoch` fields and nothing more: freshness is enforced by the peers, because the relay is an untrusted router and is the wrong place to decide whether an envelope has already been delivered. Do not add server-side envelope deduplication; see [ADR 0011](docs/adr/0011-relay-connection-epochs.md).

Each connection has bounded inbound and outbound queues, frame size limits, read and write deadlines, heartbeat handling, and a slow-consumer policy. Compression is disabled initially because encrypted payloads do not benefit from it and compression complicates the security model.

The first deployment uses an in-memory connection hub and therefore supports one active server replica. Define a narrow relay-bus boundary so a distributed presence and routing adapter can later use Redis or NATS. Do not add that infrastructure before horizontal deployment is required.

The live-only product does not persist relay frames, and must not retain ciphertext as an accidental message archive. It keeps no per-envelope deduplication state either; that responsibility sits with the peers, as described above.

## API Boundaries

The HTTPS API covers:

- Registration, login, refresh, logout, and current account state.
- Device and connector inventory, naming, and revocation.
- Pairing creation, review, approval, confirmation, polling, and completion.
- Relay-ticket issuance and connector presence.

The WebSocket surface covers:

- Connection establishment and capability negotiation.
- Presence updates.
- Opaque encrypted request, response, event, and acknowledgement envelopes.
- Heartbeat and controlled disconnect behavior.

Describe the HTTP surface with OpenAPI. Version HTTP APIs and relay protocols independently. Validate all input at the transport boundary and repeat authorization checks in the application service responsible for the operation.

## Persistence

PostgreSQL stores users, auth sessions, refresh-token families, devices, connectors, public keys, pairing state, trust records, revocation state, and security audit metadata.

Use explicit SQL migrations. Each module owns the meaning of its records and persistence operations. Database constraints should reinforce uniqueness, ownership, valid state, and expiry assumptions. Sensitive token values are never stored directly.

OpenCode sessions and messages are not server entities. Do not add conversation tables in the live-relay phase.

## Security Requirements

- Require TLS in deployed environments and use strict transport security at the edge.
- Reject browser origins by default and retain origin/Fetch Metadata checks on credential endpoints. The retired testing client does not justify an implicit browser allowlist.
- Reject cross-account routes regardless of identifiers supplied by a client.
- Redact authorization headers, cookies, tickets, codes, ciphertext, and sensitive query values from logs.
- Use generic external errors and structured internal error categories.
- Enforce payload, rate, connection, and queue limits before expensive processing.
- Make token expiry and key revocation effective for existing connections within a bounded interval.
- Never implement custom encryption. The server handles only standardized key metadata and opaque encrypted envelopes.

## Operations and Observability

Start with a single server instance, PostgreSQL, and a TLS-terminating edge. Expose health and readiness separately. Readiness includes required infrastructure but should not depend on optional third-party services.

Metrics should cover authentication outcomes, active sockets, connector presence, frame counts and sizes, rejected routes, queue saturation, disconnect reasons, and request latency. Logs and traces use account-safe opaque identifiers and never include relay content.

Audit records focus on user-visible security events such as login, logout, refresh reuse, pairing, device trust, connector trust, and revocation.

## Verification Expectations

Future server work must include unit tests for domain and application rules, PostgreSQL integration tests for constraints and transactions, HTTP contract tests, WebSocket concurrency tests, account-isolation tests, race detection, and fuzzing of public parsers.

Critical negative cases include wrong-account routing, expired tickets, ticket reuse, revoked devices, replayed envelopes, malformed frames, oversized payloads, pairing races, refresh reuse, and slow consumers.

## Out of Scope

- Decrypting or indexing OpenCode content.
- Persisting offline conversation history.
- Executing OpenCode operations on the server.
- Direct access to a developer filesystem.
- Exposing a local OpenCode server through a reverse proxy.
- Distributed relay infrastructure before multi-replica deployment.
