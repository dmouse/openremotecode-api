# ADR 0011: Relay Connection Epochs and Sequence Replay Windows

## Status

Accepted. Supersedes the envelope replay paragraph in [ADR 0002](0002-persistent-pairing-and-relay-admission.md).

## Context

Both endpoints already refused replayed envelopes. The plugin kept a TTL-evicted map of
delivered `messageId`s and a `requestId` journal that made a retried mutation return its
first outcome instead of running twice; the mobile client kept the same `messageId` map.
The relay itself keeps no such state, which is correct: it is an untrusted router, so it
is the wrong place to enforce freshness.

Both maps lived only in process memory. A plugin restart or an app restart cleared them
while an envelope captured from the previous connection could still be inside its
five-minute TTL, so exactly one replay could land in the new process. The plugin's
mutation journal cleared with it, so a replayed mutating request would execute a second
time rather than return its recorded outcome.

The envelope already carried a `sequence`, authenticated in the HPKE additional data and
never read by either receiver. Enforcing monotonicity on it was not possible as things
stood, because both senders reset their counter to zero on restart; a receiver that
demanded increasing sequences would have rejected every envelope from a restarted peer
until the pairing was redone.

Persisting the counters on both platforms was the alternative. It closes the same window,
but it makes a lost, restored or rolled-back counter file wedge that peer permanently,
and it adds durable state to two platforms to protect against a replay that must already
survive TLS.

## Decision

- Each peer generates a fresh 16-byte nonce per relay connection and publishes it in its
  hello. The relay forwards hellos unchanged, so each side learns the other's nonce.
- Both peers derive a connection epoch as the base64url SHA-256 of a canonical JSON
  transcript: a domain separator, the protocol version, and the role-ordered connector
  and client key IDs and nonces. Role ordering makes both sides compute one value.
- The epoch is carried in the envelope and authenticated as part of the HPKE additional
  data. A receiver rejects any envelope whose epoch is not the live connection's.
- Per epoch, each sender numbers its envelopes from zero and each receiver runs a sliding
  replay window (RFC 6479 in shape: a highest-accepted sequence plus a bitmap of the
  window below it). A repeat is refused; reordering inside the window is not.
- The window and the outgoing counter are created and discarded with the epoch. The
  mutation journal deliberately is not: it is keyed by `requestId` and must outlive a
  reconnect so a client retrying after an uncertain outcome still gets its first result.
- The relay validates the shape of the new fields so strict decoding accepts them, and
  does not interpret them. Deduplication stays at the endpoints.
- This changes the wire contract, so `RELAY_PROTOCOL_VERSION` becomes 2 with no
  compatibility shim. Nothing is shipped, and unsupported versions already fail
  explicitly.

## Threat Analysis

A captured envelope no longer replays into any later connection, because the receiver's
own fresh nonce is an input to the epoch and the epoch is authenticated: relabelling the
envelope breaks decryption. Within a connection, the window refuses any repeated
sequence, so a capture cannot be re-delivered even while it is unexpired.

A malicious relay can substitute a nonce in the hello it forwards, because hellos are not
end-to-end authenticated. The two peers then derive different epochs and their envelopes
stop decrypting, which is denial of service — a power the relay already has, and which
ADR 0002 documents. It cannot use substitution to make a receiver accept a stale
envelope, because it cannot make the receiver's freshly generated nonce repeat.

Nothing persists across restarts, so no counter file can be lost, rolled back or copied
between devices, and no peer can be wedged into re-pairing by losing one. A restart is
simply a new epoch.

The window is fixed size, so a peer cannot grow receiver memory by sending sparse
sequence numbers; the previous `messageId` map could be filled to its 2048-entry bound,
after which the plugin refused otherwise-valid frames. Sequences far below the window are
refused rather than re-accepted, so a peer that stalls past the window reconnects instead
of silently losing replay protection.

Epoch derivation is duplicated in TypeScript and Dart. Drift between them would leave the
two peers unable to agree on any connection, so a shared fixture pins the derivation and
both suites assert against it.

## Consequences

Envelope replay tracking is complete, and the prerequisites ADR 0002 named for mutating
operations — connection epochs, a bounded request journal, and defined uncertain-outcome
behavior — are all met. The remaining pre-release items in that ADR (connector credential
rotation, keychain storage for the plugin credential) are unaffected.

Relay protocol version 1 is gone. A peer that has not been rebuilt cannot connect, which
is the intended explicit failure rather than a silent downgrade.

A reconnect resets sequence numbering, so neither side may assume sequence continuity
across connections; anything that must survive a reconnect belongs in the request journal
or in an authoritative snapshot, as the reconnect reconciliation design already requires.
