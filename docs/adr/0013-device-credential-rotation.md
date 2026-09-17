# ADR 0013: Device Credential Rotation and an Unentangled Server Secret

## Status

Accepted and implemented on both the server and the mobile client. This decision closes the
device half of the rotation gap that [ADR 0012](0012-connector-credential-rotation.md)
deliberately deferred.

## Context

A device credential is `HMAC-SHA256(pairingCodeKey, "opencode-remote/device-credential/v1\0" || keyId)`,
lives 365 days, and is delivered as a host-bound cookie in the pairing confirm response. The
mobile client stores it in secure storage as `deviceCookie` alongside `deviceExpiresAt`, so it
already knows its own expiry. Nothing renews it.

Two things make this different from the connector case, and they pull in opposite directions.

The credential is **not sufficient on its own**. Relay-ticket issuance requires an account
access principal, the device ID, *and* this cookie together. A leaked device cookie grants
nothing by itself, and account sessions already rotate on every refresh. Rotation therefore
buys less here than it did for connectors, where the credential alone admitted a connector to
the relay.

Determinism is **harder to remove**. A retried `ConfirmPairing` re-derives the credential and
compares it against the stored hash, which is what stops a concurrent or retried confirmation
leaving either side with a losing credential. The connector could afford to lose determinism
because its credential derives from the pairing secret the plugin itself holds; a device holds
no such secret and cannot re-derive anything client-side.

The more serious defect is not the missing renewal but what the derivation is anchored to.
`pairingCodeKey` has two jobs: hashing user codes, and deriving every device credential. One
secret serving two unrelated purposes means neither can be reasoned about on its own — a
rotation undertaken for one reason silently changes what the other derives, and nothing in
the code or the documentation says so. The threat analysis below establishes that the blast
radius is in fact small, but that is a property nobody could have known without tracing every
call site, which is exactly the problem.

## Decision

- Split the secret by purpose. User-code hashing keeps `pairingCodeKey`; device-credential
  derivation moves to its own `deviceCredentialKey`. Rotating the user-code key becomes a free
  operation, and the two lifetimes stop being accidentally coupled.
- Add `POST /v1/devices/self/rotate` and `POST /v1/devices/self/rotate/activate`, authenticated
  exactly as ticket issuance is: an account access principal, the device ID, and the current
  device cookie. The device ID is never taken as the sole authority.
- Rotation issues a random opaque 256-bit credential stored as a SHA-256 hash, and returns it
  as a `Set-Cookie` with the same host-bound attributes as the original. Activation is
  authenticated by the pending cookie.
- The semantics are those of ADR 0012, unchanged: the rotation is provisional until activated,
  carries a 15-minute activation deadline, is cancelled by any authenticated call presenting the
  current credential, and is discarded rather than punished if it simply lapses. The 365-day
  lifetime starts at activation, so a provisional credential never burns time it is not being
  used for.
- The client holds both for the length of a rotation. The device identity record moves to
  version 2 for an optional pending slot, both values are durable before the activation call,
  and on load the pending credential is tried first.
- The mobile client renews once the credential is inside its final third — roughly day 245 —
  after a successful authenticated call, single-flight, with failure non-fatal.
- Initial issuance keeps the existing derivation, so confirmation stays idempotent. After a
  device's first rotation its credential is random and derives from no server key at all, which
  makes the `deviceCredentialKey` dependency transient rather than permanent.

## Threat Analysis

Rotation bounds the value of a stale device cookie — one left in a backup, a device image, or
an old secure-storage entry — to a single rotation period instead of a year. It is a smaller
prize than the connector credential, because it is only ever half of an admission check, and
this decision does not pretend otherwise. The primary gain is structural: the service stops
holding a secret it can never change.

Persisting before activating matters more here than it did in the plugin, not less. A phone is
killed by the operating system routinely and without warning, so the window between receiving a
credential and making it durable is a normal occurrence rather than a crash scenario. Holding
both credentials and settling on first use is what keeps that ordinary event from costing a
re-pairing.

Both credentials are host-bound cookies with the existing attributes; neither ever appears in a
URL, and activation authenticated by the pending cookie means the new value is exercised
exactly once before the old one is retired. At most two device credentials are live for at most
fifteen minutes.

Rotating `deviceCredentialKey` is cheaper than it first appears. Derivation has exactly one
call site — pairing confirmation — and every authentication path resolves a device by the
stored hash of the credential it was presented, never by re-deriving one. An already-paired
device therefore keeps working across a key change. The one path that does break is the
idempotent re-confirmation of a pairing completed under the previous key, which re-derives to
compare and will now mismatch; that window is bounded by a pairing's ten-minute life.

This is the opposite of what a derived credential usually implies, and it is worth stating
plainly because the intuition that "rotating the key locks everyone out" is wrong here and
would otherwise discourage a rotation that is in fact routine.

Because presenting the current credential cancels a pending rotation, activation must be the
next device-cookie call the client makes. The same livelock that ADR 0012 describes applies: a
client that rotates and then issues a relay ticket before activating would cancel its own
rotation on every attempt and quietly reach expiry. Renewal therefore belongs after a
successful authenticated call, not before one, and a rotation cancelled by the client's own
request is worth asserting against in tests.

## Consequences

The device row gains a pending-credential hash and an activation deadline, and device lookup
must try both hashes with settlement happening in the same transaction that authorizes the
request — the same shape ADR 0012 introduced for connectors.

`ServiceOptions` gains `DeviceCredentialKey`, wired through as `DEVICE_CREDENTIAL_KEY`. It
seeds from `PAIRING_CODE_KEY` when unset so an existing deployment needs no coordinated
change, but a deployment that leaves it unset gains nothing from the split; local development
sets it to a distinct value precisely so the separated path is the one being exercised.

The mobile identity record moves to version 2. As with the plugin's authorization file, the
loader must accept version 1 and upgrade it in place, or the upgrade itself would force the
re-pairing this work exists to avoid.

Rotating the user-code key becomes free, and so, in practice, does rotating the device key:
only pairing confirmation derives from it, so paired devices are unaffected and only an
in-flight re-confirmation can fail. Both keys can therefore be rotated on an ordinary
schedule rather than treated as permanent.
