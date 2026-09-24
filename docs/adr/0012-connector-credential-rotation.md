# ADR 0012: Connector Credential Rotation

## Status

Accepted and implemented on both the server and the plugin. This decision resolves the
rotation gap recorded in [ADR 0002](0002-persistent-pairing-and-relay-admission.md).

The plugin expresses the renewal trigger as remaining time — inside the final 30 days —
rather than as an elapsed fraction, which is the same day-60 point for the default 90-day
lifetime but needs no issue timestamp and so applies unchanged to an authorization written
before rotation existed.

## Context

A connector credential lasts 90 days and a device credential 365. Neither renews. When one
expires the connector row stays valid but every admission path rejects it, and the only
recovery is a new pairing: a fresh code, a fresh transcript, and another out-of-band safety
code comparison.

That recovery is the problem. ADR 0002 states plainly that the safety code protects against
substitution *only when the user compares the two displays*, and that a user who confirms
without comparing receives no protection. A ceremony the product forces on a schedule is a
ceremony people learn to click through. Expiry without renewal therefore converts a
credential-lifetime control into slow erosion of the one check the pairing design depends on.

Both credentials are deterministic derivations rather than random values:

- `deriveConnectorCredential` is `HMAC-SHA256(pairingSecret, "opencode-remote/connector-credential/v1")`.
- `deriveDeviceCredential` is `HMAC-SHA256(serverPairingCodeKey, "opencode-remote/device-credential/v1\0" || keyId)`. (Superseded by [ADR 0018](0018-connector-pairing-approval.md): the input is now a random per-pairing seed.)

Determinism is load-bearing in both cases, which is why rotation cannot simply issue a new
value. The connector derivation lets a plugin whose setup was interrupted re-derive its
credential by polling a completed pairing with the secret it still holds. The device
derivation makes concurrent or retried confirmation converge on one credential instead of
leaving either side with a losing value. The server stores only SHA-256 hashes of both.

The pieces a renewal needs already exist. The plugin persists `credentialExpiresAt` and
checks it at startup, falling back to pairing when it has passed. Its authorization file is
replaced by writing a temporary file and renaming it, so a new credential can be made
durable before it is used. `/v1/connectors/self/revoke` establishes the pattern for an
endpoint authenticated by the connector's own credential.

ADR 0001 already rotates a credential in this codebase: browser refresh credentials rotate
on every use, and reuse of a consumed one revokes the whole session family. Its recorded
consequence is that a retry after a lost successful response revokes the family, so clients
must "return to login when rotation outcome is uncertain". That fallback is cheap for a
browser session and expensive here, and this decision diverges from it for that reason.

## Decision

- Add `POST /v1/connectors/self/rotate`, authenticated by the current connector credential
  through the same plugin middleware and ticket rate limiter as `/self/revoke`.
- Rotation issues a random opaque 256-bit credential, matching ADR 0001's access and refresh
  credentials, stored as a SHA-256 hash with a fresh 90-day expiry. It keeps the connector
  row, its ID, its identity, its trust edges, and its original linking date.
- Initial issuance keeps the existing derivation, so interrupted setup can still resume.
  Determinism is only needed inside the pairing window, which the pending-pairing record
  already bounds. After a first rotation the completed-pairing poll branch no longer matches
  the stored hash and fails closed, which is correct: by then the plugin holds its own
  credential and has no reason to poll.
- A rotation is provisional until it is activated. The connector row carries the pending hash
  and a 15-minute activation deadline alongside the current one, so at most two credentials
  are ever live and only one of them is committed.
- Settlement is explicit on the new credential and implicit on the old.
  `POST /v1/connectors/self/rotate/activate`, authenticated by the pending credential, commits
  it: the old hash is dropped and the new becomes current. Ordinary authenticated calls commit
  nothing, so the commit point is one auditable call rather than a property of every request.
  Presenting the old credential cancels the rotation: the pending hash is discarded and the
  current credential is untouched, which lets the plugin simply try again later. A rotation
  that is never settled expires at its deadline and is discarded exactly as a cancellation
  would be.
- The plugin holds both credentials for the length of a rotation, mirroring the server. Its
  authorization file gains an optional pending slot at file version 2, written atomically by
  the existing temporary-file-and-rename replace, and both values are durable before the
  activation call is issued. On load it tries the pending credential first and falls back to
  the current one, so no crash point loses the credential it needs: crashing before the write
  leaves a working current credential, and crashing after activation but before promotion
  leaves a pending credential that is already current on the server.
- An unactivated rotation therefore never invalidates anything. The credential a working
  plugin holds stops working only when that plugin has durably recorded a newer one and
  deliberately activated it.
- The plugin renews on connect once the credential passes two-thirds of its lifetime,
  roughly day 60, rather than waiting for expiry. Renewal is single-flight, and a failure is
  not fatal: the current credential is still valid, so the attempt simply repeats on the
  next connection.
- Cancelling a pending rotation appends a security audit event, since a rotation the
  requester never used is worth seeing. Presenting a credential superseded by a *committed*
  rotation is likewise audited and rejected. Neither revokes the connector.
- Rotation is not revocation and must not disturb a healthy relay connection.
  `ValidateConnectorAdmission` resolves the connector by ID and checks account, identity,
  revocation, and expiry — never the credential value — so a live admission survives rotation
  on its existing lease.
- Device credentials are out of scope here. Their derivation depends on a server-wide
  `pairingCodeKey`, so rotating them is entangled with rotating that secret, which is its own
  decision. Their 365-day horizon leaves room to take it separately.

## Threat Analysis

Rotation bounds the value of a leaked *stale* credential: a copy in a backup, a synced
directory, a disk image, or an operator's terminal history stops working within one rotation
period instead of persisting for the credential's full life. It does not defend against a
live host compromise, which ADR 0002 already places out of scope; an attacker reading the
authorization file today holds a credential that is valid right now, and rotation neither
adds to nor subtracts from that.

A pending rotation leaves two credentials live for at most 15 minutes, and usually far less,
since the plugin rotates while connecting and activates immediately. Both are hashed at rest
and both die with the connector on revocation.

Making the rotation provisional is what keeps an uncertain outcome from costing a ceremony.
Strict single-use rotation fails exactly as ADR 0001 documents: a response lost after the
server commits leaves the plugin holding a credential the server has already retired. In a
browser that means logging in again; here it means the safety-code ceremony, and a ceremony
repeated for routine reasons is one users stop performing honestly.

Both sides holding two credentials is what makes that property survive a crash rather than
depend on the plugin issuing its calls in the right order. Every interruption leaves the
plugin with a credential the server still accepts: before the file is written it has the
current one, after the file is written it has both, and after activation the pending one it
recorded is the one the server committed. A rotation interrupted anywhere either lapses
quietly or completes on the next connection, and neither outcome asks the user for anything.

Expiring an unsettled rotation by discarding it, rather than by invalidating both
credentials, is deliberate. Invalidating both is the more fail-closed reflex, but it would
let anyone who can reach the endpoint force a re-pairing by rotating and then doing nothing,
which is precisely the outcome this ADR is trying to make rare. Discarding costs nothing
security-wise: a pending credential that was never used granted no access, and the surviving
credential is one its requester already held.

For the same reason, presenting a superseded credential is recorded rather than punished. It
is genuine evidence — of a stale copy, a restored backup, or theft — but auto-revoking on it
would let an old copy of the authorization file force a re-pairing. The audit event preserves
the signal without handing an attacker, or an accident, a way to compel the ceremony.

An attacker holding the credential can rotate it and, by activating the new value, lock out
the legitimate plugin, which will then re-pair. This is not a new capability: that attacker
can already connect, issue tickets, and act as the connector. Rotation makes the takeover
*noisier* rather than quieter, since the legitimate plugin's next connection fails visibly
and prompts the user, where a passive thief today produces no signal at all. An attacker who
rotates without activating achieves nothing but an audit event, because the legitimate
plugin's next use of its own credential cancels the attempt. Repeated rotation as denial of
service is bounded by the shared ticket rate limiter.

Removing determinism from the rotated credential means a lost authorization file can no
longer be recovered from the pairing secret. That is the intended direction — the file is the
credential's only home, and a recoverable credential is one that can be recovered by whoever
holds the secret — but it makes the file's durability the recovery boundary, and re-pairing
the only fallback.

## Consequences

A connector that stays online renews indefinitely and never asks the user to re-pair. One
offline longer than its remaining lifetime still expires and still re-pairs; rotation shortens
the routine path, not the abandoned one.

The connector row gains a pending-credential hash and an activation deadline, and rotation,
activation, and admission must lock it consistently with the existing `FOR UPDATE` pattern.
Credential lookup tries both hashes, and a match on the current one cancels any pending
rotation in the same transaction that authorizes the request. Commits happen only in the
activation handler. The audit trail gains `connector.credential.rotated`,
`connector.credential.activated`, `connector.credential.rotation_cancelled`, and the
superseded-use event.

The plugin's authorization file moves to version 2 for its optional pending slot, and its
load path gains a fallback: try pending, then current. Rotation becomes a small state machine
in the authorization store rather than a step in the connect sequence, and the store is the
only component that ever holds an unactivated credential.

Because presenting the current credential cancels a pending rotation, activation must be the
next credential-bearing call the plugin makes after rotating. A sequence that rotates and
then issues a relay ticket with the old credential before activating would cancel its own
rotation, and would do so on every attempt: the credential would never renew and would
silently reach expiry despite a renewal path that appears to be running. Renewal therefore
belongs after admission rather than before it, and a rotation that is cancelled by the
plugin's own call is worth asserting against in tests rather than only reasoning about.

Device credentials keep their current behavior and their 365-day cliff until the
`pairingCodeKey` rotation question is decided. That decision should also revisit whether a
server-wide secret belongs in the derivation of a per-device credential at all.
