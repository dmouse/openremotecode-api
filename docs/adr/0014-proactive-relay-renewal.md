# ADR 0014: Proactive Relay Renewal and Same-Identity Connection Replacement

## Status

Accepted.

## Context

ADR 0002 gives every relay connection a five-minute maximum authorization
lease, capped by the underlying access, device, or connector credential, so
that an account/session change (logout, revocation) takes effect on an
already-open socket no later than five minutes after it happens. The relay
enforces this by scheduling a hard `peer.stop()` at
`admission.AuthorizationExpiresAt` (`server/internal/relay/production.go`).

Until now, both the mobile client and the OpenCode plugin connector only
noticed this the reactive way: the socket closes, `onDone`/`onError` fires,
and the peer reconnects from scratch with backoff. On mobile this produced a
visible online→offline→online flip every five minutes, which the chat
screen's reconnect handling treated as a real disconnect: it reloaded the
open conversation's snapshot and discarded already-loaded message history,
resetting the user's scroll position mid-read on any sufficiently long chat.
The same forced-disconnect cycle applies to the plugin connector, risking a
gap in streamed OpenCode events every five minutes.

The fix is for each peer to renew its admission shortly before its lease
expires — requesting a fresh ticket and opening a new connection ahead of
the old one's hard cutoff — so the five-minute cycle never surfaces as a
disconnect. That, however, ran into an existing invariant:
`secureHub.register` rejected a second connection for an identity that was
already registered ("identity is already connected"), so a renewal's new
connection could not come up before the old one had already torn down,
which reintroduces the same visible gap it was meant to avoid.

## Decision

- `relay.ready` now includes `authorizationExpiresAt`, so a peer knows
  exactly when its lease ends instead of hardcoding the server's lease
  duration.
- Both the mobile client and the plugin connector schedule renewal ahead of
  that expiry (well short of it, with margin for clock skew and request
  latency): request a new ticket, open a new WebSocket, and only close the
  old one once the new one is confirmed live.
- `secureHub.register` no longer rejects a same-identity registration.
  Instead it installs the new connection in place of the old one
  immediately (so routing favors the new connection from that instant) and
  then stops the superseded connection. The superseded connection's own
  teardown runs through the existing `unregister` path, whose stale-write
  guard (`hub.peers[id] != connected`) already made a no-op of unregistering
  a peer that a later registration has replaced — this ADR relies on that
  existing guard rather than adding new state, and it means the swap never
  emits a spurious offline notice to other peers.
- The new connection is admitted the same way every other connection is:
  by consuming a freshly issued, single-use ticket, which re-derives the
  admission (and thus rechecks account, session, device, connector, and
  trust state) exactly as ADR 0002 already requires on reconnection.
  Renewal is not a new trust path; it is the existing reconnection path run
  early enough that it never has to be visible.

## Threat Analysis

Only a connection that has already independently passed ticket consumption
for a given `userID:keyID` can evict the existing connection for that same
`userID:keyID` — eviction is keyed off the identity the new connection was
just authenticated as, never an arbitrary or attacker-chosen identity, so
this cannot be used to hijack or evict another account's or another
identity's connection.

The revalidation cadence ADR 0002 relies on for revocation/logout to take
effect is unchanged: each renewal still consumes a fresh ticket on
(approximately) the same five-minute cycle, so a changed account or session
state still reaches an open socket within essentially the same bound as
before — proactive renewal moves *when the client asks*, not *how often
authorization is rechecked*. A peer whose credential has actually been
revoked cannot renew: ticket issuance and `ConsumeRelayTicket` both
revalidate from current state, so a revoked peer's renewal attempt fails
and it is left to hit its already-scheduled hard `authorizationTimer`
cutoff like before.

Briefly having two connections registered for the same identity (the
old one, mid-teardown, and the new one) does not create a window where two
different, independently-controlled parties are both trusted as that
identity: both connections were opened by the same peer using its own
credential, one right after the other. `route()` only ever resolves to
whichever connection is currently in `hub.peers`, so a message is delivered
to exactly one of the two, never duplicated.

## Consequences

Relay connections now survive their five-minute lease boundary transparently;
a peer only sees a visible disconnect for administrative revocation, network
loss, or the app/plugin process being terminated. The chat screen's
reconnect-driven history
reset ceases to fire on the five-minute cycle; it is now only exercised by a
genuine gap. The plugin connector gains the same protection against a
five-minute streaming interruption. `secureHub.register`'s contract changes
from "one live connection per identity, second connection refused" to "at
most one *routable* connection per identity at any instant, with a newer
connection always superseding an older one" — any future caller relying on
`register`'s old rejection behavior must be re-reviewed against this ADR.
