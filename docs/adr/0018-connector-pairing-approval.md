# ADR 0018: Explicit connector approval, per-pairing device credentials, bounded rate limits

Status: accepted.

## Context

Three findings from a server security review, fixed together because two of them change
the same pairing transaction.

1. **Pairing completed without consent at the OpenCode machine.** The first poll that
   observed the transcript set `ConnectorReviewedAt`, and confirmation required only
   that. The plugin showed the safety code in a toast but never asked anything. So anyone
   who obtained the 8-character user code within its ten minutes — from a screen share, a
   screenshot, over a shoulder — could claim it from their own account, confirm on their
   own phone, and bind the victim's OpenCode to themselves. Because OpenCode executes
   code, that is remote control of the victim's machine. The safety code only protects a
   user who compares it; the attacker compares it against their own phone.
2. **Device credentials were derived from a public value.** The credential was
   `HMAC(DEVICE_CREDENTIAL_KEY, keyId)`, and every confirmation reset the device to it.
   A re-pairing therefore restored a credential the device had rotated away (ADR 0013),
   and the key alone recomputed every device's credential, since key IDs travel in hellos
   and inventories.
3. **Rate limiters could exhaust memory or lock everyone out.** The connectors limiter
   never evicted, so rotating source addresses grew it without bound. The identity
   limiter refused every new client once it held 10,000 keys, so the same rotation
   denied login, registration and refresh to everyone for a whole window. Both keyed IPv6
   clients by full address, giving one host a /64's worth of budgets.

## Decision

**Connector approval.** Polling no longer approves anything. The plugin shows the safety
code in a confirm dialog in the OpenCode TUI and asks whether to let this phone control
OpenCode. On approval it calls `POST /v1/connector-pairings/{id}/approve`, authenticated
by the pairing secret (which only the connector holds) and naming the device key it
showed; the server records `ConnectorReviewedAt` only if that key is the claimed device's.
On decline — including a dismissed dialog — it cancels the pairing and a new code follows.
Confirmation already required `ConnectorReviewedAt`, so the phone's existing 409 handling
becomes "approve in OpenCode, then confirm again"; confirming a pairing rejected in
OpenCode now returns 410 instead of an indefinite 409. The approval is idempotent and a
failed request is retried without asking the user twice.

**Per-pairing device credentials.** Each confirmation draws a random 32-byte seed, stores
it on the pairing row, and issues `HMAC(DEVICE_CREDENTIAL_KEY, "…/device-credential/v2\0" ||
seed)`. A retried or concurrent confirmation of the same pairing re-derives the same
value, preserving the idempotency ADR 0013 relied on, but only while the device still holds
it: after a rotation or another pairing the stored hash no longer matches and the retry is
refused. A new pairing always issues a new credential, so re-pairing never revives an old
one, and recomputing any credential takes both the key and the database.

**Bounded limiter.** One `httpserver.RateLimiter` replaces both copies. Entries are kept in
window-start order, so expired windows are swept from the front cheaply on each call; when
the table is still full the oldest window is evicted instead of the new client refused.
Keys reduce IPv6 addresses to their /64. Client-address resolution moves with it, unchanged.

## Threat analysis

- **Approval** closes the code-leak path: a leaked code now lets an attacker claim a
  pairing, but not complete it, unless the person at OpenCode approves a phone they are not
  holding. The dialog states the consequence and the matching safety code. An attacker who
  can drive the victim's OpenCode UI already controls it. A pairing secret leak lets its
  holder approve, but the same secret already yields the connector credential.
- The approval names the device key, so it cannot be spent on a different device claiming
  the same pairing later. A pairing is claimed once (pending → verification), which already
  prevents that; the binding makes the property local to this call.
- **Compatibility:** a plugin older than this change never approves, so it cannot complete
  pairing against this server. Already-paired connectors are unaffected. Shipping the
  plugin and server together is required; there is no fallback that would keep the old
  unconsented path open.
- **Credentials:** existing devices keep working, since authentication resolves by stored
  hash. A device paired before this change still holds a key-ID-derived credential until
  its first rotation or next pairing; the mobile client renews in the final third of the
  lifetime. A confirmation retried across this upgrade is refused (the old pairing has no
  seed) and bounded by the pairing's ten-minute life. Seeds on old pairing rows remain
  until expired-record cleanup exists; each is useless without the key.
- **Limiter eviction** gives an evicted client a fresh window. An attacker who can fill the
  table already has that many budgets, so eviction adds nothing for them while keeping
  every other client served. /64 grouping means filling it takes 10,000 IPv4 addresses or
  /64 networks rather than one IPv6 host. Clients behind one shared /64 share a budget,
  the same trade-off IPv4 NAT already imposes.
