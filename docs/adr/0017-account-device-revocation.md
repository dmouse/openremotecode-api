# ADR 0017: Account-owned device revocation and client socket revalidation

Status: accepted.

## Context

Client devices could not be revoked. The schema had `devices.revoked_at` and
`connector_trust.revoked_at`, and every admission path checked them, but nothing
ever set either. A lost or replaced phone therefore kept its device credential
(365-day lifetime) and its place in every connector's trusted set, and connectors
kept accepting relay envelopes sealed by its key. The only remaining control was
the account session, which the device may still hold. That contradicts the trust
model's requirement that credentials and devices are independently revocable.

Client relay sockets were also never revalidated. Only connector sockets were
rechecked every second (ADR 0003); a client socket survived logout, session
revocation, or device revocation until its authorization lease ended, up to five
minutes (ADR 0002).

## Decision

Add `POST /v1/devices/{deviceID}/revoke` using an account access token, and
`GET /v1/devices` listing the account's activated, unrevoked devices so a user can
find the one to remove. As with connectors (ADR 0005), the authenticated principal
supplies the account; the caller supplies only the device ID. The device's own
credential is not required, because the device being removed is usually the one
the user no longer has.

Revocation, in one transaction with a `device.revoked` audit event:

- sets `devices.revoked_at`, retaining the row and credential hash for idempotent
  retries and audit history;
- clears any pending credential rotation, so it can never be activated;
- sets `connector_trust.revoked_at` on every trust row the device holds, so the
  persisted trust state says what the relay enforces rather than relying only on
  the join against `devices.revoked_at`.

A revoked device cannot be paired again: `ClaimPairing` and `ConfirmPairing`
already refuse a revoked device key. The installation must generate a new identity.

Relay admission now carries the account session a client ticket was issued under,
and the relay revalidates **both** roles immediately and every second with a
one-second check timeout. (Superseded by [ADR 0021](0021-event-driven-relay-revocation.md):
revocations now close sockets when they commit, and the periodic check runs every ~30 s.) A client check requires the device to belong to the
account, match the admitted identity, be activated, unrevoked and within its
credential lifetime, and requires the account and that session to be active. So
device revocation, logout and session revocation each close a live client socket
within about two seconds, not at the end of the lease. This supersedes the
"browser sockets retain their existing lease" statements in ADR 0002 and ADR 0003.

Connectors stop receiving the revoked identity at their next admission, which the
five-minute lease and ADR 0014's proactive renewal bound. Until then the revoked
device cannot reach them: it cannot obtain or consume a ticket, and its socket is
closed.

## Threat analysis

- Foreign and missing IDs both return 404, so device IDs cannot be probed or
  revoked across accounts. Ownership is rechecked inside the transaction.
- Any valid session of the account can revoke any of its devices, including the
  caller's own. That is an account administration operation granting nothing new:
  the same session could already revoke every connector (ADR 0005). A stolen
  session can use it to cut off the owner's devices; that is a denial of service
  inside an already compromised account, and recovery is re-pairing a new device.
- Duplicate requests append one audit event; a failed audit write rolls back the
  whole revocation. Audit rows carry only account and device IDs.
- Native requests and allowlisted browser origins are accepted; cross-site and
  disallowed origins are rejected. The list endpoint returns ID, name, public
  identity and creation time only, never credential material.
- Revalidating every client socket each second adds one short read transaction per
  live socket per second, the same cost connectors already carry. It remains well
  within a single-replica deployment; a cheaper push-based invalidation can replace
  it when the relay bus (server AGENTS.md) is introduced.
- The plugin keeps its local trust pin for a revoked device key. The server-side
  controls above stop that key reaching the connector through the relay, which is
  the only path; removing the local pin is a plugin-side follow-up.
