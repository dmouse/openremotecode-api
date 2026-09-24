# ADR 0015: Local-First Connector Revocation

## Status

Accepted. Supersedes the ordering, threat analysis, and verification claims in
[ADR 0003](0003-connector-self-revocation.md) that depended on the server confirming
revocation before the TUI disabled the connector locally. ADR 0003's decision on the dialog
flow, the endpoint's contract, and idle-socket revalidation remains in effect.

## Context

ADR 0003 had the TUI call `POST /v1/connectors/self/revoke` first and only remove pending
pairing state, the connector key, and local authorization once that call succeeded. On any
failure — network, authorization, server error, or a local cleanup step throwing before it
finished — the TUI left the existing authorization in place and told the user to retry. The
stated reasoning was that a successful server revocation must remain effective even if the
TUI crashes before cleanup, and that retries needed the saved authorization to reattempt the
call.

That reasoning correctly protects the retry path, but it also means the *local* kill switch
never fires unless the remote service cooperates. `authorization-monitor.ts` polls the
authorization file and stops the relay only when that file changes; while the file still
holds the original credential, the relay keeps admitting, renewing, and dispatching commands
exactly as before. A service outage prevents this by construction. A malicious or compromised
service can withhold a success response indefinitely while continuing to relay traffic to the
connector the user just tried to disconnect, and the developer has no local action left that
stops it: the one command Open Remote Code offers for "stop talking to remote clients right
now" was defined to depend on the network path it is meant to shut off.

## Decision

- `revokeRemoteAccess` now disables the connector locally before contacting the server. After
  the existing staleness check (the in-memory authorization must still match the file, or the
  action aborts and nothing is touched), it writes the credential and service origin to a new
  0600, atomically-written revocation queue file (`connector-revocation-queue.json`,
  `packages/agents/opencode/src/auth/revocation-queue.ts`), then clears the pairing store, the
  connector identity, and the authorization file — the same local state ADR 0003 cleared, just
  no longer gated on a network round trip. The TUI renders "Remote access revoked" as soon as
  this local step finishes.
- Only after local disablement does the TUI attempt `POST /v1/connectors/self/revoke`. Success
  clears the queue file. Failure leaves the entry queued and is not reported to the user as an
  error, because the property the dialog promises — this device no longer accepts remote
  commands — already holds.
- The plugin's main process (`index.ts`) attempts any queued revocation once at startup,
  independent of and concurrent with its normal pairing/relay bootstrap, so an interrupted or
  offline attempt is retried the next time OpenCode runs without user action. A still-failing
  attempt simply leaves the entry queued for the following start; nothing blocks on it.
- The staleness check keeps its ADR 0003 meaning: it still runs once, before any local mutation
  or network call, comparing the authorization the confirmation dialog captured against the
  file's current contents so a concurrent re-pairing or rotation is never revoked out from under
  the user.

## Threat analysis

- An unreachable, slow, or actively hostile revocation endpoint can no longer keep a connector
  admitting traffic after the user asks to revoke it. `authorization-monitor.ts` observes the
  cleared file within its existing 250ms poll and stops the relay regardless of what the server
  does or does not do afterward. This closes the gap ADR 0003 left open: revocation is now a
  local guarantee, and server confirmation is best-effort cleanup on top of it.
- The queued credential is materially the same secret the authorization file already held in
  plaintext-adjacent form (0600, same directory); moving it to a second 0600 file for the
  duration of a pending retry does not create a new disclosure surface. It is deleted as soon as
  the server confirms revocation, and by design it authorizes nothing on its own — the local
  relay is already stopped by the time it is written.
- Retaining the queued credential does reintroduce, narrowly, the risk that a copy of it read
  from disk between the local disable and the confirmed server revocation could still be used
  directly against the API before the server acts on it. This is unchanged from ADR 0003's own
  scope note that local file deletion cannot itself invalidate a copied credential; server-side
  revocation remains the only thing that does, and this decision does not shrink the window in
  which that is true. It only guarantees that the local relay stops regardless.
- A crash between writing the queue entry and clearing the authorization/pairing/identity files
  leaves both present momentarily; the next monitor poll or plugin start still converges to
  disabled, since clearing the authorization file is what matters for the relay and it is
  written last in that sequence.
- Idempotent retries and idle-socket revalidation, both already covered in ADR 0003, are
  unaffected: the endpoint's contract did not change, only when the plugin calls it.

## Verification

`test/unit/tui-revocation.test.mjs` now asserts that the authorization file is already cleared
and the credential is queued by the time the network request is observed, that a 503 response
still results in local disablement and a queued retry rather than a retained authorization and
an error dialog, and that the staleness check still blocks both the local disable and the
network call when the authorization changed underneath the dialog.
`test/unit/revocation-queue.test.mjs` covers the queue file's atomic persistence and
permission enforcement, that a queued entry is cleared once the server accepts the retry, and
that it survives an unreachable server unmodified.
