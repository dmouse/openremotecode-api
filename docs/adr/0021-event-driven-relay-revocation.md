# ADR 0021: Close relay sockets when revocations commit; periodic checks become a safety net

Status: accepted. Supersedes the per-second revalidation of ADR 0003 and ADR 0017.

## Context

Every live relay socket rechecked its authorization once a second: about 2.5 PostgreSQL
transactions per socket per second. The load test (ADR 0020) showed that this, not relaying,
set the server's capacity. At 5,000 sockets demand reached ~12,500 transactions/s against
~6,200 achieved; checks missed their one-second deadline and the server closed 900–1,700
sockets a minute, which real clients would turn into a reconnect storm. Any check error,
including a brief database outage, also closed the socket, so a one-second database blip
disconnected everyone at once.

Almost every change a check can detect is made by this server's own code at a known moment,
and the service runs a single replica, so those sockets can be closed directly instead.

## Decision

**Revocations close sockets when they commit.** `relay.Hub` is created in `cmd/server` and
shared by the relay handler and the services. After the transaction commits — never inside
it, so a rollback closes nothing — each revocation calls `Hub.Disconnect` with a
`connectors.Revocation` naming what it covers:

| Event | Closes |
|---|---|
| Connector revoked by itself or its account | that connector's sockets |
| Device revoked by its account | that device's sockets |
| Logout; refresh-token reuse; refresh of an expired session | client sockets admitted under that session |
| Refresh that finds the account no longer active | every socket of the account |

`Revocation.Covers` scopes every match to one account and to the right role.

**The periodic check becomes a safety net.** Each socket is still checked once immediately
after it registers, then at a jittered interval averaging 30 seconds (uniform over 15–45 s,
so sockets do not check in lockstep). The immediate check closes the race with a revocation
that commits after the ticket is consumed but before the socket registers: its announcement
cannot see the socket yet, but the socket's first check sees the revocation.

**Only an authorization failure closes a socket.** A check that fails for another reason, such
as a database error or timeout, is retried after five seconds and the socket stays open. Checks
now have a five-second timeout.

## Threat analysis

- Everything this server revokes is announced, so it takes effect at commit time: faster than
  the one-to-two seconds of the per-second check, and independent of database load.
- Changes nothing announces are bounded by the safety net (≤45 s) and always by the
  authorization lease (≤5 minutes, capped at credential and access-token expiry, which closes
  sockets exactly at expiry). Today that set is: an account disabled directly in the database
  (the service has no disable operation), and any change made by another replica.
- Keeping a socket open through transient check errors trades a bounded window for
  availability. During a database outage no new tickets can be issued anyway, and no
  revocation can commit without the database, so there is nothing new to enforce; the lease
  still ends any socket whose checks keep failing. Previously the same outage disconnected
  every socket and invited every client to reconnect at once against a struggling database.
- **Multiple replicas.** The hub is in-process. A second replica would not hear revocations
  committed on the first until its safety-net check (≤45 s). Before running more than one
  replica, announcements must travel over the relay bus that server AGENTS.md anticipates.

## Measurements (`cmd/loadtest`, 1 KiB envelopes, 1 msg/s per phone, 60 s window)

| Sockets | Before: server-closed / PG tx/s | After: server-closed | After: RTT p99 | After: CPU / RSS | After: PG tx/s |
|---|---|---|---|---|---|
| 5,000 | 911–1,701 / ~6,200 (saturated) | **0** | 0.35 ms | 0.36 cores / 497 MiB | 418 |
| 10,000 | — | **0** | 4.1 ms | 0.83 cores / 961 MiB | 825 |
| 20,000 | — | **0** | 3.6 ms | 1.89 cores / 1.86 GiB | 1,665 |
| 28,214* | — | **0** | 9.1 ms | 2.70 cores / 2.67 GiB | 2,419 |

\*Target 40,000: the harness ran out of ephemeral ports dialing one loopback address after
28,214 sockets. The server was not the limit and its ceiling was not reached. Memory, about
95 KiB per socket, now grows fastest; database load is about 0.08 transactions per socket per
second. Finding the next ceiling needs the harness to dial from several loopback addresses.
