# ADR 0020: Relay load test, per-module connection pools, and the revalidation ceiling

Status: accepted.

## Context

Delivery step 8 calls for load testing before launch. `cmd/loadtest` was written for it: each
simulated pair is its own account with a seeded session, device, connector and trust, obtains
tickets through `POST /v1/relay/tickets`, connects to `/v1/relay`, and exchanges envelopes of
random ciphertext that the "connector" echoes back. The relay never decrypts, so this is its
real work; endpoint HPKE cost is excluded. Runs used one server process and PostgreSQL 18 in a
container on the same 16-core host, with the harness also on that host and unrelated
workloads running, so figures are indicative rather than a benchmark.

## Findings (2026-09-24)

**1. Shared-pool deadlock (fixed).** At 2,000 sockets the server stalled: ticket requests and
WebSocket handshakes timed out, PostgreSQL fell to 21 transactions/s, and server CPU to ~0.
`pg_stat_activity` showed all 20 pooled connections *idle in transaction*. Connector
transactions (relay revalidation, ticket issuance and consumption, rotation, pairing) call the
identity service's account and session checks while holding a connection, and those checks
drew from the same 20-connection pool. Once 20 such transactions were open, each waited for a
second connection that could not be freed; progress resumed only as one-second revalidation
timeouts fired, and each timeout closed a socket. Revalidating client sockets (ADR 0017)
doubled the rate of these nested calls, but connector sockets and ticket issuance could
already reach the same state.

*Decision:* identity and connectors each get their own pool over the same database
(`cmd/server` `Databases`). Identity never calls into connectors, so the two pools cannot wait
on each other. The checks already ran on a separate connection outside the transaction, so no
atomicity is lost. Cost: up to 20 more PostgreSQL connections.

**2. Results after the fix** (1 KiB ciphertext unless stated; 60 s steady state):

| Sockets | Envelopes/s | Ready | Lost | Server-closed | RTT p50 / p99 | Server CPU / RSS | PG tx/s |
|---|---|---|---|---|---|---|---|
| 500 | 500 | 250/250 | 0 | 0 | 0.3 / 0.5 ms | 0.19 cores / 91 MiB | 1,268 |
| 2,000 | 2,000 | 1,000/1,000 | 0 | 0 | 0.3 / 0.6 ms | 0.72 cores / 247 MiB | 5,077 |
| 2,000 (10 msg/s, 4 KiB) | 20,000 | 1,000/1,000 | 0 | 0 | 2.4 / 16.6 ms | 6.71 cores / 275 MiB | 5,659 |
| 5,000 | 2,480 | 2,499/2,500 | 13 | 911 | 0.3 / 2.3 ms | 1.27 cores / 461 MiB | 6,571 |

**3. The revalidation ceiling (fixed by [ADR 0021](0021-event-driven-relay-revocation.md)).** Every relay socket rechecks its authorization once a
second: about 2.5 PostgreSQL transactions per socket per second (a locking read, plus account
and session checks). At 5,000 sockets that is ~12,500/s of demand against ~6,600/s achieved:
PostgreSQL used about six cores, and up to 17 of the connector pool's 20 connections were idle
in transaction, held across the identity round trips. Checks then exceeded their one-second
deadline and the server closed 911 sockets in one minute (each dropping its partner's session
too). Real clients reconnect, which would add ticket and admission load on top: this is a cliff,
not a slope. **Practical ceiling today: roughly 2,000–2,500 concurrent sockets per server.**

**4. Relay CPU per envelope (fixed).** 20,000 4-KiB envelopes/s cost 6.7 cores, about 0.3 ms of
server CPU per envelope. Profiling (`BenchmarkRelayRoundTrip`, `BenchmarkParseEnvelope`) showed
`parseEnvelope` at 72% of relay CPU and the base64url regular expression over the ciphertext alone
at 61%; the JSON decode itself was 10%. The key-ID, nonce and ciphertext checks now use a
256-entry byte lookup table. A per-byte `switch` was only 3.5× faster than the regex on
never-repeating ciphertext (branch mispredictions; it looked 35× faster when benchmarked on one
repeated string), while the table is about 65× faster at every size. A fuzz test holds the table
to the old regular expressions as a reference. Measured in-process:

| | Before | After |
|---|---|---|
| `parseEnvelope`, 4 KiB | 102 µs | 14.9 µs |
| Relay round trip, 4 KiB | 287 µs | 75–94 µs |
| Relay round trip, 64 KiB | 3.7–4.0 ms | 0.61 ms |

Base64url validation fell to about 4% of relay CPU. What leads now is the JSON decode (~29%),
garbage collection (~27%, about 23 KB allocated per 4-KiB frame: the decoded ciphertext string and
a `bytes.Clone` on enqueue) and socket I/O.

Load test rerun with the change (same host and harness):

| Stage | Envelopes/s | Server-closed | RTT p50 / p99 | Server CPU / RSS | PG tx/s |
|---|---|---|---|---|---|
| 2,000 sockets, 10 msg/s, 4 KiB — before | 20,000 | 0 | 2.4 / 16.6 ms | 6.71 cores / 275 MiB | 5,659 |
| 2,000 sockets, 10 msg/s, 4 KiB — after | 20,000 | 0 | 0.26 / 2.4 ms | **2.43 cores** / 225 MiB | 5,279 |
| 2,000 sockets, 25 msg/s, 4 KiB — after | 46,739 (target 50,000) | 147 | 3.6 / 28.1 ms | 5.67 cores / 295 MiB | 5,256 |
| 5,000 sockets, 1 msg/s, 1 KiB — after | 2,342 | 1,701 | 0.3 / 3.1 ms | 1.14 cores / 524 MiB | 6,191 |

Relay CPU for the same traffic fell 2.8×. At about 47,000 envelopes/s the server closed sockets
again; it does not record why it closes one, so these cannot be told apart from revalidation
timeouts or the slow-consumer policy (a full 64-message outbound queue), and the harness shared the
host's 16 cores. The 5,000-socket stage is unchanged, as expected: that ceiling is the
per-second revalidation against PostgreSQL (finding 3), not relay CPU.

## Consequences and follow-ups

- The deadlock fix ships now, with an integration test that the modules never share a pool.
- The revalidation design should change before capacity is needed beyond ~2,000 sockets. Since
  the service runs a single replica, revocation, logout and expiry can close sockets directly
  in-process at the moment they happen, leaving a slow periodic sweep (for example every 30 s,
  batched into one query) as the safety net. That removes the per-socket-per-second database
  cost. Short of that: drop `FOR UPDATE` from the read-only revalidation, fold the three checks
  into one query, and make the pool size configurable.
- Record a reason whenever the relay closes a socket (lease expiry, revalidation failure or
  timeout, slow consumer, replacement, protocol violation), as a log category and later a
  metric. Without it, load-test disconnects can only be inferred.
- Reduce per-frame allocation (validate without materializing the ciphertext string; drop the enqueue copy of a buffer the socket read already owns), then rerun the throughput stage.
- Rerun `cmd/loadtest` after each of these; it is cheap and needs only a disposable database.
