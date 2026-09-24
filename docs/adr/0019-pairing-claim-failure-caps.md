# ADR 0019: Pairing claim failure caps

Status: accepted.

## Context

A pairing user code is 40 bits and lives ten minutes. The only brake on guessing it was
the per-IP limiter on the claim route (10 requests a minute), so an attacker rotating
addresses had unlimited budget. A wrong code also rolled back the claim transaction, so it
did not spend its device challenge: one signed challenge covered every guess for its two
minutes. Nothing counted failures per account or across the service.

ADR 0018 lowered the stakes — a correct guess now only claims a pairing, which the person
at OpenCode must still approve — but a claimed pairing is still a lure ("approve this
phone") and blocks its owner until the code expires.

The same review found that a wrong code was answered 401, because `ClaimPairing` normalized
the not-found result to `ErrUnauthorized`. The mobile client treats any 401 as a lost
session and invalidates it, so **mistyping a code signed the user out**.

Moving counters to Redis or Valkey was considered and rejected for now. It changes where
counts live, not what they key on, so it would not close any of the gaps above, and the
server runs a single replica (server AGENTS.md defers shared infrastructure until
horizontal deployment). When a second replica is added, the in-memory
`httpserver.RateLimiter` is the boundary to move behind such a store.

## Decision

- **Every claim spends its challenge.** The challenge is marked used before the code is
  looked up, and a wrong code returns from the transaction without an error so that write,
  and the failure record, commit. The error is reported after commit — the same technique
  as email-verification attempts (ADR 0008).
- **Failures are counted in PostgreSQL** in `pairing_claim_failures` (account, time; no code
  is stored). Each insert purges rows older than the longest window, so the table holds
  about an hour of failures.
- **Two budgets, checked before the code is looked up:** at most 10 incorrect codes per
  account per hour, and 120 per minute across the service. Over either, the claim returns
  429 with `Retry-After` (when the account's oldest counted failure leaves the window, or
  the global window). Because the check precedes the lookup, a refused claim says nothing
  about the code, and it does not spend its challenge.
- **Per-account serialization.** A transaction-scoped advisory lock keyed on the account
  makes concurrent claims for one account take turns, so parallel guesses cannot all pass
  the same count. It is an advisory lock rather than a row lock because the account row
  belongs to the identity module. The global budget is not serialized and may be exceeded
  by the number of claims in flight at once.
- **A wrong code is 404 `invalid_code`**, never 401. The mobile client maps 404 to "code not
  found" and 429 to a new "too many attempts, wait" message, and keeps a pending review on
  429 so the user can retry.

## Threat analysis

- Guessing now costs verified accounts, not IP addresses: each account gets ten guesses an
  hour, every claim needs a logged-in, email-verified account, and registration is itself
  rate limited. The global budget bounds the total rate whatever the account count: with
  P pending pairings, the chance of any hit in a ten-minute window is about
  P × 120 × 10 / 2⁴⁰ — roughly 10⁻⁶ at a thousand pending pairings.
- **Denial of pairing.** An attacker who controls enough accounts to fill the global budget
  pauses pairing for everyone for up to a minute at a time. Filling it takes at least 720
  verified accounts (120 a minute at 10 an hour each). It affects only new pairings, never
  sign-in or existing connections, and it is exactly the signal to alert on once metrics
  exist. An attacker can always exhaust their own account's budget; that harms nobody else.
- Legitimate users rarely mistype a code ten times in an hour; if they do, the message says
  how to recover and the budget returns as old failures age out.
- The failure table stores only the account ID and time. It is purged continuously and
  cascades on account deletion.
