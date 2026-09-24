# ADR 0009: Google Federated Sign-In

## Status

Accepted. Extends ADR 0008, which stands unchanged: registration by email is still verified by a mailed code, and `status` is still the only authoritative gate on access. This ADR adds a second way to reach an account and does not alter the first.

## Context

Email registration works but costs a user a mailed six-digit code before they can do anything, and it makes this service the custodian of another password. Most people signing in from a phone already hold a Google account, and the platform SDKs make proving that a one-tap operation.

The mobile app is the only client (ADR 0006), so the flow is the native one: the SDK produces an OpenID Connect ID token, the app posts it, and the server verifies it. There is no browser redirect to host, no authorization code to exchange, and no OAuth client secret on either side.

The threats specific to this phase are a forged or replayed assertion, an assertion minted for a different application, **account takeover through automatic linking**, an enumeration oracle in whatever the linking rule reports, and a federated account becoming reachable by a password nobody set.

Account linking is the substantive decision. ADR 0008 records that every account predating it is `active` with `email_verified_at` NULL — nobody ever proved those addresses belonged to whoever registered them. Linking a Google identity to such an account on a matching address would hand it to whoever controls that address today.

## Decision

**A Google assertion is accepted only where it proves at least as much as the mechanism it substitutes for.**

### Verification

- Verification uses `google.golang.org/api/idtoken`, Google's own package, behind the narrow `identity.GoogleVerifier` interface. It pins RS256/ES256, fetches and caches Google's JWKS, and checks the signature, audience, and expiry. Writing a JWT verifier by hand was rejected: the failure modes (algorithm confusion, `kid` handling, audience omission) are well known and not worth re-deriving.
- `idtoken` does **not** check the issuer, so `internal/identity/googleid` does, accepting `accounts.google.com` and `https://accounts.google.com` and nothing else. It also requires a subject, a well-formed address within the module's own 254-character limit, and `email_verified == true`.
- **An empty audience list is a build error, not a default.** `idtoken.Validate` skips the audience check entirely when handed an empty string, so a verifier constructed without audiences would accept any token Google ever signed, for any application. `NewVerifier` refuses to return one.
- Audiences are validated by iterating the configured client IDs and calling `Validate` with each, rather than validating once with an empty audience and comparing the claim locally. This keeps the comparison inside the library that verified the signature, so no later edit to this package can leave the signature checked and the audience not. The cost is at most one signature verification per configured client ID, of which there are two or three.
- Every failure collapses into `ErrInvalidGoogleToken`. A caller probing the endpoint learns that the token was rejected, never which check rejected it.

### Account resolution

Resolution is ordered, and the order is the security argument:

1. **By subject.** `federated_identities` is keyed by `(provider, subject)`. A Google account's address can change and an address can be reassigned to a different Google account, so the subject is the only durable join key. A returning user reaches the same account even after changing their Google address, and the local account's own address is left exactly as the user set it.
2. **By address, when the address is proved.** With no existing link, a local account holding the same address is linked and signed in if it has `email_verified_at` set. A **pending** account is also linked, and Google's assertion completes its verification: that is strictly stronger than leaving it stranded behind a code it may never receive, and `ActivateUser`'s pending-only `WHERE` clause is what stops this branch touching an account in any other state. The outstanding challenge is deleted, so the mailed code cannot be replayed afterwards. The account's password hash is discarded in the same write (`ActivateFederatedUser`): anyone can register a pending account for an address they do not control, so a password set before the address was proved says nothing about the person Google vouched for, and keeping it would let whoever pre-registered the address sign in to the owner's account. A pending account never holds a session, so nothing else needs revoking; the owner can set a password later.
3. **Otherwise, a new account.** Active, `email_verified_at` set to now, and no password hash.

**An active account with a NULL `email_verified_at` is refused with `ErrAccountLinkRequired` (409).** This is the takeover case, and the one place the design deliberately costs the user a step. The response names the recovery path — sign in with the password, which does prove ownership. Disclosing that an account exists is acceptable here and is not an enumeration oracle: reaching this response requires an assertion proving the caller controls the address, so they learn nothing they could not already establish. Every other non-active status collapses into `ErrInvalidCredentials`, matching the password path exactly, so the two routes cannot be played against each other to learn an account's state.

**The refusal commits.** `googleLinkExisting` returns no error on that branch and reports the refusal through a result value instead, because returning `ErrAccountLinkRequired` from the transaction closure would roll back the `auth.google_link_required` audit event along with it. This is the same trap ADR 0008 records for the verification attempt counter.

### Schema

- `federated_identities` is keyed by `(provider, subject)` with a `provider IN ('google')` check, so an unreviewed provider name fails at the schema rather than quietly creating a parallel namespace. It carries a **per-provider unique index on `user_id`**: one local account holds at most one identity per provider. Without it, a second Google account could attach to an account it proved nothing about and then sign in as it. The stored `email` is a diagnostic snapshot refreshed on each sign-in; no authorization path reads it.
- That rule is **also checked in the service before inserting**, and refused as `ErrIdentityAlreadyLinked` (409 `account_identity_conflict`). Two reasons: a constraint violation aborts the entire PostgreSQL transaction, so the refusal could not then be audited; and the case is reachable with no concurrency at all — a second Google account that has since taken over an address already linked to an account arrives here — so it must not surface as a 500.
- Rows are never swept. They are bounded by the account count and cascade away with the user, which is also how revoking a link is expressed.
- **`users.password_hash` becomes nullable.** A federated account has no password, and NULL says so. An empty-string sentinel was rejected: `PasswordHasher.Verify` returns an *error* for an unparseable hash, so a sentinel would surface as a 500 and make federated accounts distinguishable from every other kind. `identity.User.HasPassword` is the only correct test, and `Login` consults it before hashing, burning the same dummy hash an unknown address burns so the timing matches and the error stays generic.

### Transport and configuration

- `POST /v1/auth/google` sits in the existing `/v1/auth` group and inherits its origin and Fetch Metadata gate. It has its own rate limiter sized like login (10/min): sharing login's budget would let a burst of bad passwords lock out Google sign-in, and the reverse.
- It answers with credentials and a refresh cookie, or an error. **Never a verification challenge** — a client that received one would wait for a code that is never sent.
- It is **not** gated on `REGISTRATION_ENABLED`. That switch governs the mailed-code flow; conflating them would silently lock out accounts that already exist. An operator disables this route by unsetting `GOOGLE_OAUTH_AUDIENCES`, which yields `503 google_signin_unavailable`.
- `GOOGLE_OAUTH_AUDIENCES` is a comma-separated list of OAuth client IDs, empty by default, so Google sign-in is off unless a deployment opts in. Client IDs are public identifiers, not secrets; no OAuth client secret exists anywhere in this design, on either side.

### Concurrency

`SELECT ... FOR UPDATE` takes no lock on a row that does not exist, so two devices signing in for the first time at the same moment both find nothing to lock and one loses on a unique index. `AuthenticateWithGoogle` retries once on `ErrConflict`; the loser then finds the winner's row on its second pass. A conflict surviving the retry is a real constraint problem, not contention.

### Client

The Flutter app puts the SDK behind `GoogleIdentityProvider` in `lib/platform/`, so the authentication feature never imports the plugin and the flow is testable without a platform channel. Cancellation is a distinct outcome from failure — closing the account chooser is a normal thing to do and must not leave an error banner. The action is hidden entirely unless the build carries a server client ID and the platform supports interactive sign-in, so it never appears in a state where tapping it cannot work. A rejected assertion signs the device out of Google, so retrying offers the chooser rather than silently resubmitting the account the server just refused.

## Consequences

- **Existing accounts are untouched.** The migration only drops `NOT NULL` from one column; no row is rewritten, and an integration test reconstructs the pre-migration schema to prove the `ALTER` runs and preserves its rows.
- **Some existing users will hit `account_link_required`.** Every account created before ADR 0008 has a NULL `email_verified_at` and will be refused on its first Google attempt. This is the accepted cost of closing the takeover path; the copy on both sides names the password route out of it. Verifying such an account's address, whether by a future explicit link flow or by a re-verification prompt, removes the friction permanently.
- **Linking from a signed-in session is not built.** The refusal above is currently resolved by signing in with a password and then continuing to use it. A settings-screen link action is the natural follow-up: it would authenticate first and then create the same `federated_identities` row, with no schema change. Deferred rather than designed around.
- **Unlinking is not built either.** Deleting the row is the whole operation, and the next sign-in from that subject would take the linking path again. It needs a UI and an audit event, not a mechanism.
- **The account address and the Google address may diverge.** Deliberate: the link is keyed by subject, and rewriting a user's address because their provider changed theirs would be the server overriding a user's own setting.
- **A new outbound dependency on Google's JWKS endpoint.** Cached by the library. Readiness deliberately does not include it, matching how ADR 0008 treats mail: an outage blocks Google sign-in while leaving password sign-in and every existing session working.
- **`google.golang.org/api` is a large dependency for one function.** Accepted for an audited implementation of the one thing here that must not be got wrong. `github.com/coreos/go-oidc` was the considered middle ground.
- **The ID token is a bearer credential for its lifetime.** Replay by someone who steals it in transit is bounded by TLS and by the token's own expiry. Per-request nonces are not used: the plugin takes a nonce at `initialize`, which is called once per process, so a server-issued per-sign-in nonce does not fit its API. This matches how every backend consumes these tokens.
- **iOS platform configuration is documented, not committed.** The reversed client ID URL scheme is a per-deployment value; a wrong one silently breaks the callback, which is worse than an absent one. `ios/Runner/Info.plist` carries the block as a comment, and the mobile README carries the setup.

## Verification

`go test -race ./...` and `go test -tags integration -race ./...`, including: a new address producing an active, verified, passwordless account that mails nothing; a returning subject reaching the same account and touching the link; a changed Google address following the subject and leaving the account address alone; an existing verified account being linked; an existing **unverified** account being refused, leaving no link, creating no account, auditing the refusal **durably**, and refusing again on retry; a pending account being activated, its challenge consumed, its superseded ticket rejected, and its registration password discarded so a password login afterwards fails; a disabled account answering as invalid credentials on both routes; an unverified assertion and a malformed asserted address rejected before any write; every verifier failure collapsing to one error; an unconfigured deployment reporting itself unavailable; client-name validation; a second Google identity refused for an account that already has one; and **a password login against a federated-only account returning invalid credentials rather than a 500**.

The verifier's own package signs real RS256 tokens against a local JWKS server and covers a foreign and missing issuer, a wrong audience, expiry, an unpublished `kid`, an `alg: none` token, a tampered payload, a missing or non-boolean `email_verified`, a missing subject or address, an oversized token, both issuer spellings, multiple configured audiences, and the refusal to build without one.

Integration tests cover the nullable column, the `NOT NULL` drop over a reconstructed pre-migration schema, the composite key, the per-provider unique index, the provider check constraint, the cascade delete, and `TouchFederatedIdentity` leaving the account address alone.

Mobile: `flutter analyze` and `flutter test`, covering the session and stored-credential shape matching the password path, the assertion never being persisted, rotation on restore, cancellation producing no error, a platform failure never reaching the server, a rejected assertion signing the device out of Google, each server error's copy, the action being hidden without configuration or platform support, and the button reaching the workspace from both the sign-in and create-account screens without running the password validators.

Manually: register an OAuth client, set `GOOGLE_OAUTH_AUDIENCES`, `docker compose up`, and confirm a first sign-in creates an account, a second reaches the same one, and an unverified pre-existing address is refused with the password prompt.
