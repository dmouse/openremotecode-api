# ADR 0016: Disposable Email Filter

## Status

Accepted. Refines [ADR 0008](0008-email-verified-registration.md): email verification proves an address is reachable, and this filter refuses one class of reachable address that proves nothing about the person.

## Context

Registration mails a code to the address it is given and activates the account only once the code is returned. That stops typos and addresses nobody controls, but not a throwaway inbox created for the purpose (mailinator and its many imitators). Those give an abuser an unlimited supply of verified accounts, which defeats per-account limits and makes revocation meaningless because a banned user simply registers again.

`github.com/rezmoss/go-is-disposable-email` maintains a merged list of roughly 76,000 such domains, refreshed daily upstream, with subdomain matching and an allowlist that takes precedence.

## Decision

**`Register` rejects an address whose domain is on the list, with `identity.ErrDisposableEmail`, surfaced as HTTP 400 `disposable_email`.**

- **Where it applies.** Registration only. Login, resend, and verification never consult it: an account that registered before its domain was listed must keep working. Google sign-in is not filtered either; Google has already verified the address, and refusing a person who has proved control of an address at an identity provider would only block a legitimate sign-in.
- **Explicit error, not a decoy.** ADR 0008 answers a duplicate address indistinguishably so registration cannot be used to discover accounts. The disposable verdict is a function of the domain alone and never of account state, so returning it plainly leaks nothing, and the person can act on it by choosing another address. A test asserts the verdict is identical for an address that is already registered and one that is not. The check runs before hashing the password and before the transaction, so a rejected address costs almost nothing.
- **Module boundary.** The identity module owns a one-method interface, `DisposableEmailDetector`. The vendor library is confined to `internal/identity/disposableemail`, as `googleid` confines the Google client, and `identity` imports no transport or third-party code for it.
- **Fail open.** The library does not embed its list. It downloads it from a GitHub release on first use and caches it. That is a runtime dependency on a third party for what is otherwise a self-contained service, and this is a spam control rather than a security boundary, so the adapter never lets it gate anything:
  - The list loads on a background goroutine; startup does not wait for it.
  - Until it has loaded, the detector reports every address as not disposable.
  - A failed load is retried with backoff (30 seconds, doubling to 15 minutes) and logged at warn level. A failed refresh keeps the previous list.
  - Readiness does not depend on it, as ADR 0008 already decided for mail.
- **Configuration.**
  - `DISPOSABLE_EMAIL_FILTER`: on by default in production, off in development. The upstream list contains `example.com`, which every development and test address uses. A malformed value stops startup, like the other switches.
  - `DISPOSABLE_EMAIL_CACHE_DIR`: must be writable. The production container has a read-only root filesystem, so `compose.api.prod.yaml` mounts a tmpfs there and the list is re-downloaded (about 450 KB) on each start.
  - `DISPOSABLE_EMAIL_DATA_URL`: replaces the upstream release URL so a deployment can self-host a reviewed copy. It must be HTTPS (plain HTTP is accepted only in development) and must not contain credentials.
  - `DISPOSABLE_EMAIL_ALLOW_DOMAINS`: comma-separated domains, subdomains included, that are never rejected. It is the remedy for a false positive that cannot wait for an upstream update.

## Threat analysis

- **Poisoned or tampered list.** The list decides who may register, so whoever controls the download can lock every new user out (by listing `gmail.com`) or disable the filter (by serving an empty list). The download is over TLS from GitHub's release CDN, which is the same trust the Go module proxy already carries for the build. The file is deserialized from that download, so a malformed payload is parsed by the library's decoder; the library validates before swapping it in and a failure keeps the old list. Deployments that do not want to trust the upstream release feed set `DISPOSABLE_EMAIL_DATA_URL` to a copy they host after review. The library offers no signature or hash pinning, so this ADR does not claim integrity beyond TLS.
- **Availability.** Fail-open means an attacker who can block the download can only disable the filter, not registration. Every failure is logged, and the tmpfs cache means a restart during an upstream outage starts unfiltered rather than not at all.
- **Evasion.** Anyone can use an unlisted throwaway provider, a subdomain of a domain they control, or a forwarding alias on a mainstream provider. This raises the cost of abuse; it does not stop it. Per-account and per-address rate limits remain the controls that bound abuse.
- **False positives.** The list is broad and may block a legitimate privacy-alias domain. The response tells the person to use a permanent address, and the operator can allowlist a domain without a release.
- **Information disclosure.** The error reveals only that a domain is listed, which is public information. It carries no account state.
- **Logging.** The adapter logs list sizes and load errors. It never logs the address being checked, and rejected registrations are not audited, since the audit trail records account events and there is no account.

## Consequences

- **A new runtime dependency on `github.com/rezmoss/go-is-disposable-email`,** whose only requirement is the standard library, plus an outbound HTTPS request from the API container to its data URL. Operators who firewall egress must allow it or self-host.
- **The production container is no longer fully stateless on disk,** which is why the cache directory is a tmpfs rather than the read-only rootfs being relaxed.
- **Mobile shows a specific message** for the `disposable_email` code, so the person knows to change the address rather than retry.
- **Not covered.** Existing accounts on disposable domains are left alone, and there is no periodic sweep of them.

## Verification

`go test -race ./...`, including: service tests that a listed address is rejected before any account or mail is created, that an unlisted one is accepted, that login for an existing account is unaffected, and that the verdict is the same for a registered and an unregistered address; adapter tests that the detector reports false until loaded, retries after failure, and releases the checker and stops retrying when its context ends; a handler test for the 400 `disposable_email` mapping; and configuration tests for the per-environment default, the settings, and rejection of a plaintext or credentialed data URL without echoing it.

The library itself was checked against its shipped `data.bin` (76,276 domains): mixed-case and subdomain matches are caught, the allowlist wins, and `example.com` is listed. A trailing-dot or display-name form of a listed domain cannot bypass the check because `normalizeEmail` already rejects both.
