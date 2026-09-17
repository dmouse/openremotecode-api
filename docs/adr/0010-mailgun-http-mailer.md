# ADR 0010: Mailgun HTTP Mailer

## Status

Accepted. Amends [ADR 0008](0008-email-verified-registration.md)'s "no third-party dependency" mail decision: that remains true of `SMTPMailer`, but is no longer true of the mailer subsystem as a whole.

## Context

ADR 0008 delivers verification mail over SMTP using `net/smtp`, deliberately with no vendor SDK. That works for hosts that allow outbound SMTP, but several cloud providers block outbound SMTP ports (25, 465, 587, 2525) by default as an anti-spam measure, with no per-Droplet or per-instance toggle — unblocking requires a provider support ticket, evaluated case by case, sometimes taking hours to days with no guarantee for a newer account. DigitalOcean is one such provider and is where this project's first production deployment runs. On that host, `SMTPMailer` cannot make an outbound connection to any SMTP relay, Mailgun's included, regardless of local firewall configuration (`iptables`, `ufw`, a cloud firewall) — the block is enforced upstream of the instance's own network stack, confirmed by a hung TCP handshake to `smtp.mailgun.org` on both 587 and 465 despite an `OUTPUT: ACCEPT` host firewall.

Mailgun also offers an HTTPS API, which runs over port 443 — a port cloud providers do not block, since blocking it would break unrelated HTTPS traffic entirely.

## Decision

**`MailgunMailer` (`internal/identity/mailgun_mailer.go`) is a second `Mailer` implementation, using `github.com/mailgun/mailgun-go/v5` to call Mailgun's messages endpoint over HTTPS.** It is additive: `SMTPMailer` is unchanged, and a deployment not affected by an SMTP block can keep using it with no third-party dependency, exactly as ADR 0008 decided.

- `setupMailer` prefers Mailgun when `MAILGUN_API_KEY` is set, then falls back to SMTP when `SMTP_HOST` is set, then to the logging mailer in development. The two are alternatives, not layers — a deployment configures one.
- Configuration is `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, `MAILGUN_FROM_ADDRESS`, and optional `MAILGUN_REGION` (`eu` for EU-region accounts, otherwise the US API base). A partially set Mailgun configuration — an API key with no domain, for instance — fails startup in every environment rather than silently falling through to SMTP or the logging mailer, the same fail-closed posture `PAIRING_CODE_KEY` and the rest of `validateMail` already take.
- Production requires **either** SMTP (`SMTP_HOST` and `SMTP_FROM_ADDRESS`) **or** Mailgun (all three required fields) fully configured; it no longer hardcodes SMTP as the only production-valid mailer.
- Both mailers own their own send deadline: `MailgunMailer` sets a `context.WithTimeout` per send and a matching `http.Client` timeout, the same belt-and-braces reasoning `SMTPMailer` already applies to its dial and session.
- **`MailgunMailer` never returns `ErrMailUndeliverable`.** Mailgun's messages endpoint has no synchronous per-recipient rejection analogous to an SMTP `RCPT TO` 5xx reply: its documented `400` responses are almost entirely about a malformed request (bad `to`/`from`/`cc` format, unverified sending domain, sandbox restrictions) rather than about a specific recipient's mailbox, and a recipient's presence on Mailgun's bounce/complaint/unsubscribe suppression list is consulted and reported asynchronously — the same asynchronous-bounce gap ADR 0008 already named and deferred ("Deferred: asynchronous bounce ingestion"). Rather than guess at which `400` messages mean "this recipient is bad" from Mailgun's error-message text, every Mailgun send failure is classified `ErrMailDeliveryFailed` (transient). `email_bounced_at` is therefore never set by this mailer; it stays exactly as informative as ADR 0008 left it for a deployment using SMTP, and no worse.
- The mailer talks to Mailgun exclusively through `mailgun-go`'s `Client`, matching the existing pattern for a vendor SDK dependency (`internal/identity/googleid`, added by ADR 0009): the vendor type does not leak past this one file, and `identity.Mailer` stays the only interface the rest of the identity module depends on.

## Consequences

- **A production deployment now has two mail-configuration shapes to choose from**, documented side by side in `server/README.md` and `.env.production.example`. This is more surface than ADR 0008 left, accepted because the alternative — a deployment that simply cannot send mail — blocks registration entirely.
- **Bounce tracking regresses to "never populated" for any deployment using Mailgun**, rather than "populated only for a synchronous 5xx" as it is for SMTP. Both are best-effort diagnostic states that gate nothing (ADR 0008), so this is a loss of diagnostic precision, not a security or availability regression. The already-deferred webhook-based bounce ingestion in ADR 0008 remains the correct fix for both mailers going forward — it would populate `email_bounced_at` from Mailgun's own bounce/complaint webhooks regardless of which mailer sent the message that eventually bounced.
- **A new indirect trust dependency**: `github.com/mailgun/mailgun-go/v5` and its transitive dependencies are now part of the build for any deployment, whether or not it uses Mailgun. This is the same trade-off ADR 0009 already accepted for `google.golang.org/api/idtoken`.
- **Readiness is unaffected**: mail remains excluded from `/health/ready`, per ADR 0008's existing reasoning that readiness should not depend on an optional third-party service. This applies equally to Mailgun's API.

## Verification

`go test ./...`, including: `TestLoadConfigProductionFailsClosed` cases for Mailgun alone satisfying production, a partial Mailgun configuration failing closed in every environment, and an unknown `MAILGUN_REGION` value failing closed; `TestNewMailgunMailerValidatesConfiguration`; and `TestMailgunMailerEnforcesItsDeadline` against an HTTP server that accepts the connection and never responds, asserting the send fails within its deadline as `ErrMailDeliveryFailed` and never `ErrMailUndeliverable`.

Manually, against the affected production host: set `MAILGUN_API_KEY`, `MAILGUN_DOMAIN`, and `MAILGUN_FROM_ADDRESS`, leave `SMTP_HOST` unset, redeploy, register, and confirm the verification email arrives — despite outbound SMTP remaining blocked at the network level.
