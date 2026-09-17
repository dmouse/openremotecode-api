package identity

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/mailgun/mailgun-go/v5"
)

const defaultMailgunTimeout = 10 * time.Second

type MailgunMailerConfig struct {
	APIKey      string
	Domain      string
	FromAddress string
	// Region selects the API base: "" or "us" for the default (api.mailgun.net),
	// "eu" for EU-region accounts (api.eu.mailgun.net).
	Region  string
	Timeout time.Duration
}

// MailgunMailer delivers account mail over Mailgun's HTTPS API rather than SMTP, so
// it isn't blocked by a host or network that blocks outbound SMTP ports — a common
// cloud-provider default. See docs/adr/0010-mailgun-http-mailer.md.
//
// Unlike SMTPMailer, it never returns ErrMailUndeliverable. The messages endpoint
// has no synchronous per-recipient rejection analogous to an SMTP RCPT TO reply:
// Mailgun checks its bounce/complaint/unsubscribe suppression lists and reports
// them asynchronously through webhooks this server does not yet ingest (see ADR
// 0008, "Deferred: asynchronous bounce ingestion"). Every failure this mailer sees
// is therefore treated as transient, and email_bounced_at is never set by this path.
type MailgunMailer struct {
	client      *mailgun.Client
	domain      string
	fromAddress string
	timeout     time.Duration
}

func NewMailgunMailer(config MailgunMailerConfig) (*MailgunMailer, error) {
	if strings.TrimSpace(config.APIKey) == "" {
		return nil, errors.New("mailgun mailer requires an API key")
	}
	domain := strings.TrimSpace(config.Domain)
	if domain == "" {
		return nil, errors.New("mailgun mailer requires a domain")
	}
	if !validMailAddress(config.FromAddress) {
		return nil, errors.New("mailgun mailer requires a valid from address")
	}
	if config.Timeout <= 0 {
		config.Timeout = defaultMailgunTimeout
	}

	client := mailgun.NewMailgun(config.APIKey)
	// Belt and braces alongside the per-send context deadline below, the same way
	// SMTPMailer owns its own deadline: the underlying http.Client would otherwise
	// have none of its own.
	client.SetHTTPClient(&http.Client{Timeout: config.Timeout})
	switch strings.ToLower(strings.TrimSpace(config.Region)) {
	case "", "us":
	case "eu":
		if err := client.SetAPIBase(mailgun.APIBaseEU); err != nil {
			return nil, fmt.Errorf("set mailgun API base: %w", err)
		}
	default:
		return nil, fmt.Errorf("mailgun mailer has an unsupported region %q", config.Region)
	}

	return &MailgunMailer{
		client:      client,
		domain:      domain,
		fromAddress: config.FromAddress,
		timeout:     config.Timeout,
	}, nil
}

func (mailer *MailgunMailer) SendVerificationCode(ctx context.Context, to, code string) error {
	return mailer.send(ctx, to, mailSubjectPrefix+" verification code", strings.Join([]string{
		"Enter this code to finish setting up your account:",
		"",
		"    " + code,
		"",
		fmt.Sprintf("The code expires in %d minutes.", int(verificationCodeLifetime.Minutes())),
		"If you did not request it, you can ignore this message.",
	}, "\n"))
}

func (mailer *MailgunMailer) SendRegistrationNotice(ctx context.Context, to string) error {
	return mailer.send(ctx, to, mailSubjectPrefix+" account notice", strings.Join([]string{
		"Someone tried to create an account with this email address, but one already exists.",
		"",
		"If that was you, sign in instead. No new account was created and nothing changed.",
		"If it was not you, no action is needed: whoever tried cannot access your account.",
	}, "\n"))
}

func (mailer *MailgunMailer) send(ctx context.Context, to, subject, body string) error {
	if !validMailAddress(to) {
		return fmt.Errorf("%w: invalid recipient address", ErrMailUndeliverable)
	}
	sendContext, cancel := context.WithTimeout(ctx, mailer.timeout)
	defer cancel()

	message := mailgun.NewMessage(mailer.domain, mailer.fromAddress, subject, body, to)
	if _, err := mailer.client.Send(sendContext, message); err != nil {
		return fmt.Errorf("%w: send via mailgun: %v", ErrMailDeliveryFailed, err)
	}
	return nil
}
