package identity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

const (
	// TLSModeStartTLS upgrades a plaintext submission connection, the default for
	// port 587 and the broadest provider compatibility.
	TLSModeStartTLS = "starttls"
	// TLSModeImplicit dials TLS directly, as providers requiring port 465 expect.
	TLSModeImplicit = "tls"
	// TLSModeNone is for local development only and is rejected in production.
	TLSModeNone = "none"

	defaultMailTimeout = 10 * time.Second
	mailSubjectPrefix  = "Open Remote Code"
)

type SMTPMailerConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	FromAddress string
	TLSMode     string
	Timeout     time.Duration
}

// SMTPMailer delivers account mail over stdlib net/smtp. It takes no third-party
// dependency, and it owns its own deadlines because net/smtp sets none: an
// unresponsive mail host would otherwise hang the request that triggered the send.
type SMTPMailer struct {
	config SMTPMailerConfig
	auth   smtp.Auth
}

func NewSMTPMailer(config SMTPMailerConfig) (*SMTPMailer, error) {
	if strings.TrimSpace(config.Host) == "" {
		return nil, errors.New("smtp mailer requires a host")
	}
	if config.Port <= 0 || config.Port > 65535 {
		return nil, errors.New("smtp mailer requires a valid port")
	}
	if !validMailAddress(config.FromAddress) {
		return nil, errors.New("smtp mailer requires a valid from address")
	}
	switch config.TLSMode {
	case TLSModeStartTLS, TLSModeImplicit, TLSModeNone:
	default:
		return nil, fmt.Errorf("smtp mailer has an unsupported TLS mode %q", config.TLSMode)
	}
	if config.Timeout <= 0 {
		config.Timeout = defaultMailTimeout
	}
	mailer := &SMTPMailer{config: config}
	if config.Username != "" || config.Password != "" {
		mailer.auth = smtp.PlainAuth("", config.Username, config.Password, config.Host)
	}
	return mailer, nil
}

func (mailer *SMTPMailer) SendVerificationCode(ctx context.Context, to, code string) error {
	return mailer.send(ctx, to, mailSubjectPrefix+" verification code", strings.Join([]string{
		"Enter this code to finish setting up your account:",
		"",
		"    " + code,
		"",
		fmt.Sprintf("The code expires in %d minutes.", int(verificationCodeLifetime.Minutes())),
		"If you did not request it, you can ignore this message.",
	}, "\r\n"))
}

func (mailer *SMTPMailer) SendRegistrationNotice(ctx context.Context, to string) error {
	return mailer.send(ctx, to, mailSubjectPrefix+" account notice", strings.Join([]string{
		"Someone tried to create an account with this email address, but one already exists.",
		"",
		"If that was you, sign in instead. No new account was created and nothing changed.",
		"If it was not you, no action is needed: whoever tried cannot access your account.",
	}, "\r\n"))
}

func (mailer *SMTPMailer) send(ctx context.Context, to, subject, body string) error {
	if !validMailAddress(to) {
		return fmt.Errorf("%w: invalid recipient address", ErrMailUndeliverable)
	}
	deadline := time.Now().Add(mailer.config.Timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	sendContext, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	connection, err := mailer.dial(sendContext)
	if err != nil {
		return fmt.Errorf("%w: connect to mail host: %v", ErrMailDeliveryFailed, err)
	}
	// One deadline covers the whole session. net/smtp performs blocking reads and
	// writes with no timeout of its own, so without this a silent host hangs forever.
	if err := connection.SetDeadline(deadline); err != nil {
		connection.Close()
		return fmt.Errorf("%w: set mail deadline: %v", ErrMailDeliveryFailed, err)
	}

	client, err := smtp.NewClient(connection, mailer.config.Host)
	if err != nil {
		connection.Close()
		return fmt.Errorf("%w: start mail session: %v", ErrMailDeliveryFailed, err)
	}
	defer client.Close()

	if mailer.config.TLSMode == TLSModeStartTLS {
		if err := client.StartTLS(&tls.Config{ServerName: mailer.config.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("%w: start TLS: %v", ErrMailDeliveryFailed, err)
		}
	}
	if mailer.auth != nil {
		if err := client.Auth(mailer.auth); err != nil {
			return fmt.Errorf("%w: authenticate: %v", ErrMailDeliveryFailed, err)
		}
	}
	// A rejected sender is our own misconfiguration and says nothing about the
	// recipient, so it stays a transient-class failure and records no bounce.
	if err := client.Mail(mailer.config.FromAddress); err != nil {
		return fmt.Errorf("%w: sender rejected: %v", ErrMailDeliveryFailed, err)
	}
	if err := client.Rcpt(to); err != nil {
		return classifyRecipientError("recipient rejected", err)
	}

	writer, err := client.Data()
	if err != nil {
		return classifyRecipientError("message rejected", err)
	}
	if _, err := writer.Write([]byte(mailer.message(to, subject, body))); err != nil {
		writer.Close()
		return fmt.Errorf("%w: write message: %v", ErrMailDeliveryFailed, err)
	}
	if err := writer.Close(); err != nil {
		return classifyRecipientError("message rejected", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("%w: close mail session: %v", ErrMailDeliveryFailed, err)
	}
	return nil
}

func (mailer *SMTPMailer) dial(ctx context.Context) (net.Conn, error) {
	address := net.JoinHostPort(mailer.config.Host, fmt.Sprint(mailer.config.Port))
	dialer := &net.Dialer{Timeout: mailer.config.Timeout}
	if mailer.config.TLSMode == TLSModeImplicit {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{ServerName: mailer.config.Host, MinVersion: tls.VersionTLS12},
		}
		return tlsDialer.DialContext(ctx, "tcp", address)
	}
	return dialer.DialContext(ctx, "tcp", address)
}

func (mailer *SMTPMailer) message(to, subject, body string) string {
	headers := []string{
		"From: " + mailer.config.FromAddress,
		"To: " + to,
		"Subject: " + subject,
		"Date: " + time.Now().UTC().Format(time.RFC1123Z),
		"MIME-Version: 1.0",
		"Content-Type: text/plain; charset=utf-8",
	}
	return strings.Join(headers, "\r\n") + "\r\n\r\n" + body + "\r\n"
}

// classifyRecipientError separates a permanent rejection of this recipient, which
// marks the address bad, from everything else. Only a 5xx reply is permanent; a 4xx
// or a transport error is transient and must not record a bounce.
func classifyRecipientError(stage string, err error) error {
	var protocolError *textproto.Error
	if errors.As(err, &protocolError) && protocolError.Code >= 500 && protocolError.Code < 600 {
		return fmt.Errorf("%w: %s: %v", ErrMailUndeliverable, stage, err)
	}
	return fmt.Errorf("%w: %s: %v", ErrMailDeliveryFailed, stage, err)
}

// validMailAddress is a header-injection guard as much as a sanity check: a bare
// address can never contain a line break or the envelope could be rewritten.
func validMailAddress(address string) bool {
	if address == "" || len(address) > maximumEmailLength {
		return false
	}
	if strings.ContainsAny(address, "\r\n") || strings.TrimSpace(address) != address {
		return false
	}
	return strings.Count(address, "@") == 1 &&
		!strings.HasPrefix(address, "@") &&
		!strings.HasSuffix(address, "@")
}
