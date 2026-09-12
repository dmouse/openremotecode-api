package identity

import (
	"context"
	"log/slog"
)

// LoggingMailer writes verification codes to the log instead of sending them, so
// local development needs no mail host. It is wired only when the server runs in
// development mode with no SMTP host configured.
//
// This is the one deliberate exception to "never log credentials": in development
// the log IS the delivery channel, and the code it prints is a short-lived secret
// for an account on a local database. Never wire this in production — the
// configuration loader rejects that arrangement, and this type must never become
// reachable another way.
type LoggingMailer struct {
	logger *slog.Logger
}

func NewLoggingMailer(logger *slog.Logger) *LoggingMailer {
	if logger == nil {
		logger = slog.Default()
	}
	return &LoggingMailer{logger: logger}
}

func (mailer *LoggingMailer) SendVerificationCode(ctx context.Context, to, code string) error {
	mailer.logger.InfoContext(
		ctx,
		"development mail: email verification code",
		"recipient", to,
		"code", code,
	)
	return nil
}

func (mailer *LoggingMailer) SendRegistrationNotice(ctx context.Context, to string) error {
	mailer.logger.InfoContext(
		ctx,
		"development mail: registration notice for an existing address",
		"recipient", to,
	)
	return nil
}
