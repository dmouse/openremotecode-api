package main

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"time"

	"opencode-remote/server/internal/connectors"
	connectorspostgres "opencode-remote/server/internal/connectors/postgres"
	"opencode-remote/server/internal/identity"
	"opencode-remote/server/internal/identity/googleid"
	identitypostgres "opencode-remote/server/internal/identity/postgres"
	"opencode-remote/server/internal/platform/database"

	"gorm.io/gorm"
)

const migrationTimeout = 30 * time.Second

func SetupDatabase(ctx context.Context, config Config) (*gorm.DB, *sql.DB, error) {
	db, pool, err := database.Open(config.DatabaseURL)
	if err != nil {
		return nil, nil, errors.New("database initialization failed")
	}
	migrationContext, cancel := context.WithTimeout(ctx, migrationTimeout)
	defer cancel()
	if err := identitypostgres.Migrate(migrationContext, db); err != nil {
		pool.Close()
		return nil, nil, errors.New("database migration failed")
	}
	if err := connectorspostgres.Migrate(migrationContext, db); err != nil {
		pool.Close()
		return nil, nil, errors.New("connector database migration failed")
	}
	return db, pool, nil
}

type Services struct {
	Identity   *identity.Service
	Connectors *connectors.Service
}

// setupMailer prefers Mailgun's HTTPS API when MAILGUN_API_KEY is configured: it
// isn't affected by a host or network that blocks outbound SMTP ports, a common
// cloud-provider default (see docs/adr/0010-mailgun-http-mailer.md). It falls back
// to SMTP, then to the logging mailer only when neither is configured — the
// configuration loader requires one or the other in production, so that fallback
// is reachable in development alone.
func setupMailer(config Config, logger *slog.Logger) (identity.Mailer, error) {
	if config.Mailgun.APIKey != "" {
		mailer, err := identity.NewMailgunMailer(identity.MailgunMailerConfig{
			APIKey:      config.Mailgun.APIKey,
			Domain:      config.Mailgun.Domain,
			FromAddress: config.Mailgun.FromAddress,
			Region:      config.Mailgun.Region,
		})
		if err != nil {
			return nil, errors.New("mailer initialization failed")
		}
		return mailer, nil
	}
	if config.SMTP.Host == "" {
		return identity.NewLoggingMailer(logger), nil
	}
	mailer, err := identity.NewSMTPMailer(identity.SMTPMailerConfig{
		Host:        config.SMTP.Host,
		Port:        config.SMTP.Port,
		Username:    config.SMTP.Username,
		Password:    config.SMTP.Password,
		FromAddress: config.SMTP.FromAddress,
		TLSMode:     config.SMTP.TLSMode,
	})
	if err != nil {
		return nil, errors.New("mailer initialization failed")
	}
	return mailer, nil
}

// setupGoogleVerifier returns nil when no audience is configured, which leaves
// Google sign-in switched off. It is not an error: a deployment that has registered
// no OAuth client simply does not offer the route.
func setupGoogleVerifier(
	ctx context.Context,
	config Config,
	logger *slog.Logger,
) (identity.GoogleVerifier, error) {
	if len(config.GoogleAudiences) == 0 {
		logger.Info("google sign-in disabled", "reason", "no GOOGLE_OAUTH_AUDIENCES configured")
		return nil, nil
	}
	verifier, err := googleid.NewVerifier(ctx, config.GoogleAudiences)
	if err != nil {
		return nil, errors.New("google verifier initialization failed")
	}
	return verifier, nil
}

func SetupServices(
	ctx context.Context,
	db *gorm.DB,
	config Config,
	logger *slog.Logger,
) (Services, error) {
	mailer, err := setupMailer(config, logger)
	if err != nil {
		return Services{}, err
	}
	googleVerifier, err := setupGoogleVerifier(ctx, config, logger)
	if err != nil {
		return Services{}, err
	}
	identityService, err := identity.NewService(
		identitypostgres.NewStore(db),
		identity.NewPasswordHasher(),
		mailer,
		identity.ServiceOptions{GoogleVerifier: googleVerifier},
	)
	if err != nil {
		return Services{}, errors.New("identity service initialization failed")
	}
	connectorService, err := connectors.NewService(
		connectorspostgres.NewStore(db),
		connectors.ServiceOptions{
			PairingCodeKey:      []byte(config.PairingCodeKey),
			DeviceCredentialKey: []byte(config.DeviceCredentialKey),
			ServiceID:           config.ServiceID,
			VerificationURI:     config.VerificationURI,
			AuthorizeAccount: func(ctx context.Context, userID string) error {
				if err := identityService.AuthorizeAccount(ctx, userID); errors.Is(err, identity.ErrUnauthorized) {
					return connectors.ErrUnauthorized
				} else {
					return err
				}
			},
			AuthorizeSession: func(ctx context.Context, userID, sessionID string) error {
				if err := identityService.AuthorizeSession(ctx, userID, sessionID); errors.Is(err, identity.ErrUnauthorized) {
					return connectors.ErrUnauthorized
				} else {
					return err
				}
			},
		},
	)
	if err != nil {
		return Services{}, errors.New("connector service initialization failed")
	}
	return Services{Identity: identityService, Connectors: connectorService}, nil
}
