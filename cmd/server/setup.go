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
	"opencode-remote/server/internal/identity/disposableemail"
	"opencode-remote/server/internal/identity/googleid"
	identitypostgres "opencode-remote/server/internal/identity/postgres"
	"opencode-remote/server/internal/platform/database"
	"opencode-remote/server/internal/relay"

	"gorm.io/gorm"
)

const migrationTimeout = 30 * time.Second

// Databases are two connection pools over the same PostgreSQL database, one per module.
//
// They must stay separate. Connector transactions call the identity service (account and
// session checks) while holding a connection. With one shared pool, once as many connector
// transactions are open as the pool has connections, each holds one while waiting for a
// second that can never be freed, and all of them stall until their callers time out. Relay
// sockets revalidate every second, so that happens under ordinary load, not only in a burst.
// Identity never calls back into connectors, so two pools cannot wait on each other.
type Databases struct {
	Identity   *gorm.DB
	Connectors *gorm.DB
	// Health is the pool readiness checks use.
	Health *sql.DB
	pools  []*sql.DB
}

func (databases Databases) Close() {
	for _, pool := range databases.pools {
		_ = pool.Close()
	}
}

func SetupDatabase(ctx context.Context, config Config) (Databases, error) {
	var databases Databases
	identityDB, identityPool, err := database.Open(config.DatabaseURL)
	if err != nil {
		return Databases{}, errors.New("database initialization failed")
	}
	databases.pools = append(databases.pools, identityPool)
	connectorDB, connectorPool, err := database.Open(config.DatabaseURL)
	if err != nil {
		databases.Close()
		return Databases{}, errors.New("database initialization failed")
	}
	databases.pools = append(databases.pools, connectorPool)
	databases.Identity, databases.Connectors, databases.Health = identityDB, connectorDB, connectorPool

	migrationContext, cancel := context.WithTimeout(ctx, migrationTimeout)
	defer cancel()
	if err := identitypostgres.Migrate(migrationContext, identityDB); err != nil {
		databases.Close()
		return Databases{}, errors.New("database migration failed")
	}
	if err := connectorspostgres.Migrate(migrationContext, connectorDB); err != nil {
		databases.Close()
		return Databases{}, errors.New("connector database migration failed")
	}
	return databases, nil
}

type Services struct {
	Identity   *identity.Service
	Connectors *connectors.Service
	// RelayHub holds the live relay sockets. Revocations committed by either service close
	// the affected sockets through it immediately (ADR 0021).
	RelayHub *relay.Hub
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

// setupDisposableEmailDetector returns nil when the filter is switched off. Otherwise
// the returned detector loads its list in the background for as long as ctx lives and
// allows every address until it has, so it can neither delay startup nor make a
// download failure an outage.
func setupDisposableEmailDetector(
	ctx context.Context,
	config Config,
	logger *slog.Logger,
) identity.DisposableEmailDetector {
	if !config.DisposableEmail.Enabled {
		logger.Info("disposable email filter disabled")
		return nil
	}
	return disposableemail.Start(ctx, disposableemail.Config{
		CacheDir:     config.DisposableEmail.CacheDir,
		DataURL:      config.DisposableEmail.DataURL,
		AllowDomains: config.DisposableEmail.AllowDomains,
	}, logger)
}

func SetupServices(
	ctx context.Context,
	databases Databases,
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
	relayHub := relay.NewHub()
	identityService, err := identity.NewService(
		identitypostgres.NewStore(databases.Identity),
		identity.NewPasswordHasher(),
		mailer,
		identity.ServiceOptions{
			GoogleVerifier:   googleVerifier,
			DisposableEmails: setupDisposableEmailDetector(ctx, config, logger),
			OnSessionRevoked: func(userID, sessionID string, accountInactive bool) {
				revocation := connectors.Revocation{UserID: userID, SessionID: sessionID}
				if accountInactive {
					revocation.SessionID = "" // every socket of the account
				}
				relayHub.Disconnect(revocation)
			},
		},
	)
	if err != nil {
		return Services{}, errors.New("identity service initialization failed")
	}
	connectorService, err := connectors.NewService(
		connectorspostgres.NewStore(databases.Connectors),
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
			OnRevoked: func(revocation connectors.Revocation) { relayHub.Disconnect(revocation) },
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
	return Services{Identity: identityService, Connectors: connectorService, RelayHub: relayHub}, nil
}
