package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"opencode-remote/server/internal/identity"

	"github.com/spf13/viper"
)

const (
	defaultHTTPAddress     = "127.0.0.1:8080"
	defaultDatabaseURL     = "postgres://opencode_remote:local-development-only@127.0.0.1:5432/opencode_remote?sslmode=disable"
	defaultServiceID       = "local-development"
	defaultVerificationURI = "http://127.0.0.1:8080"
	defaultSMTPPort        = 587
)

// Config is a validated startup snapshot. Services never read process environment.
type Config struct {
	HTTPAddress                string
	DatabaseURL                string
	TLS                        *tls.Config
	PairingCodeKey             string
	DeviceCredentialKey        string
	ServiceID                  string
	VerificationURI            string
	AllowedOrigins             []string
	TrustedProxies             []*net.IPNet
	InsecureDevelopmentCookies bool
	DevelopmentRelayEnabled    bool
	// RegistrationEnabled is an operational kill switch, not a security control:
	// registration is verified by email, so it defaults on in every environment.
	RegistrationEnabled bool
	SMTP                SMTPConfig
	// GoogleAudiences holds the OAuth client IDs a Google ID token may be addressed
	// to — normally one per mobile platform plus the web client ID those platforms
	// request server tokens for. Empty disables Google sign-in entirely, which is the
	// default: a deployment that has not registered an OAuth client has nothing to
	// verify against, and the route reports itself unavailable rather than failing
	// every assertion as invalid.
	GoogleAudiences []string
}

// SMTPConfig is empty only in development, where an unset host selects the mailer
// that logs codes instead of sending them.
type SMTPConfig struct {
	Host        string
	Port        int
	Username    string
	Password    string
	FromAddress string
	TLSMode     string
}

func LoadConfig() (Config, error) {
	settings := viper.New()
	settings.SetDefault("HTTP_ADDR", defaultHTTPAddress)
	settings.SetDefault("DATABASE_URL", defaultDatabaseURL)
	settings.SetDefault("APP_ENV", "production")
	// Defaulted rather than left empty so booleanSetting still parses it strictly;
	// a malformed value must fail startup instead of silently disabling registration.
	settings.SetDefault("REGISTRATION_ENABLED", "true")
	settings.SetDefault("SMTP_PORT", defaultSMTPPort)
	settings.SetDefault("SMTP_TLS_MODE", identity.TLSModeStartTLS)
	settings.AutomaticEnv()

	development := settings.GetString("APP_ENV") == "development"
	if development {
		settings.SetDefault("PAIRING_CODE_KEY", "local-development-pairing-code-key-change-me")
		settings.SetDefault("SERVICE_ID", defaultServiceID)
		settings.SetDefault("PAIRING_VERIFICATION_URI", defaultVerificationURI)
	}
	config := Config{
		HTTPAddress:    settings.GetString("HTTP_ADDR"),
		DatabaseURL:    settings.GetString("DATABASE_URL"),
		PairingCodeKey: settings.GetString("PAIRING_CODE_KEY"),
		// Separate from PAIRING_CODE_KEY so the user-code key can be rotated without
		// invalidating every paired device. Seeded from it when unset.
		DeviceCredentialKey: settings.GetString("DEVICE_CREDENTIAL_KEY"),
		ServiceID:           strings.TrimSpace(settings.GetString("SERVICE_ID")),
		VerificationURI:     strings.TrimSpace(settings.GetString("PAIRING_VERIFICATION_URI")),
		AllowedOrigins:      strings.Split(settings.GetString("BROWSER_ORIGINS"), ","),
		SMTP: SMTPConfig{
			Host:        strings.TrimSpace(settings.GetString("SMTP_HOST")),
			Port:        settings.GetInt("SMTP_PORT"),
			Username:    settings.GetString("SMTP_USERNAME"),
			Password:    settings.GetString("SMTP_PASSWORD"),
			FromAddress: strings.TrimSpace(settings.GetString("SMTP_FROM_ADDRESS")),
			TLSMode:     strings.TrimSpace(settings.GetString("SMTP_TLS_MODE")),
		},
	}
	var err error
	config.TLS, err = loadTransportTLS(development, settings.GetString("TLS_CERT_FILE"), settings.GetString("TLS_KEY_FILE"))
	if err != nil {
		return Config{}, err
	}
	if len(config.PairingCodeKey) < 32 {
		return Config{}, errors.New("PAIRING_CODE_KEY must contain at least 32 bytes")
	}
	if config.DeviceCredentialKey == "" {
		config.DeviceCredentialKey = config.PairingCodeKey
	}
	if len(config.DeviceCredentialKey) < 32 {
		return Config{}, errors.New("DEVICE_CREDENTIAL_KEY must contain at least 32 bytes")
	}
	if development {
		if config.ServiceID == "" {
			config.ServiceID = defaultServiceID
		}
		if config.VerificationURI == "" {
			config.VerificationURI = defaultVerificationURI
		}
	} else if config.ServiceID == "" || !validProductionVerificationURI(config.VerificationURI) {
		return Config{}, errors.New("production requires SERVICE_ID and an HTTPS PAIRING_VERIFICATION_URI")
	}
	for _, flag := range []struct {
		name   string
		target *bool
	}{
		{"INSECURE_DEVELOPMENT_COOKIES", &config.InsecureDevelopmentCookies},
		{"ENABLE_INSECURE_DEVELOPMENT_RELAY", &config.DevelopmentRelayEnabled},
		{"REGISTRATION_ENABLED", &config.RegistrationEnabled},
	} {
		*flag.target, err = booleanSetting(settings, flag.name)
		if err != nil {
			return Config{}, err
		}
	}
	// REGISTRATION_ENABLED is deliberately outside this check: it is an ops switch,
	// not a security downgrade, and registration is safe in production now that an
	// account cannot be used until its email is verified.
	if !development && (config.InsecureDevelopmentCookies || config.DevelopmentRelayEnabled) {
		return Config{}, errors.New("insecure development features require APP_ENV=development")
	}
	if err := validateSMTP(&config.SMTP, development); err != nil {
		return Config{}, err
	}
	config.TrustedProxies, err = parseNetworks(settings.GetString("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return Config{}, errors.New("invalid TRUSTED_PROXY_CIDRS value")
	}
	config.GoogleAudiences = parseList(settings.GetString("GOOGLE_OAUTH_AUDIENCES"))
	return config, nil
}

// parseList splits a comma-separated setting and drops empty entries, so that a
// trailing comma or an unset variable yields no audience rather than an empty one.
// An empty audience would disable idtoken's audience check altogether.
func parseList(value string) []string {
	var items []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}
	return items
}

// Viper's GetBool coerces malformed values to false; security switches must fail closed.
func booleanSetting(settings *viper.Viper, name string) (bool, error) {
	value := settings.GetString(name)
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("invalid %s value", name)
	}
	return parsed, nil
}

// validateSMTP fails closed in production the way PAIRING_CODE_KEY does: mail is
// the only way an account can be activated there, and plaintext submission would
// put verification codes on the wire. Development may leave it unset entirely,
// which selects the mailer that logs codes.
func validateSMTP(config *SMTPConfig, development bool) error {
	if config.Port <= 0 || config.Port > 65535 {
		return errors.New("SMTP_PORT must be a valid port number")
	}
	switch config.TLSMode {
	case identity.TLSModeStartTLS, identity.TLSModeImplicit:
	case identity.TLSModeNone:
		if !development {
			return errors.New("production requires SMTP_TLS_MODE of starttls or tls")
		}
	default:
		return errors.New("SMTP_TLS_MODE must be starttls, tls, or none")
	}
	if development {
		return nil
	}
	if config.Host == "" || config.FromAddress == "" {
		return errors.New("production requires SMTP_HOST and SMTP_FROM_ADDRESS")
	}
	return nil
}

func validProductionVerificationURI(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == ""
}

func parseNetworks(value string) ([]*net.IPNet, error) {
	var networks []*net.IPNet
	for _, configuredNetwork := range strings.Split(value, ",") {
		configuredNetwork = strings.TrimSpace(configuredNetwork)
		if configuredNetwork == "" {
			continue
		}
		_, network, err := net.ParseCIDR(configuredNetwork)
		if err != nil {
			return nil, err
		}
		networks = append(networks, network)
	}
	return networks, nil
}
