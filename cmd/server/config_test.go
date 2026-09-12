package main

import (
	"strings"
	"testing"

	"opencode-remote/server/internal/identity"
)

func clearConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"APP_ENV", "HTTP_ADDR", "DATABASE_URL", "TLS_CERT_FILE", "TLS_KEY_FILE",
		"PAIRING_CODE_KEY", "SERVICE_ID", "PAIRING_VERIFICATION_URI", "BROWSER_ORIGINS",
		"TRUSTED_PROXY_CIDRS", "INSECURE_DEVELOPMENT_COOKIES",
		"ENABLE_INSECURE_DEVELOPMENT_RELAY", "REGISTRATION_ENABLED",
		"SMTP_HOST", "SMTP_PORT", "SMTP_USERNAME", "SMTP_PASSWORD",
		"SMTP_FROM_ADDRESS", "SMTP_TLS_MODE",
	} {
		t.Setenv(key, "")
	}
}

func TestLoadConfigDevelopmentDefaultsAndOverrides(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("APP_ENV", "development")
	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.HTTPAddress != defaultHTTPAddress || config.DatabaseURL != defaultDatabaseURL ||
		config.ServiceID != defaultServiceID || config.VerificationURI != defaultVerificationURI ||
		config.TLS != nil || len(config.PairingCodeKey) < 32 || len(config.TrustedProxies) != 0 ||
		config.InsecureDevelopmentCookies || config.DevelopmentRelayEnabled {
		t.Fatal("unexpected development defaults")
	}
	// Registration is on unless an operator turns it off, and an unset SMTP host is
	// what selects the development mailer that logs codes.
	if !config.RegistrationEnabled || config.SMTP.Host != "" ||
		config.SMTP.Port != defaultSMTPPort || config.SMTP.TLSMode != identity.TLSModeStartTLS {
		t.Fatalf("unexpected registration and mail defaults: %#v", config.SMTP)
	}
	t.Setenv("HTTP_ADDR", "127.0.0.1:9090")
	t.Setenv("DATABASE_URL", "postgres://test.invalid/test")
	t.Setenv("SERVICE_ID", " test-service ")
	t.Setenv("PAIRING_VERIFICATION_URI", " http://127.0.0.1:9090 ")
	t.Setenv("BROWSER_ORIGINS", "https://client.example.test,https://other.example.test")
	t.Setenv("TRUSTED_PROXY_CIDRS", " 10.0.0.0/8, ,::1/128 ")
	t.Setenv("INSECURE_DEVELOPMENT_COOKIES", "true")
	t.Setenv("ENABLE_INSECURE_DEVELOPMENT_RELAY", "1")
	t.Setenv("REGISTRATION_ENABLED", "FALSE")
	t.Setenv("SMTP_HOST", " mail.example.test ")
	t.Setenv("SMTP_PORT", "465")
	t.Setenv("SMTP_FROM_ADDRESS", " no-reply@example.test ")
	t.Setenv("SMTP_TLS_MODE", "tls")
	updated, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if updated.HTTPAddress != "127.0.0.1:9090" || updated.DatabaseURL != "postgres://test.invalid/test" ||
		updated.ServiceID != "test-service" || updated.VerificationURI != "http://127.0.0.1:9090" ||
		len(updated.AllowedOrigins) != 2 || len(updated.TrustedProxies) != 2 ||
		!updated.InsecureDevelopmentCookies || !updated.DevelopmentRelayEnabled || updated.RegistrationEnabled {
		t.Fatal("environment overrides were not applied")
	}
	if updated.SMTP.Host != "mail.example.test" || updated.SMTP.Port != 465 ||
		updated.SMTP.FromAddress != "no-reply@example.test" || updated.SMTP.TLSMode != identity.TLSModeImplicit {
		t.Fatalf("mail overrides were not applied: %#v", updated.SMTP)
	}
	if config.HTTPAddress != defaultHTTPAddress || config.InsecureDevelopmentCookies {
		t.Fatal("configuration snapshot changed after loading")
	}
}

func TestLoadConfigRejectsMalformedSecuritySettings(t *testing.T) {
	for _, key := range []string{
		"INSECURE_DEVELOPMENT_COOKIES", "ENABLE_INSECURE_DEVELOPMENT_RELAY",
		"REGISTRATION_ENABLED", "TRUSTED_PROXY_CIDRS", "PAIRING_CODE_KEY",
	} {
		t.Run(key, func(t *testing.T) {
			clearConfigEnvironment(t)
			t.Setenv("APP_ENV", "development")
			t.Setenv(key, "invalid-secret-value")
			_, err := LoadConfig()
			if err == nil || !strings.Contains(err.Error(), key) || strings.Contains(err.Error(), "invalid-secret-value") {
				t.Fatal("invalid setting must fail with its name, without its value")
			}
		})
	}
}

func TestLoadConfigProductionFailsClosed(t *testing.T) {
	cert, key, _ := transportCertificate(t)
	for _, test := range []struct {
		name      string
		env       map[string]string
		wantError string
	}{
		{name: "secure production"},
		{name: "environment defaults to production", env: map[string]string{"APP_ENV": ""}},
		{name: "missing TLS", env: map[string]string{"TLS_CERT_FILE": "", "TLS_KEY_FILE": ""}, wantError: "production requires TLS"},
		{name: "missing key", env: map[string]string{"PAIRING_CODE_KEY": ""}, wantError: "PAIRING_CODE_KEY"},
		{name: "missing service", env: map[string]string{"SERVICE_ID": ""}, wantError: "SERVICE_ID"},
		{name: "HTTP verification", env: map[string]string{"PAIRING_VERIFICATION_URI": "http://example.test"}, wantError: "HTTPS"},
		{name: "cookies", env: map[string]string{"INSECURE_DEVELOPMENT_COOKIES": "true"}, wantError: "require APP_ENV=development"},
		{name: "relay", env: map[string]string{"ENABLE_INSECURE_DEVELOPMENT_RELAY": "true"}, wantError: "require APP_ENV=development"},
		{name: "missing mail host", env: map[string]string{"SMTP_HOST": ""}, wantError: "SMTP_HOST"},
		{name: "missing mail sender", env: map[string]string{"SMTP_FROM_ADDRESS": ""}, wantError: "SMTP_FROM_ADDRESS"},
		{name: "plaintext mail", env: map[string]string{"SMTP_TLS_MODE": "none"}, wantError: "SMTP_TLS_MODE"},
		{name: "unknown mail TLS mode", env: map[string]string{"SMTP_TLS_MODE": "sometimes"}, wantError: "SMTP_TLS_MODE"},
		{name: "invalid mail port", env: map[string]string{"SMTP_PORT": "70000"}, wantError: "SMTP_PORT"},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearConfigEnvironment(t)
			for name, value := range map[string]string{
				"APP_ENV": "production", "TLS_CERT_FILE": cert, "TLS_KEY_FILE": key,
				"PAIRING_CODE_KEY": strings.Repeat("k", 32), "SERVICE_ID": "test-service",
				"PAIRING_VERIFICATION_URI": "https://example.test/pair",
				"SMTP_HOST":                "mail.example.test",
				"SMTP_FROM_ADDRESS":        "no-reply@example.test",
			} {
				t.Setenv(name, value)
			}
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			config, err := LoadConfig()
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("expected %q error, got %v", test.wantError, err)
				}
				return
			}
			if err != nil || config.TLS == nil {
				t.Fatalf("valid production configuration failed: %v", err)
			}
		})
	}
}
