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
		"MAILGUN_API_KEY", "MAILGUN_DOMAIN", "MAILGUN_FROM_ADDRESS", "MAILGUN_REGION",
		"DISPOSABLE_EMAIL_FILTER", "DISPOSABLE_EMAIL_CACHE_DIR",
		"DISPOSABLE_EMAIL_DATA_URL", "DISPOSABLE_EMAIL_ALLOW_DOMAINS",
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
	t.Setenv("MAILGUN_API_KEY", " key-123 ")
	t.Setenv("MAILGUN_DOMAIN", " mg.example.test ")
	t.Setenv("MAILGUN_FROM_ADDRESS", " no-reply@example.test ")
	t.Setenv("MAILGUN_REGION", " eu ")
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
	if updated.Mailgun.APIKey != " key-123 " || updated.Mailgun.Domain != "mg.example.test" ||
		updated.Mailgun.FromAddress != "no-reply@example.test" || updated.Mailgun.Region != "eu" {
		t.Fatalf("mailgun overrides were not applied: %#v", updated.Mailgun)
	}
	if config.HTTPAddress != defaultHTTPAddress || config.InsecureDevelopmentCookies {
		t.Fatal("configuration snapshot changed after loading")
	}
}

func TestLoadConfigRejectsMalformedSecuritySettings(t *testing.T) {
	for _, key := range []string{
		"INSECURE_DEVELOPMENT_COOKIES", "ENABLE_INSECURE_DEVELOPMENT_RELAY",
		"REGISTRATION_ENABLED", "TRUSTED_PROXY_CIDRS", "PAIRING_CODE_KEY",
		"DISPOSABLE_EMAIL_FILTER",
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
		{name: "mailgun alone satisfies production", env: map[string]string{
			"SMTP_HOST": "", "SMTP_FROM_ADDRESS": "",
			"MAILGUN_API_KEY": "key", "MAILGUN_DOMAIN": "mg.example.test",
			"MAILGUN_FROM_ADDRESS": "no-reply@example.test",
		}},
		{name: "mailgun partial configuration", env: map[string]string{"MAILGUN_API_KEY": "key"}, wantError: "MAILGUN_DOMAIN"},
		{name: "mailgun unknown region", env: map[string]string{
			"MAILGUN_API_KEY": "key", "MAILGUN_DOMAIN": "mg.example.test",
			"MAILGUN_FROM_ADDRESS": "no-reply@example.test", "MAILGUN_REGION": "asia",
		}, wantError: "MAILGUN_REGION"},
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

// The upstream list contains example.com, which every development and test address
// uses, so the filter must not be on unless someone asks for it there.
func TestLoadConfigDisposableEmailFilterDefaultsByEnvironment(t *testing.T) {
	cert, key, _ := transportCertificate(t)
	for _, test := range []struct {
		name string
		env  map[string]string
		want bool
	}{
		{name: "development default", env: map[string]string{"APP_ENV": "development"}, want: false},
		{name: "development opt-in", env: map[string]string{"APP_ENV": "development", "DISPOSABLE_EMAIL_FILTER": "true"}, want: true},
		{name: "production default", want: true},
		{name: "production opt-out", env: map[string]string{"DISPOSABLE_EMAIL_FILTER": "false"}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			clearConfigEnvironment(t)
			setProductionEnvironment(t, cert, key)
			for name, value := range test.env {
				t.Setenv(name, value)
			}
			config, err := LoadConfig()
			if err != nil {
				t.Fatal(err)
			}
			if config.DisposableEmail.Enabled != test.want {
				t.Fatalf("Enabled = %v, want %v", config.DisposableEmail.Enabled, test.want)
			}
		})
	}
}

func TestLoadConfigDisposableEmailSettings(t *testing.T) {
	clearConfigEnvironment(t)
	t.Setenv("APP_ENV", "development")
	t.Setenv("DISPOSABLE_EMAIL_CACHE_DIR", " /var/cache/disposable-email ")
	t.Setenv("DISPOSABLE_EMAIL_DATA_URL", " https://lists.example.test/data.bin ")
	t.Setenv("DISPOSABLE_EMAIL_ALLOW_DOMAINS", " corp.example.test, ,partner.example.test,")

	config, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	got := config.DisposableEmail
	if got.CacheDir != "/var/cache/disposable-email" || got.DataURL != "https://lists.example.test/data.bin" ||
		len(got.AllowDomains) != 2 || got.AllowDomains[0] != "corp.example.test" || got.AllowDomains[1] != "partner.example.test" {
		t.Fatalf("unexpected disposable email settings: %#v", got)
	}
}

func TestLoadConfigRejectsUnsafeDisposableEmailDataURL(t *testing.T) {
	for _, test := range []struct {
		name        string
		development bool
		value       string
		wantValid   bool
	}{
		{name: "https", development: false, value: "https://lists.example.test/data.bin", wantValid: true},
		{name: "plaintext in production", development: false, value: "http://lists.example.test/data.bin"},
		{name: "plaintext in development", development: true, value: "http://127.0.0.1:9000/data.bin", wantValid: true},
		{name: "credentials", development: true, value: "https://user:secret@lists.example.test/data.bin"},
		{name: "no host", development: true, value: "https:///data.bin"},
		{name: "file scheme", development: true, value: "file:///etc/passwd"},
		{name: "relative", development: true, value: "/data.bin"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := validDisposableEmailDataURL(test.value, test.development); got != test.wantValid {
				t.Fatalf("validDisposableEmailDataURL(%q, %v) = %v, want %v", test.value, test.development, got, test.wantValid)
			}
		})
	}

	clearConfigEnvironment(t)
	t.Setenv("APP_ENV", "development")
	t.Setenv("DISPOSABLE_EMAIL_DATA_URL", "https://user:secret@lists.example.test/data.bin")
	_, err := LoadConfig()
	if err == nil || !strings.Contains(err.Error(), "DISPOSABLE_EMAIL_DATA_URL") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("expected a named error that does not echo the URL, got %v", err)
	}
}

// setProductionEnvironment sets the minimum a production LoadConfig accepts. A test
// then overrides or unsets exactly the settings it is about.
func setProductionEnvironment(t *testing.T, cert, key string) {
	t.Helper()
	for name, value := range map[string]string{
		"APP_ENV": "production", "TLS_CERT_FILE": cert, "TLS_KEY_FILE": key,
		"PAIRING_CODE_KEY": strings.Repeat("k", 32), "SERVICE_ID": "test-service",
		"PAIRING_VERIFICATION_URI": "https://example.test/pair",
		"SMTP_HOST":                "mail.example.test",
		"SMTP_FROM_ADDRESS":        "no-reply@example.test",
	} {
		t.Setenv(name, value)
	}
}
