package relay

import (
	"regexp"
	"strings"
	"testing"
)

// The regular expressions these checks replaced, kept as the reference they must agree with.
var (
	referenceBase64URL = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	referenceKeyID     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	referenceNonce     = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
)

func assertMatchesReference(t *testing.T, value string) {
	t.Helper()
	if got, want := validBase64URL(value, 1<<20), referenceBase64URL.MatchString(value); got != want {
		t.Fatalf("validBase64URL(%q) = %v, reference %v", value, got, want)
	}
	if got, want := exactBase64URL(value, 43), referenceKeyID.MatchString(value); got != want {
		t.Fatalf("exactBase64URL(%q, 43) = %v, reference %v", value, got, want)
	}
	if got, want := exactBase64URL(value, 22), referenceNonce.MatchString(value); got != want {
		t.Fatalf("exactBase64URL(%q, 22) = %v, reference %v", value, got, want)
	}
}

func TestBase64URLValidationMatchesTheRegularExpressions(t *testing.T) {
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	for _, value := range []string{
		"", "A", alphabet, strings.Repeat("A", 22), strings.Repeat("_", 43), strings.Repeat("-", 44),
		"AQ==", "AQ=", "a+b", "a/b", "a b", "a\nb", "a\x00b", "é", "a" + "é", "\xff", "\x80",
		strings.Repeat("A", 42) + "é", // 43 bytes of which one character is outside the alphabet
		strings.Repeat("A", 21) + "é",
	} {
		assertMatchesReference(t, value)
	}
	for character := range 256 {
		assertMatchesReference(t, string([]byte{byte(character)}))
		assertMatchesReference(t, strings.Repeat("A", 42)+string([]byte{byte(character)}))
	}
}

func TestBase64URLValidationEnforcesLength(t *testing.T) {
	if validBase64URL(strings.Repeat("A", 257), 256) || !validBase64URL(strings.Repeat("A", 256), 256) {
		t.Fatal("maximum length not enforced exactly")
	}
	if exactBase64URL(strings.Repeat("A", 42), 43) || exactBase64URL(strings.Repeat("A", 44), 43) {
		t.Fatal("exact length not enforced")
	}
}

// FuzzBase64URLValidation checks the table-driven validators against the regular expressions
// they replaced on arbitrary input. Run with: go test -fuzz FuzzBase64URLValidation ./internal/relay
func FuzzBase64URLValidation(f *testing.F) {
	for _, seed := range []string{"", "AQ", "AQ==", strings.Repeat("A", 43), "é", "\xff\xfe"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		assertMatchesReference(t, value)
	})
}
