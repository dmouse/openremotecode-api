package identity

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestPasswordHasherRoundTrip(t *testing.T) {
	hasher := newPasswordHasher(1, 8*1024, 1, 16, 32, bytes.NewReader(make([]byte, 16)), 1)
	encodedHash, err := hasher.Hash(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if !strings.HasPrefix(encodedHash, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("unexpected encoded hash %q", encodedHash)
	}

	verified, err := hasher.Verify(context.Background(), "correct horse battery staple", encodedHash)
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if !verified {
		t.Fatal("expected password to verify")
	}
	verified, err = hasher.Verify(context.Background(), "wrong password", encodedHash)
	if err != nil {
		t.Fatalf("verify wrong password: %v", err)
	}
	if verified {
		t.Fatal("expected wrong password not to verify")
	}
}

func TestPasswordHasherRejectsUnsafeStoredParameters(t *testing.T) {
	hasher := NewPasswordHasher()
	unsafeHash := "$argon2id$v=19$m=2097152,t=1,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAA"
	if _, err := hasher.Verify(context.Background(), "password", unsafeHash); err == nil {
		t.Fatal("expected unsafe memory parameter to be rejected")
	}
}

func TestNormalizeEmail(t *testing.T) {
	email, normalized, err := normalizeEmail("  Person@Example.COM ")
	if err != nil {
		t.Fatalf("normalize email: %v", err)
	}
	if email != "Person@Example.COM" || normalized != "person@example.com" {
		t.Fatalf("unexpected email values %q and %q", email, normalized)
	}
	if _, _, err := normalizeEmail("Person <person@example.com>"); err == nil {
		t.Fatal("expected display-name address to be rejected")
	}
}

func TestRegistrationPasswordCountsCharacters(t *testing.T) {
	if validRegistrationPassword("🙂🙂🙂") {
		t.Fatal("expected three multibyte characters not to satisfy the minimum")
	}
	if !validRegistrationPassword("🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂🙂") {
		t.Fatal("expected twelve multibyte characters to satisfy the minimum")
	}
	if !validRegistrationPassword(strings.Repeat("🙂", maximumPasswordLength)) {
		t.Fatal("expected the documented multibyte maximum to be accepted")
	}
	if validRegistrationPassword(strings.Repeat("🙂", maximumPasswordLength+1)) {
		t.Fatal("expected password above the character maximum to be rejected")
	}
}
