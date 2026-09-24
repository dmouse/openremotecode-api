package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeDisposableDetector flags a fixed domain and records what it was asked about.
type fakeDisposableDetector struct {
	domain string
	asked  []string
}

func (detector *fakeDisposableDetector) IsDisposable(email string) bool {
	detector.asked = append(detector.asked, email)
	return strings.HasSuffix(email, "@"+detector.domain)
}

func registerInput(email string) RegisterInput {
	return RegisterInput{Email: email, Password: "correct horse battery staple", ClientName: "Test client"}
}

func TestRegisterRejectsDisposableAddressBeforeAnyWork(t *testing.T) {
	fixture := newFixtureWithoutGoogle(t)
	detector := &fakeDisposableDetector{domain: "burner.test"}
	fixture.service.disposableEmails = detector

	_, err := fixture.service.Register(context.Background(), registerInput("Person@burner.test"))

	if !errors.Is(err, ErrDisposableEmail) {
		t.Fatalf("error = %v, want ErrDisposableEmail", err)
	}
	if fixture.repository.userCount() != 0 {
		t.Fatal("a rejected registration created an account")
	}
	if len(fixture.mailer.messages()) != 0 {
		t.Fatal("a rejected registration sent mail")
	}
	// The detector sees the address as submitted, so its own normalization applies.
	if len(detector.asked) != 1 || detector.asked[0] != "Person@burner.test" {
		t.Fatalf("detector was asked %v", detector.asked)
	}
}

func TestRegisterAcceptsAddressesTheDetectorAllows(t *testing.T) {
	fixture := newFixtureWithoutGoogle(t)
	fixture.service.disposableEmails = &fakeDisposableDetector{domain: "burner.test"}

	fixture.register(t, "person@example.com")

	if fixture.repository.userCount() != 1 {
		t.Fatalf("userCount = %d, want 1", fixture.repository.userCount())
	}
}

// Login and resend must keep working for an account whose domain was listed after it
// registered: the filter gates new accounts, never existing ones.
func TestDisposableFilterDoesNotLockOutExistingAccounts(t *testing.T) {
	fixture := newFixtureWithoutGoogle(t)
	fixture.register(t, "person@burner.test")
	fixture.service.disposableEmails = &fakeDisposableDetector{domain: "burner.test"}

	outcome, err := fixture.service.Login(context.Background(), LoginInput{
		Email:      "person@burner.test",
		Password:   "correct horse battery staple",
		ClientName: "Test client",
	})

	if err != nil {
		t.Fatalf("login of an existing account: %v", err)
	}
	if outcome.Verification == nil {
		t.Fatal("login of a pending account should return its verification challenge")
	}
}

// The verdict must not depend on whether the address is already registered, or the
// error becomes an account-existence oracle that the decoy response exists to prevent.
func TestDisposableVerdictDoesNotDependOnAccountState(t *testing.T) {
	fixture := newFixtureWithoutGoogle(t)
	fixture.register(t, "person@burner.test")
	fixture.service.disposableEmails = &fakeDisposableDetector{domain: "burner.test"}

	_, existing := fixture.service.Register(context.Background(), registerInput("person@burner.test"))
	_, fresh := fixture.service.Register(context.Background(), registerInput("other@burner.test"))

	if !errors.Is(existing, ErrDisposableEmail) || !errors.Is(fresh, ErrDisposableEmail) {
		t.Fatalf("existing = %v, fresh = %v; both must be ErrDisposableEmail", existing, fresh)
	}
}
