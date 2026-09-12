package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRegisterCreatesPendingAccountAndMailsCode(t *testing.T) {
	fixture := newVerificationFixture(t)
	challenge := fixture.register(t, "person@example.com")

	if challenge.Account.Status != AccountStatusPending {
		t.Fatalf("account status = %q, want %q", challenge.Account.Status, AccountStatusPending)
	}
	if !validToken(challenge.Ticket, "vft_") {
		t.Fatalf("verification ticket is malformed: %q", challenge.Ticket)
	}
	if challenge.Account.EmailVerifiedAt != nil || challenge.Account.EmailBouncedAt != nil {
		t.Fatal("a new account is neither verified nor bounced")
	}
	messages := fixture.mailer.messages()
	if len(messages) != 1 || messages[0].to != "person@example.com" || !validVerificationCode(messages[0].code) {
		t.Fatalf("expected one six-digit code mailed to the address, got %#v", messages)
	}
	// No session may exist yet: a pending account must not be able to authenticate.
	if len(fixture.repository.sessions) != 0 {
		t.Fatalf("registration created %d sessions", len(fixture.repository.sessions))
	}
}

// The decoy path is the anti-enumeration control. If any observable part of the
// response differs from a fresh registration, the control is gone.
func TestRegisterAnswersExistingAddressIndistinguishably(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.register(t, "person@example.com")
	fixture.mailer.reset()

	fresh := fixture.register(t, "other@example.com")
	fixture.mailer.reset()
	usersBefore := fixture.repository.userCount()

	decoy := fixture.register(t, "person@example.com")

	if fixture.repository.userCount() != usersBefore {
		t.Fatal("a duplicate registration created an account")
	}
	if decoy.Account.Status != fresh.Account.Status {
		t.Fatalf("decoy status = %q, fresh status = %q", decoy.Account.Status, fresh.Account.Status)
	}
	if !validToken(decoy.Ticket, "vft_") {
		t.Fatalf("decoy ticket is malformed: %q", decoy.Ticket)
	}
	if decoy.Account.EmailVerifiedAt != nil || decoy.Account.EmailBouncedAt != nil {
		t.Fatal("decoy account reports state of the real account")
	}
	if decoy.Account.ID == "" || decoy.Account.ID == fresh.Account.ID {
		t.Fatalf("decoy account id is not a plausible distinct identifier: %q", decoy.Account.ID)
	}
	// The owner of the address learns about the attempt by mail, not the caller.
	messages := fixture.mailer.messages()
	if len(messages) != 1 || messages[0].to != "person@example.com" || messages[0].code != "" {
		t.Fatalf("expected one registration notice and no code, got %#v", messages)
	}
	if fixture.repository.auditEventCount("auth.registration_conflict") != 1 {
		t.Fatal("the attempt was not audited")
	}

	// A code submitted against the decoy fails the same way a wrong code does.
	_, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
		Ticket: decoy.Ticket,
		Code:   "000000",
	})
	if !errors.Is(err, ErrInvalidVerificationCode) {
		t.Fatalf("decoy verification error = %v, want %v", err, ErrInvalidVerificationCode)
	}
}

func TestVerifyEmailActivatesAccountAndIssuesSession(t *testing.T) {
	fixture := newVerificationFixture(t)
	challenge := fixture.register(t, "person@example.com")
	code := fixture.mailer.lastCode()

	outcome, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
		Ticket: challenge.Ticket,
		Code:   code,
	})
	if err != nil {
		t.Fatalf("verify email: %v", err)
	}
	if outcome.Credentials == nil {
		t.Fatal("verification returned no credentials")
	}
	credentials := *outcome.Credentials
	if credentials.Account.Status != AccountStatusActive || credentials.Account.EmailVerifiedAt == nil {
		t.Fatalf("verified account = %#v", credentials.Account)
	}
	if !validToken(credentials.AccessToken, "ora_") || !validToken(credentials.RefreshToken, "orr_") {
		t.Fatal("verification did not issue a usable session")
	}
	if _, outstanding := fixture.repository.verificationFor(challenge.Account.ID); outstanding {
		t.Fatal("the verification record survived a successful verification")
	}
	// The session is real: it authenticates.
	principal, err := fixture.service.AuthenticateAccess(context.Background(), credentials.AccessToken)
	if err != nil {
		t.Fatalf("authenticate the new session: %v", err)
	}
	if principal.Account.ID != challenge.Account.ID {
		t.Fatalf("session belongs to %q, want %q", principal.Account.ID, challenge.Account.ID)
	}

	// The ticket is spent, so replaying it cannot mint a second session.
	if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
		Ticket: challenge.Ticket,
		Code:   code,
	}); !errors.Is(err, ErrInvalidVerificationCode) {
		t.Fatalf("replayed ticket error = %v, want %v", err, ErrInvalidVerificationCode)
	}
}

// The attempt counter is incremented by returning nil from the transaction closure.
// Returning an error there would roll the increment back and make guessing free, so
// this asserts the increment is actually durable.
func TestWrongVerificationCodeIncrementIsDurable(t *testing.T) {
	fixture := newVerificationFixture(t)
	challenge := fixture.register(t, "person@example.com")
	code := fixture.mailer.lastCode()

	for attempt := 1; attempt <= 3; attempt++ {
		_, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
			Ticket: challenge.Ticket,
			Code:   wrongCode(code),
		})
		if !errors.Is(err, ErrInvalidVerificationCode) {
			t.Fatalf("attempt %d error = %v, want %v", attempt, err, ErrInvalidVerificationCode)
		}
		record, ok := fixture.repository.verificationFor(challenge.Account.ID)
		if !ok {
			t.Fatalf("attempt %d removed the verification record", attempt)
		}
		if record.Attempts != attempt {
			t.Fatalf("after attempt %d, attempts = %d", attempt, record.Attempts)
		}
	}

	// The right code still works while attempts remain.
	if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
		Ticket: challenge.Ticket,
		Code:   code,
	}); err != nil {
		t.Fatalf("verify after wrong attempts: %v", err)
	}
}

func TestVerificationRejectsExhaustedAndExpiredChallenges(t *testing.T) {
	t.Run("attempts exhausted", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		challenge := fixture.register(t, "person@example.com")
		code := fixture.mailer.lastCode()

		for range maxVerificationAttempts {
			if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
				Ticket: challenge.Ticket,
				Code:   wrongCode(code),
			}); !errors.Is(err, ErrInvalidVerificationCode) {
				t.Fatalf("unexpected error: %v", err)
			}
		}
		// The cap holds even against the correct code.
		if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
			Ticket: challenge.Ticket,
			Code:   code,
		}); !errors.Is(err, ErrInvalidVerificationCode) {
			t.Fatalf("exhausted challenge accepted the code: %v", err)
		}
	})

	t.Run("expired", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		challenge := fixture.register(t, "person@example.com")
		code := fixture.mailer.lastCode()
		fixture.advance(verificationCodeLifetime + time.Second)

		if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
			Ticket: challenge.Ticket,
			Code:   code,
		}); !errors.Is(err, ErrInvalidVerificationCode) {
			t.Fatalf("expired challenge accepted the code: %v", err)
		}
	})

	t.Run("malformed input", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		challenge := fixture.register(t, "person@example.com")
		for _, code := range []string{"", "12345", "1234567", "abcdef", "12 456"} {
			if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
				Ticket: challenge.Ticket,
				Code:   code,
			}); !errors.Is(err, ErrInvalidVerificationCode) {
				t.Fatalf("code %q error = %v", code, err)
			}
		}
	})
}

// Signing in to a pending account must not mail a new code on every attempt.
func TestLoginAgainstPendingAccountRespectsResendCooldown(t *testing.T) {
	fixture := newVerificationFixture(t)
	challenge := fixture.register(t, "person@example.com")
	originalCode := fixture.mailer.lastCode()
	fixture.mailer.reset()

	fixture.advance(minimumResendInterval / 2)
	outcome, err := fixture.service.Login(context.Background(), LoginInput{
		Email:      "person@example.com",
		Password:   "correct horse battery staple",
		ClientName: "Second client",
	})
	if err != nil {
		t.Fatalf("login against pending account: %v", err)
	}
	if outcome.Credentials != nil || outcome.Verification == nil {
		t.Fatal("a pending account must not receive credentials")
	}
	reissued := *outcome.Verification
	if reissued.Ticket == challenge.Ticket {
		t.Fatal("the verification ticket did not rotate")
	}
	if messages := fixture.mailer.messages(); len(messages) != 0 {
		t.Fatalf("login within the cooldown sent mail: %#v", messages)
	}
	// The code the user already holds still works, through the new ticket.
	if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
		Ticket: reissued.Ticket,
		Code:   originalCode,
	}); err != nil {
		t.Fatalf("the original code stopped working: %v", err)
	}

	// Past the cooldown, a fresh sign-in rotates the code and mails it.
	second := newVerificationFixture(t)
	second.register(t, "person@example.com")
	firstCode := second.mailer.lastCode()
	second.mailer.reset()
	second.advance(minimumResendInterval + time.Second)
	if _, err := second.service.Login(context.Background(), LoginInput{
		Email:      "person@example.com",
		Password:   "correct horse battery staple",
		ClientName: "Second client",
	}); err != nil {
		t.Fatalf("login past the cooldown: %v", err)
	}
	messages := second.mailer.messages()
	if len(messages) != 1 || messages[0].code == "" {
		t.Fatalf("expected one new code past the cooldown, got %#v", messages)
	}
	if messages[0].code == firstCode {
		t.Fatal("the code did not rotate past the cooldown")
	}
}

// Keeping the attempt count with a reused code stops repeated sign-ins from
// resetting the cap and turning it into an unbounded guessing budget.
func TestReusedCodeKeepsItsAttemptCount(t *testing.T) {
	fixture := newVerificationFixture(t)
	challenge := fixture.register(t, "person@example.com")
	code := fixture.mailer.lastCode()

	if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
		Ticket: challenge.Ticket,
		Code:   wrongCode(code),
	}); !errors.Is(err, ErrInvalidVerificationCode) {
		t.Fatalf("unexpected error: %v", err)
	}

	fixture.advance(minimumResendInterval / 2)
	if _, err := fixture.service.Login(context.Background(), LoginInput{
		Email:      "person@example.com",
		Password:   "correct horse battery staple",
		ClientName: "Second client",
	}); err != nil {
		t.Fatalf("login against pending account: %v", err)
	}

	record, ok := fixture.repository.verificationFor(challenge.Account.ID)
	if !ok {
		t.Fatal("the verification record disappeared")
	}
	if record.Attempts != 1 {
		t.Fatalf("attempts = %d after reissuing the same code, want 1", record.Attempts)
	}
}

func TestResendVerification(t *testing.T) {
	t.Run("rotates and mails past the cooldown", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		challenge := fixture.register(t, "person@example.com")
		originalCode := fixture.mailer.lastCode()
		fixture.mailer.reset()
		fixture.advance(minimumResendInterval + time.Second)

		rotated, err := fixture.service.ResendVerification(context.Background(), challenge.Ticket)
		if err != nil {
			t.Fatalf("resend: %v", err)
		}
		if rotated.Ticket == challenge.Ticket {
			t.Fatal("resend did not rotate the ticket")
		}
		messages := fixture.mailer.messages()
		if len(messages) != 1 || messages[0].code == originalCode {
			t.Fatalf("resend did not mail a new code: %#v", messages)
		}
		// The superseded ticket and code are both dead.
		if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
			Ticket: challenge.Ticket,
			Code:   originalCode,
		}); !errors.Is(err, ErrInvalidVerificationCode) {
			t.Fatalf("the superseded ticket still works: %v", err)
		}
		if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
			Ticket: rotated.Ticket,
			Code:   messages[0].code,
		}); err != nil {
			t.Fatalf("the rotated challenge does not work: %v", err)
		}
	})

	t.Run("enforces the cooldown", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		challenge := fixture.register(t, "person@example.com")
		fixture.mailer.reset()
		fixture.advance(minimumResendInterval - time.Second)

		_, err := fixture.service.ResendVerification(context.Background(), challenge.Ticket)
		if !errors.Is(err, ErrVerificationThrottled) {
			t.Fatalf("resend error = %v, want %v", err, ErrVerificationThrottled)
		}
		if messages := fixture.mailer.messages(); len(messages) != 0 {
			t.Fatalf("throttled resend sent mail: %#v", messages)
		}
	})

	t.Run("an already-verified account looks like an unknown ticket", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		challenge := fixture.register(t, "person@example.com")
		code := fixture.mailer.lastCode()
		if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
			Ticket: challenge.Ticket,
			Code:   code,
		}); err != nil {
			t.Fatalf("verify: %v", err)
		}
		fixture.advance(minimumResendInterval + time.Second)

		_, verifiedErr := fixture.service.ResendVerification(context.Background(), challenge.Ticket)
		unknownTicket, err := issueToken(&countingRandom{}, "vft_")
		if err != nil {
			t.Fatalf("issue ticket: %v", err)
		}
		_, unknownErr := fixture.service.ResendVerification(context.Background(), unknownTicket)
		if !errors.Is(verifiedErr, ErrInvalidVerificationCode) || !errors.Is(unknownErr, ErrInvalidVerificationCode) {
			t.Fatalf("errors differ: verified = %v, unknown = %v", verifiedErr, unknownErr)
		}
	})
}

// Every account that exists today is active with a NULL email_verified_at. If
// anything gated access on verification rather than status, this release would lock
// every one of them out.
func TestExistingActiveAccountWithoutVerificationStillSignsIn(t *testing.T) {
	fixture := newVerificationFixture(t)
	passwordHash, err := testPasswords{}.Hash(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	legacy := User{
		Account: Account{
			ID:        "usr_legacy_account_000001",
			Email:     "legacy@example.com",
			Status:    AccountStatusActive,
			CreatedAt: fixture.now.Add(-30 * 24 * time.Hour),
		},
		NormalizedEmail: "legacy@example.com",
		PasswordHash:    &passwordHash,
	}
	if err := fixture.repository.WithinTransaction(
		context.Background(),
		func(store TransactionStore) error { return store.CreateUser(context.Background(), legacy) },
	); err != nil {
		t.Fatalf("seed legacy account: %v", err)
	}

	outcome, err := fixture.service.Login(context.Background(), LoginInput{
		Email:      "legacy@example.com",
		Password:   "correct horse battery staple",
		ClientName: "Existing install",
	})
	if err != nil {
		t.Fatalf("legacy login: %v", err)
	}
	if outcome.Credentials == nil {
		t.Fatal("an existing active account must still receive credentials")
	}
	if outcome.Credentials.Account.EmailVerifiedAt != nil {
		t.Fatal("logging in must not retroactively mark the address verified")
	}
	if _, err := fixture.service.AuthenticateAccess(
		context.Background(),
		outcome.Credentials.AccessToken,
	); err != nil {
		t.Fatalf("authenticate legacy session: %v", err)
	}
}

func TestLoginKeepsOtherStatusesIndistinguishable(t *testing.T) {
	fixture := newVerificationFixture(t)
	passwordHash, err := testPasswords{}.Hash(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := fixture.repository.WithinTransaction(
		context.Background(),
		func(store TransactionStore) error {
			return store.CreateUser(context.Background(), User{
				Account: Account{
					ID:        "usr_disabled_account_0001",
					Email:     "disabled@example.com",
					Status:    AccountStatusDisabled,
					CreatedAt: fixture.now,
				},
				NormalizedEmail: "disabled@example.com",
				PasswordHash:    &passwordHash,
			})
		},
	); err != nil {
		t.Fatalf("seed disabled account: %v", err)
	}

	_, disabledErr := fixture.service.Login(context.Background(), LoginInput{
		Email:      "disabled@example.com",
		Password:   "correct horse battery staple",
		ClientName: "Client",
	})
	_, unknownErr := fixture.service.Login(context.Background(), LoginInput{
		Email:      "nobody@example.com",
		Password:   "correct horse battery staple",
		ClientName: "Client",
	})
	if !errors.Is(disabledErr, ErrInvalidCredentials) || !errors.Is(unknownErr, ErrInvalidCredentials) {
		t.Fatalf("errors differ: disabled = %v, unknown = %v", disabledErr, unknownErr)
	}
	if messages := fixture.mailer.messages(); len(messages) != 0 {
		t.Fatalf("a failed login sent mail: %#v", messages)
	}
}

func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}
