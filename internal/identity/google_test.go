package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	googleSubject = "108734295610293847561"
	googleToken   = "google-id-token"
)

// signInWithGoogle drives the happy path and fails the test if it does not produce
// credentials, so each test can assert on the account rather than on plumbing.
func signInWithGoogle(
	t *testing.T,
	fixture *verificationFixture,
	token string,
) Credentials {
	t.Helper()
	credentials, err := fixture.service.AuthenticateWithGoogle(context.Background(), GoogleAuthInput{
		IDToken:    token,
		ClientName: "Open Remote Code Mobile",
	})
	if err != nil {
		t.Fatalf("google sign-in: %v", err)
	}
	return credentials
}

func TestGoogleSignInCreatesVerifiedAccount(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "person@example.com",
		EmailVerified: true,
	})

	credentials := signInWithGoogle(t, fixture, googleToken)

	if credentials.Account.Status != AccountStatusActive {
		t.Fatalf("google account status = %q, want active", credentials.Account.Status)
	}
	// The whole point of the federated path: Google already proved the address, so
	// the account must never be left pending behind a code nobody asked for.
	if credentials.Account.EmailVerifiedAt == nil {
		t.Fatal("a google account must be created with its address already verified")
	}
	if messages := fixture.mailer.messages(); len(messages) != 0 {
		t.Fatalf("google sign-in sent %d mails, want none", len(messages))
	}
	if fixture.repository.auditEventCount("auth.google_account_created") != 1 {
		t.Fatal("account creation must be audited")
	}

	// The session must actually work, not merely be returned.
	if _, err := fixture.service.AuthenticateAccess(
		context.Background(),
		credentials.AccessToken,
	); err != nil {
		t.Fatalf("authenticate google session: %v", err)
	}

	link, ok := fixture.linkFor(ProviderGoogle, googleSubject)
	if !ok {
		t.Fatal("google sign-in must record a federated identity")
	}
	if link.UserID != credentials.Account.ID {
		t.Fatalf("link points at %q, want %q", link.UserID, credentials.Account.ID)
	}
}

// A federated account has no password hash at all. Login must treat that as bad
// credentials, not as a hash it failed to parse, which would surface as a 500 and
// distinguish these accounts from every other kind.
func TestPasswordLoginRejectsFederatedOnlyAccount(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "person@example.com",
		EmailVerified: true,
	})
	signInWithGoogle(t, fixture, googleToken)

	_, err := fixture.service.Login(context.Background(), LoginInput{
		Email:      "person@example.com",
		Password:   "correct horse battery staple",
		ClientName: "Test client",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("password login against a federated account = %v, want ErrInvalidCredentials", err)
	}
}

func TestGoogleSignInReturnsToTheSameAccount(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "person@example.com",
		EmailVerified: true,
	})
	first := signInWithGoogle(t, fixture, googleToken)

	fixture.advance(time.Hour)
	second := signInWithGoogle(t, fixture, googleToken)

	if first.Account.ID != second.Account.ID {
		t.Fatalf("second sign-in produced account %q, want %q", second.Account.ID, first.Account.ID)
	}
	if count := fixture.repository.userCount(); count != 1 {
		t.Fatalf("google sign-in created %d accounts, want 1", count)
	}
	if fixture.repository.auditEventCount("auth.google_signin_succeeded") != 1 {
		t.Fatal("a returning sign-in must be audited as a sign-in, not a creation")
	}
	link, _ := fixture.linkFor(ProviderGoogle, googleSubject)
	if !link.LastAuthenticatedAt.Equal(fixture.now) {
		t.Fatalf("link last authenticated at %v, want %v", link.LastAuthenticatedAt, fixture.now)
	}
}

// The subject is the join key, so a Google account that changes address keeps
// reaching the same local account, and the local address is left as the user set it.
func TestGoogleSignInFollowsSubjectNotAddress(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "person@example.com",
		EmailVerified: true,
	})
	first := signInWithGoogle(t, fixture, googleToken)

	fixture.advance(time.Hour)
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "renamed@example.com",
		EmailVerified: true,
	})
	second := signInWithGoogle(t, fixture, googleToken)

	if second.Account.ID != first.Account.ID {
		t.Fatal("a changed google address must not create a second account")
	}
	if second.Account.Email != "person@example.com" {
		t.Fatalf("account address = %q, want it left unchanged", second.Account.Email)
	}
	link, _ := fixture.linkFor(ProviderGoogle, googleSubject)
	if link.Email != "renamed@example.com" {
		t.Fatalf("link diagnostic address = %q, want the newly asserted one", link.Email)
	}
}

func TestGoogleSignInLinksVerifiedAccount(t *testing.T) {
	fixture := newVerificationFixture(t)
	challenge := fixture.register(t, "person@example.com")
	outcome, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
		Ticket: challenge.Ticket,
		Code:   fixture.mailer.lastCode(),
	})
	if err != nil {
		t.Fatalf("verify email: %v", err)
	}
	existingID := outcome.Credentials.Account.ID

	fixture.advance(time.Hour)
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "person@example.com",
		EmailVerified: true,
	})
	credentials := signInWithGoogle(t, fixture, googleToken)

	if credentials.Account.ID != existingID {
		t.Fatalf("google sign-in reached account %q, want the existing %q", credentials.Account.ID, existingID)
	}
	if count := fixture.repository.userCount(); count != 1 {
		t.Fatalf("linking created %d accounts, want 1", count)
	}
	if fixture.repository.auditEventCount("auth.google_identity_linked") != 1 {
		t.Fatal("linking an existing account must be audited")
	}
}

// The rule that motivates the whole linking design. An account created before email
// verification existed carries no proof that its owner controls the address, so a
// matching Google address is not evidence they are the same person.
func TestGoogleSignInRefusesUnverifiedLegacyAccount(t *testing.T) {
	fixture := newVerificationFixture(t)
	passwordHash, err := testPasswords{}.Hash(context.Background(), "correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	fixture.seedUser(t, User{
		Account: Account{
			ID:        "usr_legacy_account_000001",
			Email:     "legacy@example.com",
			Status:    AccountStatusActive,
			CreatedAt: fixture.now.Add(-30 * 24 * time.Hour),
		},
		NormalizedEmail: "legacy@example.com",
		PasswordHash:    &passwordHash,
	})
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "legacy@example.com",
		EmailVerified: true,
	})

	_, err = fixture.service.AuthenticateWithGoogle(context.Background(), GoogleAuthInput{
		IDToken:    googleToken,
		ClientName: "Open Remote Code Mobile",
	})
	if !errors.Is(err, ErrAccountLinkRequired) {
		t.Fatalf("google sign-in against a legacy account = %v, want ErrAccountLinkRequired", err)
	}
	if _, linked := fixture.linkFor(ProviderGoogle, googleSubject); linked {
		t.Fatal("a refused sign-in must not leave a link behind")
	}
	if count := fixture.repository.userCount(); count != 1 {
		t.Fatalf("a refused sign-in created an account: %d users", count)
	}
	if fixture.repository.auditEventCount("auth.google_link_required") != 1 {
		t.Fatal("a refused link must be audited")
	}
	// The refusal must be durable: retrying cannot wear it down into a link.
	if _, err := fixture.service.AuthenticateWithGoogle(context.Background(), GoogleAuthInput{
		IDToken:    googleToken,
		ClientName: "Open Remote Code Mobile",
	}); !errors.Is(err, ErrAccountLinkRequired) {
		t.Fatalf("retried google sign-in = %v, want ErrAccountLinkRequired", err)
	}
}

// Google's assertion is at least as strong as the code this account is waiting for,
// so it completes the verification rather than leaving the account stranded.
func TestGoogleSignInCompletesPendingVerification(t *testing.T) {
	fixture := newVerificationFixture(t)
	challenge := fixture.register(t, "person@example.com")
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "person@example.com",
		EmailVerified: true,
	})

	credentials := signInWithGoogle(t, fixture, googleToken)

	if credentials.Account.Status != AccountStatusActive {
		t.Fatalf("account status = %q, want active", credentials.Account.Status)
	}
	if credentials.Account.EmailVerifiedAt == nil {
		t.Fatal("google sign-in must complete the pending verification")
	}
	account := fixture.accountFor(t, credentials.Account.ID)
	if account.Status != AccountStatusActive || account.EmailVerifiedAt == nil {
		t.Fatalf("stored account not activated: %+v", account)
	}
	// The outstanding challenge is consumed, so the mailed code cannot be replayed.
	if _, outstanding := fixture.repository.verificationFor(credentials.Account.ID); outstanding {
		t.Fatal("activating through google must consume the outstanding challenge")
	}
	if _, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
		Ticket: challenge.Ticket,
		Code:   fixture.mailer.lastCode(),
	}); !errors.Is(err, ErrInvalidVerificationCode) {
		t.Fatal("the superseded verification ticket must no longer work")
	}
	// The password chosen at registration never proved the address, so it is discarded:
	// otherwise whoever pre-registered the address could sign in to the owner's account.
	if fixture.repository.users[credentials.Account.ID].HasPassword() {
		t.Fatal("google activation must discard the pending account's password")
	}
	if _, err := fixture.service.Login(context.Background(), LoginInput{
		Email:      "person@example.com",
		Password:   "correct horse battery staple",
		ClientName: "Test client",
	}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("password login after google activation = %v, want ErrInvalidCredentials", err)
	}
}

// A disabled account must answer identically on both routes, so the pair cannot be
// played against each other to learn an account's state.
func TestGoogleSignInHidesDisabledAccount(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.seedUser(t, User{
		Account: Account{
			ID:        "usr_disabled_account_0001",
			Email:     "disabled@example.com",
			Status:    AccountStatusDisabled,
			CreatedAt: fixture.now,
		},
		NormalizedEmail: "disabled@example.com",
	})
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "disabled@example.com",
		EmailVerified: true,
	})

	_, err := fixture.service.AuthenticateWithGoogle(context.Background(), GoogleAuthInput{
		IDToken:    googleToken,
		ClientName: "Open Remote Code Mobile",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("google sign-in against a disabled account = %v, want ErrInvalidCredentials", err)
	}
	if _, linked := fixture.linkFor(ProviderGoogle, googleSubject); linked {
		t.Fatal("a disabled account must not be linked")
	}
}

func TestGoogleSignInRejectsUnverifiedAssertion(t *testing.T) {
	fixture := newVerificationFixture(t)
	// A verifier is contracted to reject this itself. The service checks again
	// because the entire linking rule rests on this one claim.
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "person@example.com",
		EmailVerified: false,
	})

	_, err := fixture.service.AuthenticateWithGoogle(context.Background(), GoogleAuthInput{
		IDToken:    googleToken,
		ClientName: "Open Remote Code Mobile",
	})
	if !errors.Is(err, ErrInvalidGoogleToken) {
		t.Fatalf("unverified assertion = %v, want ErrInvalidGoogleToken", err)
	}
	if count := fixture.repository.userCount(); count != 0 {
		t.Fatalf("an unverified assertion created %d accounts", count)
	}
}

func TestGoogleSignInCollapsesVerifierFailures(t *testing.T) {
	fixture := newVerificationFixture(t)
	// A verifier that leaks a more specific reason must not widen what the caller
	// learns; every failure reaches the transport as the same error.
	fixture.google.fail(errors.New("audience provided does not match aud claim"))

	_, err := fixture.service.AuthenticateWithGoogle(context.Background(), GoogleAuthInput{
		IDToken:    googleToken,
		ClientName: "Open Remote Code Mobile",
	})
	if !errors.Is(err, ErrInvalidGoogleToken) {
		t.Fatalf("verifier failure = %v, want ErrInvalidGoogleToken", err)
	}
}

func TestGoogleSignInReportsUnconfiguredDeployment(t *testing.T) {
	fixture := newFixtureWithoutGoogle(t)

	_, err := fixture.service.AuthenticateWithGoogle(context.Background(), GoogleAuthInput{
		IDToken:    googleToken,
		ClientName: "Open Remote Code Mobile",
	})
	if !errors.Is(err, ErrGoogleUnavailable) {
		t.Fatalf("unconfigured deployment = %v, want ErrGoogleUnavailable", err)
	}
}

func TestGoogleSignInValidatesClientName(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "person@example.com",
		EmailVerified: true,
	})

	for name, clientName := range map[string]string{
		"empty":       "",
		"whitespace":  "   ",
		"control":     "Mobile\x00client",
		"over length": string(make([]rune, 65)),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fixture.service.AuthenticateWithGoogle(context.Background(), GoogleAuthInput{
				IDToken:    googleToken,
				ClientName: clientName,
			})
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("client name %q = %v, want ErrInvalidInput", clientName, err)
			}
		})
	}
	if count := fixture.repository.userCount(); count != 0 {
		t.Fatalf("a rejected client name created %d accounts", count)
	}
}

// An address Google asserts but that this service would refuse to store must be
// rejected before it reaches the database, and must not be mistaken for a valid one.
func TestGoogleSignInRejectsMalformedAssertedAddress(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "not-an-address",
		EmailVerified: true,
	})

	_, err := fixture.service.AuthenticateWithGoogle(context.Background(), GoogleAuthInput{
		IDToken:    googleToken,
		ClientName: "Open Remote Code Mobile",
	})
	if !errors.Is(err, ErrInvalidGoogleToken) {
		t.Fatalf("malformed asserted address = %v, want ErrInvalidGoogleToken", err)
	}
	if count := fixture.repository.userCount(); count != 0 {
		t.Fatalf("a malformed address created %d accounts", count)
	}
}

// One local account holds at most one identity per provider. Without that, a second
// Google account could attach to an account it never proved anything about and then
// sign in as it.
func TestGoogleSignInRefusesSecondIdentityForOneAccount(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.google.accept(googleToken, GoogleIdentity{
		Subject:       googleSubject,
		Email:         "person@example.com",
		EmailVerified: true,
	})
	credentials := signInWithGoogle(t, fixture, googleToken)

	// A different Google account that has since taken over the same address.
	fixture.google.accept("second-token", GoogleIdentity{
		Subject:       "209845736102938475612",
		Email:         "person@example.com",
		EmailVerified: true,
	})
	_, err := fixture.service.AuthenticateWithGoogle(context.Background(), GoogleAuthInput{
		IDToken:    "second-token",
		ClientName: "Open Remote Code Mobile",
	})
	// Reported as its own refusal rather than surfacing as a constraint violation:
	// this is reachable without any concurrency, so it must not be a 500.
	if !errors.Is(err, ErrIdentityAlreadyLinked) {
		t.Fatalf("second google identity = %v, want ErrIdentityAlreadyLinked", err)
	}
	link, _ := fixture.linkFor(ProviderGoogle, googleSubject)
	if link.UserID != credentials.Account.ID {
		t.Fatal("the original link must survive the refused attempt")
	}
	if _, linked := fixture.linkFor(ProviderGoogle, "209845736102938475612"); linked {
		t.Fatal("the refused identity must not be recorded")
	}
	if fixture.repository.auditEventCount("auth.google_identity_conflict") != 1 {
		t.Fatal("the refusal must be audited, and the audit must survive the commit")
	}
}
