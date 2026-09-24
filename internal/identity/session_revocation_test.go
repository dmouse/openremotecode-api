package identity

import (
	"context"
	"testing"
)

// verifiedSession registers, verifies, and returns the resulting credentials and session ID.
func verifiedSession(t *testing.T, fixture *verificationFixture, email string) (Credentials, string) {
	t.Helper()
	challenge := fixture.register(t, email)
	outcome, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
		Ticket: challenge.Ticket, Code: fixture.mailer.lastCode(),
	})
	if err != nil || outcome.Credentials == nil {
		t.Fatalf("verify email: %v", err)
	}
	principal, err := fixture.service.AuthenticateAccess(context.Background(), outcome.Credentials.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	return *outcome.Credentials, principal.SessionID
}

// Every committed session revocation is announced once, after it commits, so relay sockets
// admitted under that session close at once instead of at their next periodic check.
func TestSessionRevocationsAreAnnounced(t *testing.T) {
	ctx := context.Background()
	fixture := newVerificationFixture(t)
	first, sessionID := verifiedSession(t, fixture, "person@example.com")
	userID := first.Account.ID

	// A refresh that succeeds revokes nothing.
	rotated, err := fixture.service.Refresh(ctx, first.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixture.revocations) != 0 {
		t.Fatalf("a successful refresh announced %+v", fixture.revocations)
	}
	// Presenting the already-used token is reuse: the session is revoked and announced.
	if _, err := fixture.service.Refresh(ctx, first.RefreshToken); err == nil {
		t.Fatal("reused refresh token was accepted")
	}
	if want := (announcedRevocation{userID, sessionID, false}); len(fixture.revocations) != 1 || fixture.revocations[0] != want {
		t.Fatalf("reuse announced %+v, want %+v", fixture.revocations, want)
	}
	// The session is already revoked, so later attempts announce nothing new.
	_, _ = fixture.service.Refresh(ctx, rotated.RefreshToken)
	_ = fixture.service.Logout(ctx, rotated.RefreshToken)
	if len(fixture.revocations) != 1 {
		t.Fatalf("an already revoked session was announced again: %+v", fixture.revocations)
	}

	// Logout of a live session announces it, once.
	fixture = newVerificationFixture(t)
	credentials, sessionID := verifiedSession(t, fixture, "person@example.com")
	for range 2 {
		if err := fixture.service.Logout(ctx, credentials.RefreshToken); err != nil {
			t.Fatal(err)
		}
	}
	if want := (announcedRevocation{credentials.Account.ID, sessionID, false}); len(fixture.revocations) != 1 || fixture.revocations[0] != want {
		t.Fatalf("logout announced %+v, want %+v", fixture.revocations, want)
	}

	// A refresh for an account that is no longer active ends the session and says why, so
	// every socket of the account can be closed rather than only this session's.
	fixture = newVerificationFixture(t)
	credentials, sessionID = verifiedSession(t, fixture, "person@example.com")
	user := fixture.repository.users[credentials.Account.ID]
	user.Status = AccountStatusDisabled
	fixture.repository.users[user.ID] = user
	if _, err := fixture.service.Refresh(ctx, credentials.RefreshToken); err == nil {
		t.Fatal("a disabled account refreshed")
	}
	if want := (announcedRevocation{credentials.Account.ID, sessionID, true}); len(fixture.revocations) != 1 || fixture.revocations[0] != want {
		t.Fatalf("disabled account announced %+v, want %+v", fixture.revocations, want)
	}
}
