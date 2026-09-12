package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// A permanent rejection is the only thing that may mark an address bad, and it must
// never stop the account from being usable.
func TestBounceFlagRecordsOnlyPermanentFailures(t *testing.T) {
	t.Run("undeliverable sets the flag", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		fixture.mailer.fail(fmt.Errorf("%w: no such mailbox", ErrMailUndeliverable))

		challenge := fixture.register(t, "person@example.com")
		if fixture.accountFor(t, challenge.Account.ID).EmailBouncedAt == nil {
			t.Fatal("a permanent rejection did not record a bounce")
		}
		// Registration still succeeded: the account exists and is recoverable.
		if challenge.Ticket == "" || challenge.Account.Status != AccountStatusPending {
			t.Fatalf("registration did not return a usable challenge: %#v", challenge)
		}
	})

	t.Run("transient failure leaves the flag alone", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		fixture.mailer.fail(fmt.Errorf("%w: connection refused", ErrMailDeliveryFailed))

		challenge := fixture.register(t, "person@example.com")
		if fixture.accountFor(t, challenge.Account.ID).EmailBouncedAt != nil {
			t.Fatal("a transient failure recorded a bounce")
		}
	})

	t.Run("a later success clears the flag", func(t *testing.T) {
		fixture := newVerificationFixture(t)
		fixture.mailer.fail(fmt.Errorf("%w: no such mailbox", ErrMailUndeliverable))
		challenge := fixture.register(t, "person@example.com")
		if fixture.accountFor(t, challenge.Account.ID).EmailBouncedAt == nil {
			t.Fatal("setup did not record a bounce")
		}

		fixture.mailer.fail(nil)
		fixture.advance(minimumResendInterval + time.Second)
		if _, err := fixture.service.ResendVerification(context.Background(), challenge.Ticket); err != nil {
			t.Fatalf("resend: %v", err)
		}
		if fixture.accountFor(t, challenge.Account.ID).EmailBouncedAt != nil {
			t.Fatal("a successful send did not clear the stale bounce")
		}
	})
}

// A bounce is diagnostic state. It must not gate anything, or a misread address
// would lock an account out of its own recovery path.
func TestBounceFlagNeverBlocksTheAccount(t *testing.T) {
	fixture := newVerificationFixture(t)
	fixture.mailer.fail(fmt.Errorf("%w: no such mailbox", ErrMailUndeliverable))
	challenge := fixture.register(t, "person@example.com")

	fixture.advance(minimumResendInterval + time.Second)
	if _, err := fixture.service.ResendVerification(context.Background(), challenge.Ticket); err != nil {
		t.Fatalf("resend for a bounced address: %v", err)
	}
	outcome, err := fixture.service.Login(context.Background(), LoginInput{
		Email:      "person@example.com",
		Password:   "correct horse battery staple",
		ClientName: "Client",
	})
	if err != nil {
		t.Fatalf("login for a bounced address: %v", err)
	}
	if outcome.Verification == nil {
		t.Fatal("a bounced pending account did not receive a challenge")
	}

	// And the code still verifies, producing a working session.
	code := fixture.mailer.lastCode()
	verified, err := fixture.service.VerifyEmail(context.Background(), VerifyEmailInput{
		Ticket: outcome.Verification.Ticket,
		Code:   code,
	})
	if err != nil {
		t.Fatalf("verify for a bounced address: %v", err)
	}
	if verified.Credentials == nil {
		t.Fatal("verification produced no session")
	}
	if _, err := fixture.service.AuthenticateAccess(
		context.Background(),
		verified.Credentials.AccessToken,
	); err != nil {
		t.Fatalf("a bounced address blocked authentication: %v", err)
	}
}

// The notice mail on the decoy path may hard-bounce. That must flag the real
// account without changing one byte of the response.
func TestDecoyBounceDoesNotChangeTheResponse(t *testing.T) {
	fixture := newVerificationFixture(t)
	existing := fixture.register(t, "person@example.com")
	fixture.mailer.fail(fmt.Errorf("%w: no such mailbox", ErrMailUndeliverable))

	decoy := fixture.register(t, "person@example.com")
	unknown := fixture.register(t, "nobody@example.com")

	if fixture.accountFor(t, existing.Account.ID).EmailBouncedAt == nil {
		t.Fatal("the bounced notice did not flag the existing account")
	}
	if decoy.Account.EmailBouncedAt != nil || unknown.Account.EmailBouncedAt != nil {
		t.Fatal("a challenge reported bounce state, which is an enumeration oracle")
	}
	if decoy.Account.Status != unknown.Account.Status ||
		(decoy.Account.EmailVerifiedAt == nil) != (unknown.Account.EmailVerifiedAt == nil) {
		t.Fatalf("decoy and fresh challenges differ: %#v vs %#v", decoy.Account, unknown.Account)
	}
}

// net/smtp sets no deadlines of its own, so a silent mail host would otherwise hang
// the request that triggered the send for as long as the socket stays open.
func TestSMTPMailerEnforcesItsDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	// Accept the connection and then say nothing at all: no SMTP greeting ever comes.
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- connection
	}()
	t.Cleanup(func() {
		select {
		case connection := <-accepted:
			connection.Close()
		default:
		}
	})

	host, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	var portNumber int
	if _, err := fmt.Sscanf(port, "%d", &portNumber); err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	mailer, err := NewSMTPMailer(SMTPMailerConfig{
		Host:        host,
		Port:        portNumber,
		FromAddress: "no-reply@example.test",
		TLSMode:     TLSModeNone,
		Timeout:     250 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create mailer: %v", err)
	}

	started := time.Now()
	err = mailer.SendVerificationCode(context.Background(), "person@example.com", "123456")
	elapsed := time.Since(started)

	if !errors.Is(err, ErrMailDeliveryFailed) {
		t.Fatalf("error = %v, want %v", err, ErrMailDeliveryFailed)
	}
	if errors.Is(err, ErrMailUndeliverable) {
		t.Fatal("an unresponsive host must not mark the address undeliverable")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the send took %v, so the deadline was not enforced", elapsed)
	}
}

func TestNewSMTPMailerValidatesConfiguration(t *testing.T) {
	valid := SMTPMailerConfig{
		Host:        "mail.example.test",
		Port:        587,
		FromAddress: "no-reply@example.test",
		TLSMode:     TLSModeStartTLS,
	}
	if _, err := NewSMTPMailer(valid); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}

	for name, mutate := range map[string]func(*SMTPMailerConfig){
		"no host":                   func(config *SMTPMailerConfig) { config.Host = " " },
		"no sender":                 func(config *SMTPMailerConfig) { config.FromAddress = "" },
		"sender without an at sign": func(config *SMTPMailerConfig) { config.FromAddress = "no-reply" },
		"header injection in sender": func(config *SMTPMailerConfig) {
			config.FromAddress = "no-reply@example.test\r\nBcc: victim@example.test"
		},
		"bad port":     func(config *SMTPMailerConfig) { config.Port = 0 },
		"unknown mode": func(config *SMTPMailerConfig) { config.TLSMode = "sometimes" },
	} {
		t.Run(name, func(t *testing.T) {
			config := valid
			mutate(&config)
			if _, err := NewSMTPMailer(config); err == nil {
				t.Fatal("invalid configuration was accepted")
			}
		})
	}
}

func TestVerificationCodeIsSixDigits(t *testing.T) {
	random := &countingRandom{}
	for range 100 {
		code, err := issueVerificationCode(random)
		if err != nil {
			t.Fatalf("issue verification code: %v", err)
		}
		if !validVerificationCode(code) {
			t.Fatalf("code %q is not six digits", code)
		}
	}
}
