package identity

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultAccessLifetime    = 15 * time.Minute
	defaultRefreshLifetime   = 30 * 24 * time.Hour
	minimumPasswordLength    = 12
	maximumPasswordLength    = 128
	maximumPasswordBytes     = maximumPasswordLength * utf8.UTFMax
	maximumEmailLength       = 254
	maximumClientNameLength  = 64
	verificationCodeLength   = 6
	verificationCodeLifetime = 10 * time.Minute
	maxVerificationAttempts  = 8
	minimumResendInterval    = 30 * time.Second
)

type ServiceOptions struct {
	Now             func() time.Time
	Random          io.Reader
	AccessLifetime  time.Duration
	RefreshLifetime time.Duration
	// GoogleVerifier is nil in a deployment that has not configured Google sign-in.
	// AuthenticateWithGoogle then answers ErrGoogleUnavailable rather than pretending
	// every assertion is invalid, which would be indistinguishable from a bug.
	GoogleVerifier GoogleVerifier
	// DisposableEmails, when set, makes Register refuse throwaway-mail domains. It is
	// deliberately not applied to sign-in or to Google accounts: an existing account
	// must always be able to authenticate, and Google has already vouched for the
	// address it asserts.
	DisposableEmails DisposableEmailDetector
	// OnSessionRevoked is told about each committed session revocation, so relay sockets
	// admitted under that session can be closed at once. accountInactive is true when the
	// session ended because the account is no longer active.
	OnSessionRevoked func(userID, sessionID string, accountInactive bool)
}

type Service struct {
	repository       Repository
	passwords        Passwords
	mailer           Mailer
	googleVerifier   GoogleVerifier
	disposableEmails DisposableEmailDetector
	onSessionRevoked func(userID, sessionID string, accountInactive bool)
	now              func() time.Time
	random           io.Reader
	accessLifetime   time.Duration
	refreshLifetime  time.Duration
	dummyHash        string
}

func NewService(
	repository Repository,
	passwords Passwords,
	mailer Mailer,
	options ServiceOptions,
) (*Service, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = defaultRandom()
	}
	if options.AccessLifetime <= 0 {
		options.AccessLifetime = defaultAccessLifetime
	}
	if options.RefreshLifetime <= 0 {
		options.RefreshLifetime = defaultRefreshLifetime
	}
	if options.OnSessionRevoked == nil {
		options.OnSessionRevoked = func(string, string, bool) {}
	}
	dummyHash, err := passwords.Hash(context.Background(), "invalid-account-password")
	if err != nil {
		return nil, err
	}
	return &Service{
		repository:       repository,
		passwords:        passwords,
		mailer:           mailer,
		googleVerifier:   options.GoogleVerifier,
		disposableEmails: options.DisposableEmails,
		onSessionRevoked: options.OnSessionRevoked,
		now:              options.Now,
		random:           options.Random,
		accessLifetime:   options.AccessLifetime,
		refreshLifetime:  options.RefreshLifetime,
		dummyHash:        dummyHash,
	}, nil
}

// Register creates a pending account and mails it a verification code. It never
// returns a session: the account cannot authenticate anywhere until VerifyEmail
// activates it.
func (service *Service) Register(
	ctx context.Context,
	input RegisterInput,
) (AuthOutcome, error) {
	email, normalizedEmail, err := normalizeEmail(input.Email)
	if err != nil || !validRegistrationPassword(input.Password) {
		return AuthOutcome{}, ErrInvalidInput
	}
	// Ahead of the hash and the transaction so a rejected address costs nothing, and
	// ahead of the duplicate handling because the verdict cannot depend on account
	// state without becoming an oracle.
	if service.disposableEmails != nil && service.disposableEmails.IsDisposable(email) {
		return AuthOutcome{}, ErrDisposableEmail
	}
	clientName, err := normalizeClientName(input.ClientName)
	if err != nil {
		return AuthOutcome{}, ErrInvalidInput
	}
	passwordHash, err := service.passwords.Hash(ctx, input.Password)
	if err != nil {
		return AuthOutcome{}, err
	}
	now := service.now().UTC()
	userID, err := issueIdentifier(service.random, "usr_")
	if err != nil {
		return AuthOutcome{}, err
	}
	user := User{
		Account: Account{
			ID:        userID,
			Email:     email,
			Status:    AccountStatusPending,
			CreatedAt: now,
		},
		NormalizedEmail: normalizedEmail,
		PasswordHash:    &passwordHash,
	}
	material, err := service.newVerificationMaterial(user.Account, clientName, now)
	if err != nil {
		return AuthOutcome{}, err
	}

	err = service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		if err := store.CreateUser(ctx, user); err != nil {
			return err
		}
		if err := store.CreateEmailVerification(ctx, material.record); err != nil {
			return err
		}
		return store.AppendAuditEvent(ctx, accountAuditEvent(
			"auth.registration_succeeded",
			user.ID,
			now,
		))
	})
	// The address is already taken. Detecting it as a CreateUser conflict rather than
	// a pre-flight lookup keeps both paths on the same timing and avoids a TOCTOU race.
	if errors.Is(err, ErrConflict) {
		return service.decoyRegistration(ctx, email, normalizedEmail, now)
	}
	if err != nil {
		return AuthOutcome{}, err
	}
	// Sending after the commit keeps a network round trip out of the transaction. A
	// failure here leaves an ordinary pending account, recoverable through resend or
	// by signing in again, so registration still succeeds.
	service.deliverVerificationCode(ctx, user.ID, email, material.code)
	return AuthOutcome{Verification: &material.challenge}, nil
}

// decoyRegistration answers an already-registered address with a challenge that is
// indistinguishable from a real one: same shape, same status, a well-formed ticket
// backed by no row, and a synthetic account that reports nothing about the real one.
// Any code submitted against it fails as an ordinary wrong code. The owner of the
// address is told out of band, by mail, that someone tried to register it.
func (service *Service) decoyRegistration(
	ctx context.Context,
	email string,
	normalizedEmail string,
	now time.Time,
) (AuthOutcome, error) {
	ticket, err := issueToken(service.random, "vft_")
	if err != nil {
		return AuthOutcome{}, err
	}
	decoyID, err := issueIdentifier(service.random, "usr_")
	if err != nil {
		return AuthOutcome{}, err
	}
	err = service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		// Recorded without a user so operators can see the attempt while the audit
		// trail does not become the oracle the response refuses to be.
		return store.AppendAuditEvent(ctx, anonymousAuditEvent("auth.registration_conflict", now))
	})
	if err != nil {
		return AuthOutcome{}, err
	}
	service.deliverRegistrationNotice(ctx, normalizedEmail, email)
	return AuthOutcome{Verification: &VerificationChallenge{
		Account: Account{
			ID:        decoyID,
			Email:     email,
			Status:    AccountStatusPending,
			CreatedAt: now,
		},
		Ticket:          ticket,
		TicketExpiresAt: now.Add(verificationCodeLifetime),
	}}, nil
}

func (service *Service) Login(
	ctx context.Context,
	input LoginInput,
) (AuthOutcome, error) {
	_, normalizedEmail, err := normalizeEmail(input.Email)
	if err != nil || !validLoginPassword(input.Password) {
		return AuthOutcome{}, ErrInvalidCredentials
	}
	clientName, err := normalizeClientName(input.ClientName)
	if err != nil {
		return AuthOutcome{}, ErrInvalidInput
	}

	user, err := service.repository.UserByNormalizedEmail(ctx, normalizedEmail)
	if errors.Is(err, ErrNotFound) {
		_, _ = service.passwords.Verify(ctx, input.Password, service.dummyHash)
		return AuthOutcome{}, ErrInvalidCredentials
	}
	if err != nil {
		return AuthOutcome{}, err
	}
	// A federated-only account has no password to compare against. It burns the same
	// dummy hash as an unknown address so the timing matches, and reports the same
	// generic error: whether an address is reachable by password is not something an
	// unauthenticated caller may probe for.
	if !user.HasPassword() {
		_, _ = service.passwords.Verify(ctx, input.Password, service.dummyHash)
		return AuthOutcome{}, ErrInvalidCredentials
	}
	verified, err := service.passwords.Verify(ctx, input.Password, *user.PasswordHash)
	if err != nil {
		return AuthOutcome{}, err
	}
	if !verified {
		return AuthOutcome{}, ErrInvalidCredentials
	}

	now := service.now().UTC()
	switch user.Status {
	case AccountStatusActive:
	case AccountStatusPending:
		// Answering with a fresh challenge rather than ErrInvalidCredentials is safe
		// here: the caller already proved the password, so this reveals nothing they
		// did not just demonstrate. Every other status stays indistinguishable.
		return service.reissueVerification(ctx, user, clientName, now)
	default:
		return AuthOutcome{}, ErrInvalidCredentials
	}

	material, err := service.newSessionMaterial(user.Account, clientName, now)
	if err != nil {
		return AuthOutcome{}, err
	}
	err = service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		if err := persistSessionMaterial(ctx, store, material); err != nil {
			return err
		}
		return store.AppendAuditEvent(ctx, auditEvent(
			"auth.login_succeeded",
			user.ID,
			material.session.ID,
			now,
		))
	})
	if err != nil {
		return AuthOutcome{}, err
	}
	return AuthOutcome{Credentials: &material.credentials}, nil
}

// reissueVerification hands a pending account a usable ticket again. Within the
// resend cooldown it rotates only the ticket and keeps the outstanding code, so
// repeated sign-in attempts do not mail a new code every time.
func (service *Service) reissueVerification(
	ctx context.Context,
	user User,
	clientName string,
	now time.Time,
) (AuthOutcome, error) {
	material, err := service.newVerificationMaterial(user.Account, clientName, now)
	if err != nil {
		return AuthOutcome{}, err
	}
	reusedCode := false
	err = service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		existing, err := store.EmailVerificationByUserIDForUpdate(ctx, user.ID)
		switch {
		case errors.Is(err, ErrNotFound):
		case err != nil:
			return err
		case existing.ExpiresAt.After(now) && now.Sub(existing.CreatedAt) < minimumResendInterval:
			// Keep the code the user may already be holding, and keep its attempt
			// count with it: the cap belongs to the code, not to the ticket.
			material.record.CodeHash = existing.CodeHash
			material.record.CreatedAt = existing.CreatedAt
			material.record.Attempts = existing.Attempts
			reusedCode = true
		}
		if err := store.ReplaceEmailVerification(ctx, material.record); err != nil {
			return err
		}
		return store.AppendAuditEvent(ctx, accountAuditEvent(
			"auth.verification_reissued",
			user.ID,
			now,
		))
	})
	if err != nil {
		return AuthOutcome{}, err
	}
	if !reusedCode {
		service.deliverVerificationCode(ctx, user.ID, user.Email, material.code)
	}
	return AuthOutcome{Verification: &material.challenge}, nil
}

// VerifyEmail exchanges a verification ticket and its code for a real session. It is
// the only path that activates an account, and the only one a verification ticket
// can reach besides ResendVerification.
func (service *Service) VerifyEmail(
	ctx context.Context,
	input VerifyEmailInput,
) (AuthOutcome, error) {
	if !validToken(input.Ticket, "vft_") || !validVerificationCode(input.Code) {
		return AuthOutcome{}, ErrInvalidVerificationCode
	}
	now := service.now().UTC()
	codeHash := hashToken(input.Code)
	var credentials Credentials
	verified := false

	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		record, err := store.EmailVerificationForUpdate(ctx, hashToken(input.Ticket))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !record.ExpiresAt.After(now) || record.Attempts >= maxVerificationAttempts {
			return nil
		}
		if subtle.ConstantTimeCompare(record.CodeHash, codeHash) != 1 {
			// Returning the increment (and not an error) is what commits it. Failing
			// the transaction here would roll the counter back and make guessing free.
			return store.IncrementEmailVerificationAttempts(ctx, record.UserID)
		}

		user, err := store.UserByID(ctx, record.UserID)
		if err != nil {
			return err
		}
		if user.Status != AccountStatusPending {
			return nil
		}
		account := user.Account
		account.Status = AccountStatusActive
		account.EmailVerifiedAt = &now
		material, err := service.newSessionMaterial(account, record.ClientName, now)
		if err != nil {
			return err
		}
		if err := store.ActivateUser(ctx, record.UserID, now); err != nil {
			return err
		}
		if err := store.DeleteEmailVerification(ctx, record.UserID); err != nil {
			return err
		}
		if err := persistSessionMaterial(ctx, store, material); err != nil {
			return err
		}
		if err := store.AppendAuditEvent(ctx, auditEvent(
			"auth.email_verified",
			user.ID,
			material.session.ID,
			now,
		)); err != nil {
			return err
		}
		verified = true
		credentials = material.credentials
		return nil
	})
	if err != nil {
		return AuthOutcome{}, err
	}
	if !verified {
		return AuthOutcome{}, ErrInvalidVerificationCode
	}
	return AuthOutcome{Credentials: &credentials}, nil
}

// ResendVerification rotates the ticket and code behind an outstanding challenge and
// mails the new code. An unknown ticket and a ticket whose account is no longer
// pending are answered identically, so neither reports on an account's state.
func (service *Service) ResendVerification(
	ctx context.Context,
	ticket string,
) (VerificationChallenge, error) {
	if !validToken(ticket, "vft_") {
		return VerificationChallenge{}, ErrInvalidVerificationCode
	}
	now := service.now().UTC()
	var (
		material  verificationMaterial
		email     string
		userID    string
		throttled bool
		reissued  bool
	)

	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		record, err := store.EmailVerificationForUpdate(ctx, hashToken(ticket))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if now.Sub(record.CreatedAt) < minimumResendInterval {
			throttled = true
			return nil
		}
		user, err := store.UserByID(ctx, record.UserID)
		if err != nil {
			return err
		}
		if user.Status != AccountStatusPending {
			return nil
		}
		material, err = service.newVerificationMaterial(user.Account, record.ClientName, now)
		if err != nil {
			return err
		}
		if err := store.ReplaceEmailVerification(ctx, material.record); err != nil {
			return err
		}
		if err := store.AppendAuditEvent(ctx, accountAuditEvent(
			"auth.verification_resent",
			user.ID,
			now,
		)); err != nil {
			return err
		}
		email, userID, reissued = user.Email, user.ID, true
		return nil
	})
	if err != nil {
		return VerificationChallenge{}, err
	}
	if throttled {
		return VerificationChallenge{}, ErrVerificationThrottled
	}
	if !reissued {
		return VerificationChallenge{}, ErrInvalidVerificationCode
	}
	service.deliverVerificationCode(ctx, userID, email, material.code)
	return material.challenge, nil
}

func (service *Service) Refresh(
	ctx context.Context,
	refreshToken string,
) (Credentials, error) {
	if !validToken(refreshToken, "orr_") {
		return Credentials{}, ErrInvalidRefresh
	}
	now := service.now().UTC()
	newAccessToken, err := issueToken(service.random, "ora_")
	if err != nil {
		return Credentials{}, err
	}
	newRefreshToken, err := issueToken(service.random, "orr_")
	if err != nil {
		return Credentials{}, err
	}
	accessExpiresAt := now.Add(service.accessLifetime)
	var credentials Credentials
	valid := false
	// Set when this call revokes a session; reported only once the revocation has committed.
	var revoked *Session
	accountInactive := false

	err = service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		refresh, err := store.RefreshCredentialForUpdate(ctx, hashToken(refreshToken))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		session, err := store.SessionForUpdate(ctx, refresh.SessionID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}

		if refresh.UsedAt != nil {
			if session.RevokedAt == nil {
				if err := store.RevokeSession(ctx, session.ID, now); err != nil {
					return err
				}
				revoked = &session
				if err := store.AppendAuditEvent(ctx, auditEvent(
					"auth.refresh_reuse_detected",
					session.UserID,
					session.ID,
					now,
				)); err != nil {
					return err
				}
			}
			return nil
		}
		if session.RevokedAt != nil ||
			!refresh.ExpiresAt.After(now) ||
			!session.RefreshExpiresAt.After(now) {
			if session.RevokedAt == nil {
				revoked = &session
				return store.RevokeSession(ctx, session.ID, now)
			}
			return nil
		}

		user, err := store.UserByID(ctx, session.UserID)
		if err != nil {
			return err
		}
		if user.Status != AccountStatusActive {
			revoked, accountInactive = &session, true
			return store.RevokeSession(ctx, session.ID, now)
		}
		if err := store.MarkRefreshCredentialUsed(ctx, refresh.TokenHash, now); err != nil {
			return err
		}
		if err := store.RotateSessionAccess(
			ctx,
			session.ID,
			hashToken(newAccessToken),
			accessExpiresAt,
			now,
		); err != nil {
			return err
		}
		if err := store.CreateRefreshCredential(ctx, RefreshCredential{
			TokenHash: hashToken(newRefreshToken),
			SessionID: session.ID,
			ExpiresAt: session.RefreshExpiresAt,
			CreatedAt: now,
		}); err != nil {
			return err
		}
		if err := store.AppendAuditEvent(ctx, auditEvent(
			"auth.refresh_succeeded",
			user.ID,
			session.ID,
			now,
		)); err != nil {
			return err
		}

		valid = true
		credentials = Credentials{
			Account:               user.Account,
			AccessToken:           newAccessToken,
			AccessTokenExpiresAt:  accessExpiresAt,
			RefreshToken:          newRefreshToken,
			RefreshTokenExpiresAt: session.RefreshExpiresAt,
		}
		return nil
	})
	if err != nil {
		return Credentials{}, err
	}
	if revoked != nil {
		service.onSessionRevoked(revoked.UserID, revoked.ID, accountInactive)
	}
	if !valid {
		return Credentials{}, ErrInvalidRefresh
	}
	return credentials, nil
}

func (service *Service) Logout(ctx context.Context, refreshToken string) error {
	if !validToken(refreshToken, "orr_") {
		return nil
	}
	now := service.now().UTC()
	var revoked *Session
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		refresh, err := store.RefreshCredentialForUpdate(ctx, hashToken(refreshToken))
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		session, err := store.SessionForUpdate(ctx, refresh.SessionID)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil || session.RevokedAt != nil {
			return err
		}
		if err := store.RevokeSession(ctx, session.ID, now); err != nil {
			return err
		}
		revoked = &session
		return store.AppendAuditEvent(ctx, auditEvent(
			"auth.logout_succeeded",
			session.UserID,
			session.ID,
			now,
		))
	})
	if err == nil && revoked != nil {
		service.onSessionRevoked(revoked.UserID, revoked.ID, false)
	}
	return err
}

func (service *Service) CurrentAccount(
	ctx context.Context,
	accessToken string,
) (Account, error) {
	principal, err := service.AuthenticateAccess(ctx, accessToken)
	return principal.Account, err
}

func (service *Service) AuthenticateAccess(
	ctx context.Context,
	accessToken string,
) (AccessPrincipal, error) {
	if !validToken(accessToken, "ora_") {
		return AccessPrincipal{}, ErrUnauthorized
	}
	principal, err := service.repository.AccessPrincipalByAccessTokenHash(
		ctx,
		hashToken(accessToken),
		service.now().UTC(),
	)
	if errors.Is(err, ErrNotFound) {
		return AccessPrincipal{}, ErrUnauthorized
	}
	return principal, err
}

func (service *Service) AuthorizeAccount(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrUnauthorized
	}
	_, err := service.repository.ActiveAccountByID(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return ErrUnauthorized
	}
	return err
}

func (service *Service) AuthorizeSession(ctx context.Context, userID, sessionID string) error {
	if userID == "" || sessionID == "" {
		return ErrUnauthorized
	}
	err := service.repository.ActiveSessionByID(ctx, userID, sessionID, service.now().UTC())
	if errors.Is(err, ErrNotFound) {
		return ErrUnauthorized
	}
	return err
}

type sessionMaterial struct {
	session     Session
	refresh     RefreshCredential
	credentials Credentials
}

func (service *Service) newSessionMaterial(
	account Account,
	clientName string,
	now time.Time,
) (sessionMaterial, error) {
	sessionID, err := issueIdentifier(service.random, "asn_")
	if err != nil {
		return sessionMaterial{}, err
	}
	accessToken, err := issueToken(service.random, "ora_")
	if err != nil {
		return sessionMaterial{}, err
	}
	refreshToken, err := issueToken(service.random, "orr_")
	if err != nil {
		return sessionMaterial{}, err
	}
	accessExpiresAt := now.Add(service.accessLifetime)
	refreshExpiresAt := now.Add(service.refreshLifetime)
	return sessionMaterial{
		session: Session{
			ID:                   sessionID,
			UserID:               account.ID,
			AccessTokenHash:      hashToken(accessToken),
			AccessTokenExpiresAt: accessExpiresAt,
			RefreshExpiresAt:     refreshExpiresAt,
			ClientName:           clientName,
			CreatedAt:            now,
			LastRefreshedAt:      now,
		},
		refresh: RefreshCredential{
			TokenHash: hashToken(refreshToken),
			SessionID: sessionID,
			ExpiresAt: refreshExpiresAt,
			CreatedAt: now,
		},
		credentials: Credentials{
			Account:               account,
			AccessToken:           accessToken,
			AccessTokenExpiresAt:  accessExpiresAt,
			RefreshToken:          refreshToken,
			RefreshTokenExpiresAt: refreshExpiresAt,
		},
	}, nil
}

type verificationMaterial struct {
	challenge VerificationChallenge
	record    EmailVerification
	code      string
}

func (service *Service) newVerificationMaterial(
	account Account,
	clientName string,
	now time.Time,
) (verificationMaterial, error) {
	ticket, err := issueToken(service.random, "vft_")
	if err != nil {
		return verificationMaterial{}, err
	}
	code, err := issueVerificationCode(service.random)
	if err != nil {
		return verificationMaterial{}, err
	}
	expiresAt := now.Add(verificationCodeLifetime)
	return verificationMaterial{
		challenge: VerificationChallenge{
			Account:         account,
			Ticket:          ticket,
			TicketExpiresAt: expiresAt,
		},
		record: EmailVerification{
			UserID:     account.ID,
			TicketHash: hashToken(ticket),
			CodeHash:   hashToken(code),
			ClientName: clientName,
			ExpiresAt:  expiresAt,
			CreatedAt:  now,
		},
		code: code,
	}, nil
}

func (service *Service) deliverVerificationCode(ctx context.Context, userID, email, code string) {
	service.recordDelivery(ctx, userID, service.mailer.SendVerificationCode(ctx, email, code))
}

func (service *Service) deliverRegistrationNotice(ctx context.Context, normalizedEmail, email string) {
	err := service.mailer.SendRegistrationNotice(ctx, email)
	// Attribute the outcome to whichever account owns the address. The response has
	// already been decided, so nothing learned here can leak into it.
	userID := ""
	if user, lookupErr := service.repository.UserByNormalizedEmail(ctx, normalizedEmail); lookupErr == nil {
		userID = user.ID
	}
	service.recordDelivery(ctx, userID, err)
}

// recordDelivery keeps the bounce flag current. It is diagnostic state, so it is
// recorded on a best-effort basis and never changes what the caller is told —
// on the registration-conflict path, that is what keeps the flag from becoming an
// enumeration side channel.
func (service *Service) recordDelivery(ctx context.Context, userID string, err error) {
	if userID == "" {
		return
	}
	switch {
	case errors.Is(err, ErrMailUndeliverable):
		bouncedAt := service.now().UTC()
		_ = service.repository.SetEmailBounced(ctx, userID, &bouncedAt)
	case err != nil:
		// Transient failure. It says nothing about the address, and flagging it would
		// mark every user's mail bad during an outage.
	default:
		// The mailbox works; clear a flag left by an earlier failure.
		_ = service.repository.SetEmailBounced(ctx, userID, nil)
	}
}

func persistSessionMaterial(
	ctx context.Context,
	store TransactionStore,
	material sessionMaterial,
) error {
	if err := store.CreateSession(ctx, material.session); err != nil {
		return err
	}
	return store.CreateRefreshCredential(ctx, material.refresh)
}

func auditEvent(eventType, userID, sessionID string, occurredAt time.Time) AuditEvent {
	return AuditEvent{
		UserID:     &userID,
		SessionID:  &sessionID,
		EventType:  eventType,
		OccurredAt: occurredAt,
	}
}

// accountAuditEvent records an event that belongs to an account but to no session,
// which is every step of verification before a session exists.
func accountAuditEvent(eventType, userID string, occurredAt time.Time) AuditEvent {
	return AuditEvent{
		UserID:     &userID,
		EventType:  eventType,
		OccurredAt: occurredAt,
	}
}

// anonymousAuditEvent records an event that must not name an account, so that the
// audit trail cannot answer a question the response deliberately refuses to.
func anonymousAuditEvent(eventType string, occurredAt time.Time) AuditEvent {
	return AuditEvent{
		EventType:  eventType,
		OccurredAt: occurredAt,
	}
}

func validVerificationCode(code string) bool {
	if len(code) != verificationCodeLength {
		return false
	}
	for _, character := range []byte(code) {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func normalizeEmail(value string) (string, string, error) {
	email := strings.TrimSpace(value)
	if email == "" || len(email) > maximumEmailLength || !utf8.ValidString(email) {
		return "", "", ErrInvalidInput
	}
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email {
		return "", "", ErrInvalidInput
	}
	return email, strings.ToLower(email), nil
}

func normalizeClientName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" ||
		!utf8.ValidString(value) ||
		utf8.RuneCountInString(value) > maximumClientNameLength {
		return "", ErrInvalidInput
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return "", ErrInvalidInput
		}
	}
	return value, nil
}

func validRegistrationPassword(password string) bool {
	characterCount := utf8.RuneCountInString(password)
	return characterCount >= minimumPasswordLength &&
		characterCount <= maximumPasswordLength &&
		len(password) <= maximumPasswordBytes &&
		utf8.ValidString(password)
}

func validLoginPassword(password string) bool {
	return password != "" &&
		utf8.ValidString(password) &&
		utf8.RuneCountInString(password) <= maximumPasswordLength &&
		len(password) <= maximumPasswordBytes
}

func validToken(token, prefix string) bool {
	if !strings.HasPrefix(token, prefix) || len(token) != len(prefix)+43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token[len(prefix):])
	return err == nil && len(decoded) == tokenRandomLength
}
