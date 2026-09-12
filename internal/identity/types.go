package identity

import (
	"context"
	"errors"
	"time"
)

var (
	ErrConflict                = errors.New("identity record conflicts with existing data")
	ErrInvalidCredentials      = errors.New("invalid credentials")
	ErrInvalidInput            = errors.New("invalid input")
	ErrInvalidRefresh          = errors.New("invalid refresh credential")
	ErrInvalidVerificationCode = errors.New("invalid verification code")
	ErrNotFound                = errors.New("identity record not found")
	ErrUnauthorized            = errors.New("unauthorized")
	ErrVerificationThrottled   = errors.New("verification code was requested too recently")
)

// Federated sign-in failures. They are separated from ErrInvalidCredentials because
// each says something different to the client, and only one of them is recoverable.
var (
	// ErrInvalidGoogleToken covers every way an assertion can fail to establish an
	// identity: malformed, expired, wrong audience, wrong issuer, bad signature, or
	// an address Google itself has not verified. They collapse into one error because
	// no client can act differently on the distinction and a caller probing the
	// endpoint must not learn which check rejected it.
	ErrInvalidGoogleToken = errors.New("google identity assertion is invalid")
	// ErrAccountLinkRequired is returned when a verified Google address matches a
	// local account whose own address was never verified. Linking silently would let
	// whoever controls the address take over an account they may never have owned,
	// so the user is sent through password sign-in, which proves the account instead.
	ErrAccountLinkRequired = errors.New("account requires an explicit link before google sign-in")
	// ErrGoogleUnavailable means the deployment has no configured audience, so the
	// route cannot verify anything and says so rather than failing as a bad token.
	ErrGoogleUnavailable = errors.New("google sign-in is not configured")
	// ErrIdentityAlreadyLinked is returned when the account holding this address is
	// already linked to a different account at the same provider. One local account
	// holds at most one identity per provider, so the second is refused rather than
	// silently becoming a second way in.
	ErrIdentityAlreadyLinked = errors.New("account is already linked to another identity from this provider")
)

// Mail delivery failures are classified because they receive different treatment:
// only a permanent rejection says anything about the address itself.
var (
	// ErrMailDeliveryFailed is a transient or infrastructure failure (timeout,
	// connection refused, 4xx, authentication failure). It says nothing about the
	// recipient and must never set the bounce flag.
	ErrMailDeliveryFailed = errors.New("mail delivery failed")
	// ErrMailUndeliverable is a permanent per-recipient rejection. The address is bad.
	ErrMailUndeliverable = errors.New("mail recipient is undeliverable")
)

const (
	AccountStatusPending  = "pending"
	AccountStatusActive   = "active"
	AccountStatusDisabled = "disabled"
)

type Account struct {
	ID              string
	Email           string
	Status          string
	EmailVerifiedAt *time.Time
	// EmailBouncedAt records when delivery to this address last failed permanently.
	// It lives on the account rather than on EmailVerification because deliverability
	// is a property of the address and must outlive a verification row, which is
	// deleted once the code is accepted. It is diagnostic state only: no
	// authorization path may consult it, and it never blocks a resend.
	EmailBouncedAt *time.Time
	CreatedAt      time.Time
}

type AccessPrincipal struct {
	Account              Account
	SessionID            string
	AccessTokenExpiresAt time.Time
}

type User struct {
	Account
	NormalizedEmail string
	// PasswordHash is nil for an account that has no password credential, which is
	// every account created through a federated provider. It is a pointer rather
	// than an empty-string sentinel so that "no password" is expressible in SQL as
	// NULL and cannot be mistaken for a hash that merely fails to parse.
	PasswordHash *string
}

// HasPassword reports whether this account can be reached through password sign-in.
// Login consults it before hashing so that a federated-only account fails as bad
// credentials rather than as an unparseable hash.
func (user User) HasPassword() bool {
	return user.PasswordHash != nil && *user.PasswordHash != ""
}

type Session struct {
	ID                   string
	UserID               string
	AccessTokenHash      []byte
	AccessTokenExpiresAt time.Time
	RefreshExpiresAt     time.Time
	ClientName           string
	CreatedAt            time.Time
	LastRefreshedAt      time.Time
	RevokedAt            *time.Time
}

type RefreshCredential struct {
	TokenHash []byte
	SessionID string
	ExpiresAt time.Time
	CreatedAt time.Time
	UsedAt    *time.Time
}

// EmailVerification is the pending-account challenge record. It is keyed by user
// so that a reissue replaces the outstanding challenge rather than accumulating rows.
type EmailVerification struct {
	UserID     string
	TicketHash []byte
	CodeHash   []byte
	ClientName string
	Attempts   int
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// VerificationChallenge is the unauthenticated response to registering or signing
// in to a pending account. The ticket is scoped only to VerifyEmail and
// ResendVerification; it is not a bearer credential and authenticates nothing else.
type VerificationChallenge struct {
	Account         Account
	Ticket          string
	TicketExpiresAt time.Time
}

// AuthOutcome carries exactly one of Credentials (the account is active and now has
// a session) or Verification (the account is pending and must prove email ownership).
type AuthOutcome struct {
	Credentials  *Credentials
	Verification *VerificationChallenge
}

type VerifyEmailInput struct {
	Ticket string
	Code   string
}

// ProviderGoogle is the only federated provider in this release. It is a named
// constant rather than a literal so that the persistence key stays stable if a
// second provider is ever added alongside it.
const ProviderGoogle = "google"

// FederatedIdentity binds one provider account to one local user. It is keyed by
// (provider, subject) rather than by address: a Google account's address can change,
// but its subject cannot, so the subject is the only durable join key.
type FederatedIdentity struct {
	Provider string
	Subject  string
	UserID   string
	// Email is the address the provider asserted at link time. It is retained for
	// operator diagnostics only. No authorization path reads it, and it is
	// deliberately not kept in step with the account address.
	Email               string
	CreatedAt           time.Time
	LastAuthenticatedAt time.Time
}

// GoogleIdentity is the verified subset of an ID token that this service acts on.
// A value of this type means every check in GoogleVerifier already passed; nothing
// downstream re-validates it.
type GoogleIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// GoogleVerifier turns a raw ID token into a verified identity. It is an interface
// so the service can be tested without reaching Google, and so the transport-level
// dependency stays out of the domain. Implementations must verify the signature,
// issuer, audience, and expiry, and must not return a partially checked result.
type GoogleVerifier interface {
	Verify(ctx context.Context, rawIDToken string) (GoogleIdentity, error)
}

type GoogleAuthInput struct {
	IDToken    string
	ClientName string
}

type AuditEvent struct {
	UserID     *string
	SessionID  *string
	EventType  string
	OccurredAt time.Time
}

type RegisterInput struct {
	Email      string
	Password   string
	ClientName string
}

type LoginInput struct {
	Email      string
	Password   string
	ClientName string
}

type Credentials struct {
	Account               Account
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

type Repository interface {
	WithinTransaction(context.Context, func(TransactionStore) error) error
	UserByNormalizedEmail(context.Context, string) (User, error)
	AccessPrincipalByAccessTokenHash(context.Context, []byte, time.Time) (AccessPrincipal, error)
	ActiveAccountByID(context.Context, string) (Account, error)
	ActiveSessionByID(context.Context, string, string, time.Time) error
	// SetEmailBounced records (or, with a nil timestamp, clears) the delivery flag.
	// It is on Repository rather than TransactionStore because every mail send now
	// happens after its transaction has committed, so the write stands alone. That
	// also makes it the whole integration surface for a future bounce webhook.
	SetEmailBounced(ctx context.Context, userID string, at *time.Time) error
}

type TransactionStore interface {
	CreateUser(context.Context, User) error
	// FederatedIdentityForUpdate locks the link for a (provider, subject) pair so a
	// concurrent first sign-in from two devices cannot create two accounts.
	FederatedIdentityForUpdate(context.Context, string, string) (FederatedIdentity, error)
	// FederatedIdentityByUserForUpdate answers whether this account already holds an
	// identity from this provider. Linking checks it rather than letting the unique
	// index reject the insert: in PostgreSQL a constraint violation aborts the whole
	// transaction, so the refusal could not then be audited.
	FederatedIdentityByUserForUpdate(context.Context, string, string) (FederatedIdentity, error)
	CreateFederatedIdentity(context.Context, FederatedIdentity) error
	TouchFederatedIdentity(context.Context, string, string, string, time.Time) error
	UserByNormalizedEmailForUpdate(context.Context, string) (User, error)
	CreateSession(context.Context, Session) error
	CreateRefreshCredential(context.Context, RefreshCredential) error
	CreateEmailVerification(context.Context, EmailVerification) error
	ReplaceEmailVerification(context.Context, EmailVerification) error
	EmailVerificationForUpdate(context.Context, []byte) (EmailVerification, error)
	EmailVerificationByUserIDForUpdate(context.Context, string) (EmailVerification, error)
	IncrementEmailVerificationAttempts(context.Context, string) error
	DeleteEmailVerification(context.Context, string) error
	ActivateUser(context.Context, string, time.Time) error
	RefreshCredentialForUpdate(context.Context, []byte) (RefreshCredential, error)
	SessionForUpdate(context.Context, string) (Session, error)
	UserByID(context.Context, string) (User, error)
	MarkRefreshCredentialUsed(context.Context, []byte, time.Time) error
	RotateSessionAccess(context.Context, string, []byte, time.Time, time.Time) error
	RevokeSession(context.Context, string, time.Time) error
	AppendAuditEvent(context.Context, AuditEvent) error
}

type Passwords interface {
	Hash(context.Context, string) (string, error)
	Verify(context.Context, string, string) (bool, error)
}
