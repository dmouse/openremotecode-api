package connectors

import (
	"context"
	"errors"
	"time"
)

var (
	ErrConflict     = errors.New("connector state conflicts with existing data")
	ErrExpired      = errors.New("connector operation expired")
	ErrInvalidInput = errors.New("connector input is invalid")
	ErrNotFound     = errors.New("connector record not found")
	ErrUnauthorized = errors.New("connector credential is invalid")
	// ErrInvalidCode is a pairing code that matches no pairing. It is deliberately not
	// ErrUnauthorized: a typo must not read as an expired session to the client.
	ErrInvalidCode = errors.New("pairing code not found")
	// ErrTooManyAttempts is matched by every AttemptsExceededError.
	ErrTooManyAttempts = errors.New("too many incorrect pairing codes")
)

// AttemptsExceededError refuses a pairing claim because too many incorrect codes were
// tried recently, and says when trying again can succeed.
type AttemptsExceededError struct{ RetryAfter time.Duration }

func (err AttemptsExceededError) Error() string        { return ErrTooManyAttempts.Error() }
func (err AttemptsExceededError) Is(target error) bool { return target == ErrTooManyAttempts }

// ClaimFailureCounts are the incorrect pairing codes tried within the current windows.
type ClaimFailureCounts struct {
	Account int
	// AccountOldest is the earliest counted failure for the account; its window ends one
	// window length after it. Zero when Account is zero.
	AccountOldest time.Time
	Global        int
}

const (
	ChallengePurposeConnector = "connector"
	ChallengePurposeDevice    = "device"

	PairingStatePending      = "pending"
	PairingStateVerification = "verification"
	PairingStateConfirmed    = "confirmed"
	PairingStateCompleted    = "completed"
	PairingStateExpired      = "expired"

	RelayRoleClient    = "client"
	RelayRoleConnector = "connector"
)

type PublicIdentity struct {
	Version   int    `json:"version"`
	Suite     string `json:"suite"`
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

type IdentityProof struct {
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
}

type Challenge struct {
	Hash      []byte
	Purpose   string
	UserID    *string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
}

type Pairing struct {
	ID                      string
	SecretHash              []byte
	UserCodeHash            []byte
	ConnectorName           string
	ConnectorIdentity       PublicIdentity
	ConnectorCredentialHash []byte
	// DeviceCredentialSeed is the random input the confirmation derived the device
	// credential from, kept so a retried confirmation returns the same value.
	DeviceCredentialSeed []byte
	State                string
	UserID               *string
	DeviceID             *string
	ConnectorID          *string
	CreatedAt            time.Time
	ExpiresAt            time.Time
	// ConnectorReviewedAt records the explicit approval given in OpenCode (ApprovePairing).
	ConnectorReviewedAt *time.Time
	ConfirmedAt         *time.Time
	CompletedAt         *time.Time
}

type Device struct {
	ID                  string
	UserID              string
	Name                string
	Identity            PublicIdentity
	CredentialHash      []byte
	CredentialExpiresAt *time.Time
	// A rotation is provisional: the pending credential grants nothing until it is
	// activated, and expires at PendingCredentialExpiresAt if it never is.
	PendingCredentialHash      []byte
	PendingCredentialExpiresAt *time.Time
	CreatedAt                  time.Time
	ActivatedAt                *time.Time
	RevokedAt                  *time.Time
}

type Connector struct {
	ID                  string
	UserID              string
	Name                string
	Identity            PublicIdentity
	CredentialHash      []byte
	CredentialExpiresAt *time.Time
	// A rotation is provisional: the pending credential grants nothing until it is
	// activated, and expires at PendingCredentialExpiresAt if it never is.
	PendingCredentialHash      []byte
	PendingCredentialExpiresAt *time.Time
	CreatedAt                  time.Time
	RevokedAt                  *time.Time
}

type Trust struct {
	UserID      string
	DeviceID    string
	ConnectorID string
	CreatedAt   time.Time
	RevokedAt   *time.Time
}

type RelayTicket struct {
	TokenHash              []byte
	UserID                 string
	Role                   string
	SubjectID              string
	SubjectKeyID           string
	CredentialID           string
	AuthorizationExpiresAt *time.Time
	CreatedAt              time.Time
	ExpiresAt              time.Time
	ConsumedAt             *time.Time
}

type AuditEvent struct {
	UserID      *string
	DeviceID    *string
	ConnectorID *string
	PairingID   *string
	EventType   string
	OccurredAt  time.Time
}

type ChallengeResult struct {
	Challenge string
	ExpiresAt time.Time
}

type BeginPairingInput struct {
	Name     string
	Identity PublicIdentity
	Proof    IdentityProof
}

type BeginPairingResult struct {
	PairingID       string
	PairingSecret   string
	UserCode        string
	ServiceID       string
	VerificationURI string
	ExpiresAt       time.Time
	PollInterval    time.Duration
}

type ClaimPairingInput struct {
	UserID     string
	UserCode   string
	DeviceName string
	Identity   PublicIdentity
	Proof      IdentityProof
}

type PairingTranscript struct {
	Version           int            `json:"version"`
	ServiceID         string         `json:"serviceId"`
	PairingID         string         `json:"pairingId"`
	ConnectorIdentity PublicIdentity `json:"connectorIdentity"`
	DeviceIdentity    PublicIdentity `json:"deviceIdentity"`
}

type ClaimPairingResult struct {
	PairingID  string
	DeviceID   string
	ExpiresAt  time.Time
	Transcript PairingTranscript
}

type ConfirmPairingResult struct {
	DeviceID                  string
	ConnectorID               string
	DeviceCredential          string
	DeviceCredentialExpiresAt time.Time
}

type PollPairingResult struct {
	Status                       string
	PairingID                    string
	ServiceID                    string
	ExpiresAt                    time.Time
	Transcript                   *PairingTranscript
	ConnectorID                  string
	ConnectorCredential          string
	ConnectorCredentialExpiresAt *time.Time
	LinkedAt                     *time.Time
}

type TicketResult struct {
	Ticket    string
	ExpiresAt time.Time
}

// RotationResult carries a credential that grants nothing until it is activated. ActivateBy
// is the deadline after which the rotation lapses and the current credential simply remains.
type RotationResult struct {
	Credential string
	ActivateBy time.Time
}

type Admission struct {
	UserID    string
	Role      string
	SubjectID string
	// SessionID is the account session a client ticket was issued under, rechecked for
	// the life of the socket so logging out ends it. Empty for connectors.
	SessionID              string
	Identity               PublicIdentity
	TrustedIdentities      []PublicIdentity
	AuthorizationExpiresAt time.Time
}

// Revocation names the live relay sockets a committed revocation must close. UserID is always
// set and scopes the match to one account; at most one of the other fields narrows it. With
// none, it covers every socket of the account.
type Revocation struct {
	UserID string
	// ConnectorID covers that connector's sockets.
	ConnectorID string
	// DeviceID covers that client device's sockets.
	DeviceID string
	// SessionID covers client sockets admitted under that account session.
	SessionID string
}

// Covers reports whether a live admission falls under the revocation.
func (revocation Revocation) Covers(admission Admission) bool {
	if revocation.UserID == "" || admission.UserID != revocation.UserID {
		return false
	}
	switch {
	case revocation.ConnectorID != "":
		return admission.Role == RelayRoleConnector && admission.SubjectID == revocation.ConnectorID
	case revocation.DeviceID != "":
		return admission.Role == RelayRoleClient && admission.SubjectID == revocation.DeviceID
	case revocation.SessionID != "":
		return admission.Role == RelayRoleClient && admission.SessionID == revocation.SessionID
	default:
		return true
	}
}

type Repository interface {
	WithinTransaction(context.Context, func(TransactionStore) error) error
	ListConnectors(context.Context, string) ([]Connector, error)
	// ListDevices returns the account's activated, unrevoked client devices.
	ListDevices(context.Context, string) ([]Device, error)
}

type TransactionStore interface {
	CreateChallenge(context.Context, Challenge) error
	ChallengeForUpdate(context.Context, []byte) (Challenge, error)
	SaveChallenge(context.Context, Challenge) error
	CreatePairing(context.Context, Pairing) error
	ExpirePairingsForKey(context.Context, string, time.Time) error
	PairingByCodeForUpdate(context.Context, []byte) (Pairing, error)
	PairingBySecretForUpdate(context.Context, []byte) (Pairing, error)
	PairingByIDForUpdate(context.Context, string) (Pairing, error)
	SavePairing(context.Context, Pairing) error
	DeviceByKeyIDForUpdate(context.Context, string) (Device, error)
	DeviceByIDForUpdate(context.Context, string) (Device, error)
	DeviceByCredentialForUpdate(context.Context, []byte) (Device, error)
	// Matches a hash against either the live or the pending credential, so an
	// activation can be authorized by a credential that is not current yet.
	DeviceByAnyCredentialForUpdate(context.Context, []byte) (Device, error)
	CreateDevice(context.Context, Device) error
	SaveDevice(context.Context, Device) error
	ConnectorByKeyIDForUpdate(context.Context, string) (Connector, error)
	ConnectorByIDForUpdate(context.Context, string) (Connector, error)
	ConnectorByCredentialForUpdate(context.Context, []byte) (Connector, error)
	// Matches a hash against either the live or the pending credential, so an
	// activation can be authorized by a credential that is not current yet.
	ConnectorByAnyCredentialForUpdate(context.Context, []byte) (Connector, error)
	CreateConnector(context.Context, Connector) error
	SaveConnector(context.Context, Connector) error
	UpsertTrust(context.Context, Trust) error
	// RevokeDeviceTrust ends every trust relationship the device holds on the account.
	RevokeDeviceTrust(context.Context, string, string, time.Time) error
	TrustedIdentities(context.Context, string, string, string) ([]PublicIdentity, error)
	// ClaimFailuresForUpdate counts the account's incorrect pairing codes since the first
	// time and everyone's since the second. It serializes claims per account for the rest
	// of the transaction, so concurrent guesses cannot all pass the same count.
	ClaimFailuresForUpdate(context.Context, string, time.Time, time.Time) (ClaimFailureCounts, error)
	// RecordClaimFailure stores one incorrect code and drops failures older than the
	// second time, which no window counts any more.
	RecordClaimFailure(context.Context, string, time.Time, time.Time) error
	CreateRelayTicket(context.Context, RelayTicket) error
	RelayTicketForUpdate(context.Context, []byte) (RelayTicket, error)
	SaveRelayTicket(context.Context, RelayTicket) error
	AppendAuditEvent(context.Context, AuditEvent) error
}
