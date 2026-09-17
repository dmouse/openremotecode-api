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
)

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
	State                   string
	UserID                  *string
	DeviceID                *string
	ConnectorID             *string
	CreatedAt               time.Time
	ExpiresAt               time.Time
	ConnectorReviewedAt     *time.Time
	ConfirmedAt             *time.Time
	CompletedAt             *time.Time
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
	UserID                 string
	Role                   string
	SubjectID              string
	Identity               PublicIdentity
	TrustedIdentities      []PublicIdentity
	AuthorizationExpiresAt time.Time
}

type Repository interface {
	WithinTransaction(context.Context, func(TransactionStore) error) error
	ListConnectors(context.Context, string) ([]Connector, error)
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
	TrustedIdentities(context.Context, string, string, string) ([]PublicIdentity, error)
	CreateRelayTicket(context.Context, RelayTicket) error
	RelayTicketForUpdate(context.Context, []byte) (RelayTicket, error)
	SaveRelayTicket(context.Context, RelayTicket) error
	AppendAuditEvent(context.Context, AuditEvent) error
}
