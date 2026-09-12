package postgres

import (
	"context"
	"time"

	"opencode-remote/server/internal/connectors"
	identitypostgres "opencode-remote/server/internal/identity/postgres"

	"gorm.io/gorm"
)

type ChallengeModel struct {
	Hash      []byte                      `gorm:"type:bytea;primaryKey;autoIncrement:false;check:pairing_challenges_hash_length_check,octet_length(hash) = 32"`
	Purpose   string                      `gorm:"type:varchar(16);not null;check:pairing_challenges_purpose_check,purpose IN ('connector','device')"`
	UserID    *string                     `gorm:"type:varchar(32);index:pairing_challenges_user_id_idx"`
	User      *identitypostgres.UserModel `gorm:"foreignKey:UserID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	CreatedAt time.Time                   `gorm:"type:timestamptz;not null"`
	ExpiresAt time.Time                   `gorm:"type:timestamptz;not null;index:pairing_challenges_expires_at_idx;check:pairing_challenges_expiry_check,expires_at > created_at"`
	UsedAt    *time.Time                  `gorm:"type:timestamptz"`
}

func (ChallengeModel) TableName() string { return "pairing_challenges" }

type DeviceModel struct {
	ID                  string                     `gorm:"type:varchar(32);primaryKey;check:devices_id_check,char_length(id) >= 20"`
	UserID              string                     `gorm:"type:varchar(32);not null;index:devices_user_id_idx"`
	User                identitypostgres.UserModel `gorm:"foreignKey:UserID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	Name                string                     `gorm:"type:varchar(64);not null"`
	IdentityVersion     int                        `gorm:"not null;check:devices_identity_version_check,identity_version = 1"`
	IdentitySuite       string                     `gorm:"type:varchar(64);not null"`
	KeyID               string                     `gorm:"type:char(43);not null;uniqueIndex:devices_key_id_key"`
	PublicKey           string                     `gorm:"type:varchar(1024);not null"`
	CredentialHash      []byte                     `gorm:"type:bytea;uniqueIndex:devices_credential_hash_key;check:devices_credential_hash_length_check,credential_hash IS NULL OR octet_length(credential_hash) = 32"`
	CredentialExpiresAt *time.Time                 `gorm:"type:timestamptz"`
	CreatedAt           time.Time                  `gorm:"type:timestamptz;not null"`
	ActivatedAt         *time.Time                 `gorm:"type:timestamptz"`
	RevokedAt           *time.Time                 `gorm:"type:timestamptz;index:devices_revoked_at_idx"`
}

func (DeviceModel) TableName() string { return "devices" }

type ConnectorModel struct {
	ID                  string                     `gorm:"type:varchar(32);primaryKey;check:connectors_id_check,char_length(id) >= 20"`
	UserID              string                     `gorm:"type:varchar(32);not null;index:connectors_user_id_idx"`
	User                identitypostgres.UserModel `gorm:"foreignKey:UserID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	Name                string                     `gorm:"type:varchar(64);not null"`
	IdentityVersion     int                        `gorm:"not null;check:connectors_identity_version_check,identity_version = 1"`
	IdentitySuite       string                     `gorm:"type:varchar(64);not null"`
	KeyID               string                     `gorm:"type:char(43);not null;uniqueIndex:connectors_key_id_key"`
	PublicKey           string                     `gorm:"type:varchar(1024);not null"`
	CredentialHash      []byte                     `gorm:"type:bytea;uniqueIndex:connectors_credential_hash_key;check:connectors_credential_hash_length_check,credential_hash IS NULL OR octet_length(credential_hash) = 32"`
	CredentialExpiresAt *time.Time                 `gorm:"type:timestamptz"`
	CreatedAt           time.Time                  `gorm:"type:timestamptz;not null"`
	RevokedAt           *time.Time                 `gorm:"type:timestamptz;index:connectors_revoked_at_idx"`
}

func (ConnectorModel) TableName() string { return "connectors" }

type PairingModel struct {
	ID                       string                      `gorm:"type:varchar(32);primaryKey;check:connector_pairings_id_check,char_length(id) >= 20"`
	SecretHash               []byte                      `gorm:"type:bytea;not null;uniqueIndex:connector_pairings_secret_hash_key;check:connector_pairings_secret_hash_length_check,octet_length(secret_hash) = 32"`
	UserCodeHash             []byte                      `gorm:"type:bytea;not null;uniqueIndex:connector_pairings_user_code_hash_key;check:connector_pairings_user_code_hash_length_check,octet_length(user_code_hash) = 32"`
	ConnectorName            string                      `gorm:"type:varchar(64);not null"`
	ConnectorIdentityVersion int                         `gorm:"not null"`
	ConnectorIdentitySuite   string                      `gorm:"type:varchar(64);not null"`
	ConnectorKeyID           string                      `gorm:"type:char(43);not null;index:connector_pairings_key_id_idx"`
	ConnectorPublicKey       string                      `gorm:"type:varchar(1024);not null"`
	ConnectorCredentialHash  []byte                      `gorm:"type:bytea;check:connector_pairings_credential_hash_length_check,connector_credential_hash IS NULL OR octet_length(connector_credential_hash) = 32"`
	State                    string                      `gorm:"type:varchar(16);not null;index:connector_pairings_state_expires_idx,priority:1;check:connector_pairings_state_check,state IN ('pending','verification','confirmed','completed','expired')"`
	UserID                   *string                     `gorm:"type:varchar(32);index:connector_pairings_user_id_idx"`
	User                     *identitypostgres.UserModel `gorm:"foreignKey:UserID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	DeviceID                 *string                     `gorm:"type:varchar(32);index:connector_pairings_device_id_idx"`
	Device                   *DeviceModel                `gorm:"foreignKey:DeviceID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	ConnectorID              *string                     `gorm:"type:varchar(32);index:connector_pairings_connector_id_idx"`
	Connector                *ConnectorModel             `gorm:"foreignKey:ConnectorID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	CreatedAt                time.Time                   `gorm:"type:timestamptz;not null"`
	ExpiresAt                time.Time                   `gorm:"type:timestamptz;not null;index:connector_pairings_state_expires_idx,priority:2;check:connector_pairings_expiry_check,expires_at > created_at"`
	ConnectorReviewedAt      *time.Time                  `gorm:"type:timestamptz"`
	ConfirmedAt              *time.Time                  `gorm:"type:timestamptz"`
	CompletedAt              *time.Time                  `gorm:"type:timestamptz"`
}

func (PairingModel) TableName() string { return "connector_pairings" }

type TrustModel struct {
	UserID      string                     `gorm:"type:varchar(32);primaryKey"`
	User        identitypostgres.UserModel `gorm:"foreignKey:UserID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	DeviceID    string                     `gorm:"type:varchar(32);primaryKey"`
	Device      DeviceModel                `gorm:"foreignKey:DeviceID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	ConnectorID string                     `gorm:"type:varchar(32);primaryKey"`
	Connector   ConnectorModel             `gorm:"foreignKey:ConnectorID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	CreatedAt   time.Time                  `gorm:"type:timestamptz;not null"`
	RevokedAt   *time.Time                 `gorm:"type:timestamptz;index:connector_trust_revoked_at_idx"`
}

func (TrustModel) TableName() string { return "connector_trust" }

type RelayTicketModel struct {
	TokenHash              []byte     `gorm:"type:bytea;primaryKey;autoIncrement:false;check:relay_tickets_token_hash_length_check,octet_length(token_hash) = 32"`
	UserID                 string     `gorm:"type:varchar(32);not null;index:relay_tickets_user_id_idx"`
	Role                   string     `gorm:"type:varchar(16);not null;check:relay_tickets_role_check,role IN ('client','connector')"`
	SubjectID              string     `gorm:"type:varchar(32);not null;index:relay_tickets_subject_idx,priority:2"`
	SubjectKeyID           string     `gorm:"type:char(43);not null"`
	CredentialID           string     `gorm:"type:varchar(32);not null"`
	AuthorizationExpiresAt *time.Time `gorm:"type:timestamptz"`
	CreatedAt              time.Time  `gorm:"type:timestamptz;not null"`
	ExpiresAt              time.Time  `gorm:"type:timestamptz;not null;index:relay_tickets_expires_at_idx;check:relay_tickets_expiry_check,expires_at > created_at"`
	ConsumedAt             *time.Time `gorm:"type:timestamptz"`
}

func (RelayTicketModel) TableName() string { return "relay_tickets" }

type AuditEventModel struct {
	ID          uint64    `gorm:"primaryKey;autoIncrement"`
	UserID      *string   `gorm:"type:varchar(32);index:connector_audit_user_id_idx"`
	DeviceID    *string   `gorm:"type:varchar(32);index:connector_audit_device_id_idx"`
	ConnectorID *string   `gorm:"type:varchar(32);index:connector_audit_connector_id_idx"`
	PairingID   *string   `gorm:"type:varchar(32);index:connector_audit_pairing_id_idx"`
	EventType   string    `gorm:"type:varchar(64);not null;index:connector_audit_type_occurred_idx,priority:1"`
	OccurredAt  time.Time `gorm:"type:timestamptz;not null;index:connector_audit_type_occurred_idx,priority:2"`
}

func (AuditEventModel) TableName() string { return "connector_audit_events" }

func Migrate(ctx context.Context, database *gorm.DB) error {
	return database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		if err := transaction.AutoMigrate(
			&ChallengeModel{},
			&DeviceModel{},
			&ConnectorModel{},
			&PairingModel{},
			&TrustModel{},
			&RelayTicketModel{},
			&AuditEventModel{},
		); err != nil {
			return err
		}
		if err := transaction.Model(&PairingModel{}).
			Where("state IN ? AND connector_credential_hash IS NULL", []string{
				connectors.PairingStatePending,
				connectors.PairingStateVerification,
				connectors.PairingStateConfirmed,
			}).
			Update("state", connectors.PairingStateExpired).Error; err != nil {
			return err
		}
		if err := transaction.Exec(`
			WITH ranked AS (
				SELECT id, row_number() OVER (
					PARTITION BY connector_key_id ORDER BY created_at DESC, id DESC
				) AS position
				FROM connector_pairings
				WHERE state <> 'completed' AND state <> 'expired'
			)
			UPDATE connector_pairings
			SET state = 'expired'
			FROM ranked
			WHERE connector_pairings.id = ranked.id AND ranked.position > 1
		`).Error; err != nil {
			return err
		}
		return transaction.Exec(`
			CREATE UNIQUE INDEX IF NOT EXISTS connector_pairings_active_key_id_key
			ON connector_pairings (connector_key_id)
			WHERE state <> 'completed' AND state <> 'expired'
		`).Error
	})
}
