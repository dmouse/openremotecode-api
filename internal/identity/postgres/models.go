package postgres

import (
	"context"
	"time"

	"gorm.io/gorm"
)

type UserModel struct {
	ID              string `gorm:"type:varchar(32);primaryKey;check:users_id_check,char_length(id) >= 20"`
	Email           string `gorm:"type:varchar(254);not null"`
	NormalizedEmail string `gorm:"type:varchar(254);not null;uniqueIndex:users_normalized_email_key"`
	// PasswordHash is NULL for an account that has no password credential, which is
	// every account created through a federated provider. The column was NOT NULL
	// before federated sign-in existed; dropping that is the whole migration, and it
	// leaves every existing row untouched. Nothing may treat NULL as a hash that
	// failed to parse — identity.User.HasPassword is the only correct test.
	PasswordHash    *string    `gorm:"type:text"`
	Status          string     `gorm:"type:varchar(16);not null;check:users_status_check,status IN ('pending','active','disabled')"`
	EmailVerifiedAt *time.Time `gorm:"type:timestamptz"`
	EmailBouncedAt  *time.Time `gorm:"type:timestamptz"`
	CreatedAt       time.Time  `gorm:"type:timestamptz;not null"`
}

func (UserModel) TableName() string { return "users" }

// FederatedIdentityModel binds an external provider account to a local user. The
// primary key is (provider, subject), so one provider account can reach at most one
// local account. UserID additionally carries a unique index per provider, so one
// local account holds at most one identity per provider: without it, two Google
// accounts could both point at the same user and either could sign in as it.
//
// Rows are never swept. They are bounded by the account count and cascade away with
// the user, which is also how revoking a link is expressed — deleting the row makes
// the next sign-in from that subject take the linking path again.
type FederatedIdentityModel struct {
	Provider string    `gorm:"type:varchar(32);primaryKey;uniqueIndex:federated_identities_provider_user_key,priority:1;check:federated_identities_provider_check,provider IN ('google')"`
	Subject  string    `gorm:"type:varchar(255);primaryKey;check:federated_identities_subject_check,char_length(subject) > 0"`
	UserID   string    `gorm:"type:varchar(32);not null;uniqueIndex:federated_identities_provider_user_key,priority:2"`
	User     UserModel `gorm:"foreignKey:UserID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	// Email is the address the provider asserted, kept for operator diagnostics. It
	// is not an authorization input and is deliberately not unique: two Google
	// accounts can legitimately assert the same address over time.
	Email               string    `gorm:"type:varchar(254);not null"`
	CreatedAt           time.Time `gorm:"type:timestamptz;not null"`
	LastAuthenticatedAt time.Time `gorm:"type:timestamptz;not null"`
}

func (FederatedIdentityModel) TableName() string { return "federated_identities" }

type SessionModel struct {
	ID                   string     `gorm:"type:varchar(32);primaryKey;check:auth_sessions_id_check,char_length(id) >= 20"`
	UserID               string     `gorm:"type:varchar(32);not null;index:auth_sessions_user_id_idx"`
	User                 UserModel  `gorm:"foreignKey:UserID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	AccessTokenHash      []byte     `gorm:"type:bytea;not null;uniqueIndex:auth_sessions_access_token_hash_key;check:auth_sessions_access_token_hash_length_check,octet_length(access_token_hash) = 32"`
	AccessTokenExpiresAt time.Time  `gorm:"type:timestamptz;not null;index:auth_sessions_access_expires_at_idx"`
	RefreshExpiresAt     time.Time  `gorm:"type:timestamptz;not null;index:auth_sessions_refresh_expires_at_idx"`
	ClientName           string     `gorm:"type:varchar(64);not null"`
	CreatedAt            time.Time  `gorm:"type:timestamptz;not null;check:auth_sessions_expiry_check,access_token_expires_at > created_at AND refresh_expires_at > created_at"`
	LastRefreshedAt      time.Time  `gorm:"type:timestamptz;not null"`
	RevokedAt            *time.Time `gorm:"type:timestamptz;index:auth_sessions_revoked_at_idx"`
}

func (SessionModel) TableName() string { return "auth_sessions" }

type RefreshCredentialModel struct {
	TokenHash []byte       `gorm:"type:bytea;primaryKey;autoIncrement:false;check:refresh_credentials_token_hash_length_check,octet_length(token_hash) = 32"`
	SessionID string       `gorm:"type:varchar(32);not null;index:refresh_credentials_session_id_idx"`
	Session   SessionModel `gorm:"foreignKey:SessionID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	ExpiresAt time.Time    `gorm:"type:timestamptz;not null;index:refresh_credentials_expires_at_idx"`
	CreatedAt time.Time    `gorm:"type:timestamptz;not null;check:refresh_credentials_expiry_check,expires_at > created_at"`
	UsedAt    *time.Time   `gorm:"type:timestamptz"`
}

func (RefreshCredentialModel) TableName() string { return "refresh_credentials" }

// EmailVerificationModel is keyed by user so that reissuing a challenge replaces the
// outstanding one. Rows are never swept: they are bounded by the pending-account
// count and cascade away with the user.
type EmailVerificationModel struct {
	UserID     string    `gorm:"type:varchar(32);primaryKey"`
	User       UserModel `gorm:"foreignKey:UserID;constraint:OnUpdate:RESTRICT,OnDelete:CASCADE"`
	TicketHash []byte    `gorm:"type:bytea;not null;uniqueIndex:email_verifications_ticket_hash_key;check:email_verifications_ticket_hash_length_check,octet_length(ticket_hash) = 32"`
	CodeHash   []byte    `gorm:"type:bytea;not null;check:email_verifications_code_hash_length_check,octet_length(code_hash) = 32"`
	ClientName string    `gorm:"type:varchar(64);not null"`
	Attempts   int       `gorm:"not null;default:0"`
	ExpiresAt  time.Time `gorm:"type:timestamptz;not null;index:email_verifications_expires_at_idx"`
	CreatedAt  time.Time `gorm:"type:timestamptz;not null;check:email_verifications_expiry_check,expires_at > created_at"`
}

func (EmailVerificationModel) TableName() string { return "email_verifications" }

type AuditEventModel struct {
	ID         uint64        `gorm:"primaryKey;autoIncrement"`
	UserID     *string       `gorm:"type:varchar(32);index:audit_events_user_id_idx"`
	User       *UserModel    `gorm:"foreignKey:UserID;constraint:OnUpdate:RESTRICT,OnDelete:SET NULL"`
	SessionID  *string       `gorm:"type:varchar(32);index:audit_events_session_id_idx"`
	Session    *SessionModel `gorm:"foreignKey:SessionID;constraint:OnUpdate:RESTRICT,OnDelete:SET NULL"`
	EventType  string        `gorm:"type:varchar(64);not null;index:audit_events_type_occurred_idx,priority:1"`
	OccurredAt time.Time     `gorm:"type:timestamptz;not null;index:audit_events_type_occurred_idx,priority:2"`
}

func (AuditEventModel) TableName() string { return "audit_events" }

func Migrate(ctx context.Context, database *gorm.DB) error {
	return database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		return transaction.AutoMigrate(
			&UserModel{},
			&FederatedIdentityModel{},
			&SessionModel{},
			&RefreshCredentialModel{},
			&EmailVerificationModel{},
			&AuditEventModel{},
		)
	})
}
