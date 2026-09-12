package postgres

import (
	"context"
	"errors"
	"time"

	"opencode-remote/server/internal/identity"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Store struct {
	database *gorm.DB
}

func NewStore(database *gorm.DB) *Store {
	return &Store{database: database}
}

func (store *Store) WithinTransaction(
	ctx context.Context,
	operation func(identity.TransactionStore) error,
) error {
	return translateError(store.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		return operation(&transactionStore{database: transaction})
	}))
}

func (store *Store) UserByNormalizedEmail(
	ctx context.Context,
	normalizedEmail string,
) (identity.User, error) {
	var model UserModel
	err := store.database.WithContext(ctx).
		Where("normalized_email = ?", normalizedEmail).
		First(&model).Error
	if err != nil {
		return identity.User{}, translateError(err)
	}
	return userFromModel(model), nil
}

func (store *Store) AccessPrincipalByAccessTokenHash(
	ctx context.Context,
	accessTokenHash []byte,
	now time.Time,
) (identity.AccessPrincipal, error) {
	var result struct {
		UserModel
		SessionID            string    `gorm:"column:session_id"`
		AccessTokenExpiresAt time.Time `gorm:"column:session_access_token_expires_at"`
	}
	err := store.database.WithContext(ctx).
		Model(&UserModel{}).
		Select("users.*, auth_sessions.id AS session_id, auth_sessions.access_token_expires_at AS session_access_token_expires_at").
		Joins("JOIN auth_sessions ON auth_sessions.user_id = users.id").
		Where(
			"auth_sessions.access_token_hash = ? AND "+
				"auth_sessions.access_token_expires_at > ? AND "+
				"auth_sessions.revoked_at IS NULL AND users.status = ?",
			accessTokenHash,
			now,
			identity.AccountStatusActive,
		).
		First(&result).Error
	if err != nil {
		return identity.AccessPrincipal{}, translateError(err)
	}
	return identity.AccessPrincipal{
		Account:              accountFromModel(result.UserModel),
		SessionID:            result.SessionID,
		AccessTokenExpiresAt: result.AccessTokenExpiresAt,
	}, nil
}

func (store *Store) ActiveAccountByID(ctx context.Context, userID string) (identity.Account, error) {
	var model UserModel
	err := store.database.WithContext(ctx).
		Where("id = ? AND status = ?", userID, identity.AccountStatusActive).
		First(&model).Error
	if err != nil {
		return identity.Account{}, translateError(err)
	}
	return accountFromModel(model), nil
}

func (store *Store) ActiveSessionByID(ctx context.Context, userID, sessionID string, now time.Time) error {
	var count int64
	err := store.database.WithContext(ctx).
		Table("auth_sessions").
		Joins("JOIN users ON users.id = auth_sessions.user_id").
		Where("auth_sessions.id = ? AND auth_sessions.user_id = ?", sessionID, userID).
		Where("auth_sessions.revoked_at IS NULL AND auth_sessions.access_token_expires_at > ?", now).
		Where("users.status = ?", identity.AccountStatusActive).
		Count(&count).Error
	if err != nil {
		return translateError(err)
	}
	if count != 1 {
		return identity.ErrNotFound
	}
	return nil
}

// SetEmailBounced records or clears the delivery flag for an address. A nil
// timestamp clears it, so a mailbox that starts working again stops looking broken.
// It deliberately stands outside any transaction: every send happens after its
// transaction commits, so there is nothing for a rollback to undo.
func (store *Store) SetEmailBounced(ctx context.Context, userID string, at *time.Time) error {
	return translateError(store.database.WithContext(ctx).
		Model(&UserModel{}).
		Where("id = ?", userID).
		Update("email_bounced_at", at).Error)
}

type transactionStore struct {
	database *gorm.DB
}

func (store *transactionStore) CreateUser(ctx context.Context, user identity.User) error {
	return translateError(store.database.WithContext(ctx).
		Omit(clause.Associations).
		Create(&UserModel{
			ID:              user.ID,
			Email:           user.Email,
			NormalizedEmail: user.NormalizedEmail,
			PasswordHash:    user.PasswordHash,
			Status:          user.Status,
			EmailVerifiedAt: user.EmailVerifiedAt,
			EmailBouncedAt:  user.EmailBouncedAt,
			CreatedAt:       user.CreatedAt,
		}).Error)
}

// FederatedIdentityForUpdate locks an existing link so two concurrent sign-ins from
// the same provider account serialize. A missing row locks nothing, which is why
// AuthenticateWithGoogle retries a conflict rather than assuming this is enough.
func (store *transactionStore) FederatedIdentityForUpdate(
	ctx context.Context,
	provider string,
	subject string,
) (identity.FederatedIdentity, error) {
	var model FederatedIdentityModel
	err := store.database.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("provider = ? AND subject = ?", provider, subject).
		First(&model).Error
	if err != nil {
		return identity.FederatedIdentity{}, translateError(err)
	}
	return federatedIdentityFromModel(model), nil
}

// FederatedIdentityByUserForUpdate finds the identity this account already holds
// for a provider, if any. Linking calls it instead of relying on the unique index,
// because a constraint violation aborts the PostgreSQL transaction and would take
// the refusal's audit event with it.
func (store *transactionStore) FederatedIdentityByUserForUpdate(
	ctx context.Context,
	provider string,
	userID string,
) (identity.FederatedIdentity, error) {
	var model FederatedIdentityModel
	err := store.database.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("provider = ? AND user_id = ?", provider, userID).
		First(&model).Error
	if err != nil {
		return identity.FederatedIdentity{}, translateError(err)
	}
	return federatedIdentityFromModel(model), nil
}

func (store *transactionStore) CreateFederatedIdentity(
	ctx context.Context,
	link identity.FederatedIdentity,
) error {
	return translateError(store.database.WithContext(ctx).
		Omit(clause.Associations).
		Create(&FederatedIdentityModel{
			Provider:            link.Provider,
			Subject:             link.Subject,
			UserID:              link.UserID,
			Email:               link.Email,
			CreatedAt:           link.CreatedAt,
			LastAuthenticatedAt: link.LastAuthenticatedAt,
		}).Error)
}

// TouchFederatedIdentity records the latest sign-in and refreshes the diagnostic
// address snapshot. It deliberately does not touch the account's own address: the
// link is keyed by subject, and the two are allowed to diverge.
func (store *transactionStore) TouchFederatedIdentity(
	ctx context.Context,
	provider string,
	subject string,
	email string,
	at time.Time,
) error {
	result := store.database.WithContext(ctx).
		Model(&FederatedIdentityModel{}).
		Where("provider = ? AND subject = ?", provider, subject).
		Updates(map[string]any{"email": email, "last_authenticated_at": at})
	if result.Error != nil {
		return translateError(result.Error)
	}
	if result.RowsAffected != 1 {
		return identity.ErrNotFound
	}
	return nil
}

// UserByNormalizedEmailForUpdate is the locking counterpart of the repository's
// lookup. Google sign-in needs the row held for the rest of the transaction because
// it may activate or link the account it finds.
func (store *transactionStore) UserByNormalizedEmailForUpdate(
	ctx context.Context,
	normalizedEmail string,
) (identity.User, error) {
	var model UserModel
	err := store.database.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("normalized_email = ?", normalizedEmail).
		First(&model).Error
	if err != nil {
		return identity.User{}, translateError(err)
	}
	return userFromModel(model), nil
}

func (store *transactionStore) CreateSession(
	ctx context.Context,
	session identity.Session,
) error {
	return translateError(store.database.WithContext(ctx).
		Omit(clause.Associations).
		Create(&SessionModel{
			ID:                   session.ID,
			UserID:               session.UserID,
			AccessTokenHash:      session.AccessTokenHash,
			AccessTokenExpiresAt: session.AccessTokenExpiresAt,
			RefreshExpiresAt:     session.RefreshExpiresAt,
			ClientName:           session.ClientName,
			CreatedAt:            session.CreatedAt,
			LastRefreshedAt:      session.LastRefreshedAt,
			RevokedAt:            session.RevokedAt,
		}).Error)
}

func (store *transactionStore) CreateRefreshCredential(
	ctx context.Context,
	credential identity.RefreshCredential,
) error {
	return translateError(store.database.WithContext(ctx).
		Omit(clause.Associations).
		Create(&RefreshCredentialModel{
			TokenHash: credential.TokenHash,
			SessionID: credential.SessionID,
			ExpiresAt: credential.ExpiresAt,
			CreatedAt: credential.CreatedAt,
			UsedAt:    credential.UsedAt,
		}).Error)
}

func (store *transactionStore) CreateEmailVerification(
	ctx context.Context,
	verification identity.EmailVerification,
) error {
	return translateError(store.database.WithContext(ctx).
		Omit(clause.Associations).
		Create(emailVerificationModelFrom(verification)).Error)
}

// ReplaceEmailVerification upserts by user so that reissuing a challenge (login
// against a pending account, or an explicit resend) rotates the outstanding row
// instead of colliding with it.
func (store *transactionStore) ReplaceEmailVerification(
	ctx context.Context,
	verification identity.EmailVerification,
) error {
	return translateError(store.database.WithContext(ctx).
		Omit(clause.Associations).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "user_id"}},
			UpdateAll: true,
		}).
		Create(emailVerificationModelFrom(verification)).Error)
}

func (store *transactionStore) EmailVerificationForUpdate(
	ctx context.Context,
	ticketHash []byte,
) (identity.EmailVerification, error) {
	var model EmailVerificationModel
	err := store.database.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("ticket_hash = ?", ticketHash).
		First(&model).Error
	if err != nil {
		return identity.EmailVerification{}, translateError(err)
	}
	return emailVerificationFromModel(model), nil
}

// EmailVerificationByUserIDForUpdate locks the outstanding challenge for an account.
// Signing in to a pending account reaches the record by user rather than by ticket,
// because the caller proved a password rather than presenting a ticket.
func (store *transactionStore) EmailVerificationByUserIDForUpdate(
	ctx context.Context,
	userID string,
) (identity.EmailVerification, error) {
	var model EmailVerificationModel
	err := store.database.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("user_id = ?", userID).
		First(&model).Error
	if err != nil {
		return identity.EmailVerification{}, translateError(err)
	}
	return emailVerificationFromModel(model), nil
}

func (store *transactionStore) IncrementEmailVerificationAttempts(
	ctx context.Context,
	userID string,
) error {
	result := store.database.WithContext(ctx).
		Model(&EmailVerificationModel{}).
		Where("user_id = ?", userID).
		Update("attempts", gorm.Expr("attempts + 1"))
	if result.Error != nil {
		return translateError(result.Error)
	}
	if result.RowsAffected != 1 {
		return identity.ErrNotFound
	}
	return nil
}

func (store *transactionStore) DeleteEmailVerification(
	ctx context.Context,
	userID string,
) error {
	return translateError(store.database.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&EmailVerificationModel{}).Error)
}

// ActivateUser promotes a pending account. The pending-only WHERE clause is what
// guarantees this can never touch an existing active account, including the
// pre-verification accounts that carry a NULL email_verified_at.
func (store *transactionStore) ActivateUser(
	ctx context.Context,
	userID string,
	verifiedAt time.Time,
) error {
	result := store.database.WithContext(ctx).
		Model(&UserModel{}).
		Where("id = ? AND status = ?", userID, identity.AccountStatusPending).
		Updates(map[string]any{
			"status":            identity.AccountStatusActive,
			"email_verified_at": verifiedAt,
		})
	if result.Error != nil {
		return translateError(result.Error)
	}
	if result.RowsAffected != 1 {
		return identity.ErrNotFound
	}
	return nil
}

func (store *transactionStore) RefreshCredentialForUpdate(
	ctx context.Context,
	tokenHash []byte,
) (identity.RefreshCredential, error) {
	var model RefreshCredentialModel
	err := store.database.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("token_hash = ?", tokenHash).
		First(&model).Error
	if err != nil {
		return identity.RefreshCredential{}, translateError(err)
	}
	return refreshCredentialFromModel(model), nil
}

func (store *transactionStore) SessionForUpdate(
	ctx context.Context,
	sessionID string,
) (identity.Session, error) {
	var model SessionModel
	err := store.database.WithContext(ctx).
		Clauses(clause.Locking{Strength: "UPDATE"}).
		Where("id = ?", sessionID).
		First(&model).Error
	if err != nil {
		return identity.Session{}, translateError(err)
	}
	return sessionFromModel(model), nil
}

func (store *transactionStore) UserByID(
	ctx context.Context,
	userID string,
) (identity.User, error) {
	var model UserModel
	err := store.database.WithContext(ctx).Where("id = ?", userID).First(&model).Error
	if err != nil {
		return identity.User{}, translateError(err)
	}
	return userFromModel(model), nil
}

func (store *transactionStore) MarkRefreshCredentialUsed(
	ctx context.Context,
	tokenHash []byte,
	usedAt time.Time,
) error {
	result := store.database.WithContext(ctx).
		Model(&RefreshCredentialModel{}).
		Where("token_hash = ? AND used_at IS NULL", tokenHash).
		Update("used_at", usedAt)
	if result.Error != nil {
		return translateError(result.Error)
	}
	if result.RowsAffected != 1 {
		return identity.ErrNotFound
	}
	return nil
}

func (store *transactionStore) RotateSessionAccess(
	ctx context.Context,
	sessionID string,
	accessTokenHash []byte,
	accessExpiresAt time.Time,
	refreshedAt time.Time,
) error {
	result := store.database.WithContext(ctx).
		Model(&SessionModel{}).
		Where("id = ? AND revoked_at IS NULL", sessionID).
		Updates(map[string]any{
			"access_token_hash":       accessTokenHash,
			"access_token_expires_at": accessExpiresAt,
			"last_refreshed_at":       refreshedAt,
		})
	if result.Error != nil {
		return translateError(result.Error)
	}
	if result.RowsAffected != 1 {
		return identity.ErrNotFound
	}
	return nil
}

func (store *transactionStore) RevokeSession(
	ctx context.Context,
	sessionID string,
	revokedAt time.Time,
) error {
	return translateError(store.database.WithContext(ctx).
		Model(&SessionModel{}).
		Where("id = ? AND revoked_at IS NULL", sessionID).
		Update("revoked_at", revokedAt).Error)
}

func (store *transactionStore) AppendAuditEvent(
	ctx context.Context,
	event identity.AuditEvent,
) error {
	return translateError(store.database.WithContext(ctx).
		Omit(clause.Associations).
		Create(&AuditEventModel{
			UserID:     event.UserID,
			SessionID:  event.SessionID,
			EventType:  event.EventType,
			OccurredAt: event.OccurredAt,
		}).Error)
}

func userFromModel(model UserModel) identity.User {
	return identity.User{
		Account:         accountFromModel(model),
		NormalizedEmail: model.NormalizedEmail,
		PasswordHash:    model.PasswordHash,
	}
}

func federatedIdentityFromModel(model FederatedIdentityModel) identity.FederatedIdentity {
	return identity.FederatedIdentity{
		Provider:            model.Provider,
		Subject:             model.Subject,
		UserID:              model.UserID,
		Email:               model.Email,
		CreatedAt:           model.CreatedAt,
		LastAuthenticatedAt: model.LastAuthenticatedAt,
	}
}

func accountFromModel(model UserModel) identity.Account {
	return identity.Account{
		ID:              model.ID,
		Email:           model.Email,
		Status:          model.Status,
		EmailVerifiedAt: model.EmailVerifiedAt,
		EmailBouncedAt:  model.EmailBouncedAt,
		CreatedAt:       model.CreatedAt,
	}
}

func emailVerificationModelFrom(
	verification identity.EmailVerification,
) *EmailVerificationModel {
	return &EmailVerificationModel{
		UserID:     verification.UserID,
		TicketHash: verification.TicketHash,
		CodeHash:   verification.CodeHash,
		ClientName: verification.ClientName,
		Attempts:   verification.Attempts,
		ExpiresAt:  verification.ExpiresAt,
		CreatedAt:  verification.CreatedAt,
	}
}

func emailVerificationFromModel(model EmailVerificationModel) identity.EmailVerification {
	return identity.EmailVerification{
		UserID:     model.UserID,
		TicketHash: model.TicketHash,
		CodeHash:   model.CodeHash,
		ClientName: model.ClientName,
		Attempts:   model.Attempts,
		ExpiresAt:  model.ExpiresAt,
		CreatedAt:  model.CreatedAt,
	}
}

func sessionFromModel(model SessionModel) identity.Session {
	return identity.Session{
		ID:                   model.ID,
		UserID:               model.UserID,
		AccessTokenHash:      model.AccessTokenHash,
		AccessTokenExpiresAt: model.AccessTokenExpiresAt,
		RefreshExpiresAt:     model.RefreshExpiresAt,
		ClientName:           model.ClientName,
		CreatedAt:            model.CreatedAt,
		LastRefreshedAt:      model.LastRefreshedAt,
		RevokedAt:            model.RevokedAt,
	}
}

func refreshCredentialFromModel(model RefreshCredentialModel) identity.RefreshCredential {
	return identity.RefreshCredential{
		TokenHash: model.TokenHash,
		SessionID: model.SessionID,
		ExpiresAt: model.ExpiresAt,
		CreatedAt: model.CreatedAt,
		UsedAt:    model.UsedAt,
	}
}

func translateError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return identity.ErrNotFound
	case errors.Is(err, gorm.ErrDuplicatedKey), errors.Is(err, gorm.ErrForeignKeyViolated):
		return identity.ErrConflict
	default:
		return err
	}
}
