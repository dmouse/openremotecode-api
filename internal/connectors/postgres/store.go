package postgres

import (
	"context"
	"errors"
	"time"

	"opencode-remote/server/internal/connectors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type Store struct{ database *gorm.DB }

func NewStore(database *gorm.DB) *Store { return &Store{database: database} }

func (store *Store) WithinTransaction(ctx context.Context, operation func(connectors.TransactionStore) error) error {
	return translateError(store.database.WithContext(ctx).Transaction(func(transaction *gorm.DB) error {
		return operation(&transactionStore{database: transaction})
	}))
}

func (store *Store) ListConnectors(ctx context.Context, userID string) ([]connectors.Connector, error) {
	var models []ConnectorModel
	err := store.database.WithContext(ctx).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Order("created_at ASC").Find(&models).Error
	if err != nil {
		return nil, translateError(err)
	}
	result := make([]connectors.Connector, 0, len(models))
	for _, model := range models {
		result = append(result, connectorFromModel(model))
	}
	return result, nil
}

type transactionStore struct{ database *gorm.DB }

func (store *transactionStore) CreateChallenge(ctx context.Context, value connectors.Challenge) error {
	return translateError(store.database.WithContext(ctx).Omit(clause.Associations).Create(challengeModel(value)).Error)
}

func (store *transactionStore) ChallengeForUpdate(ctx context.Context, hash []byte) (connectors.Challenge, error) {
	var model ChallengeModel
	err := store.lock(ctx).Where("hash = ?", hash).First(&model).Error
	if err != nil {
		return connectors.Challenge{}, translateError(err)
	}
	return challengeFromModel(model), nil
}

func (store *transactionStore) SaveChallenge(ctx context.Context, value connectors.Challenge) error {
	return save(ctx, store.database, challengeModel(value))
}

func (store *transactionStore) CreatePairing(ctx context.Context, value connectors.Pairing) error {
	return translateError(store.database.WithContext(ctx).Omit(clause.Associations).Create(pairingModel(value)).Error)
}

func (store *transactionStore) ExpirePairingsForKey(ctx context.Context, keyID string, now time.Time) error {
	return translateError(store.database.WithContext(ctx).
		Model(&PairingModel{}).
		Where("connector_key_id = ? AND state IN ? AND expires_at <= ?", keyID, []string{
			connectors.PairingStatePending,
			connectors.PairingStateVerification,
			connectors.PairingStateConfirmed,
		}, now).
		Update("state", connectors.PairingStateExpired).Error)
}

func (store *transactionStore) PairingByCodeForUpdate(ctx context.Context, hash []byte) (connectors.Pairing, error) {
	return store.pairingForUpdate(ctx, "user_code_hash = ?", hash)
}

func (store *transactionStore) PairingBySecretForUpdate(ctx context.Context, hash []byte) (connectors.Pairing, error) {
	return store.pairingForUpdate(ctx, "secret_hash = ?", hash)
}

func (store *transactionStore) PairingByIDForUpdate(ctx context.Context, id string) (connectors.Pairing, error) {
	return store.pairingForUpdate(ctx, "id = ?", id)
}

func (store *transactionStore) pairingForUpdate(ctx context.Context, query string, argument any) (connectors.Pairing, error) {
	var model PairingModel
	err := store.lock(ctx).Where(query, argument).First(&model).Error
	if err != nil {
		return connectors.Pairing{}, translateError(err)
	}
	return pairingFromModel(model), nil
}

func (store *transactionStore) SavePairing(ctx context.Context, value connectors.Pairing) error {
	return save(ctx, store.database, pairingModel(value))
}

func (store *transactionStore) DeviceByKeyIDForUpdate(ctx context.Context, keyID string) (connectors.Device, error) {
	return store.deviceForUpdate(ctx, "key_id = ?", keyID)
}

func (store *transactionStore) DeviceByIDForUpdate(ctx context.Context, id string) (connectors.Device, error) {
	return store.deviceForUpdate(ctx, "id = ?", id)
}

func (store *transactionStore) DeviceByCredentialForUpdate(ctx context.Context, hash []byte) (connectors.Device, error) {
	return store.deviceForUpdate(ctx, "credential_hash = ?", hash)
}

func (store *transactionStore) deviceForUpdate(ctx context.Context, query string, argument any) (connectors.Device, error) {
	var model DeviceModel
	err := store.lock(ctx).Where(query, argument).First(&model).Error
	if err != nil {
		return connectors.Device{}, translateError(err)
	}
	return deviceFromModel(model), nil
}

func (store *transactionStore) CreateDevice(ctx context.Context, value connectors.Device) error {
	return translateError(store.database.WithContext(ctx).Omit(clause.Associations).Create(deviceModel(value)).Error)
}

func (store *transactionStore) SaveDevice(ctx context.Context, value connectors.Device) error {
	return save(ctx, store.database, deviceModel(value))
}

func (store *transactionStore) ConnectorByKeyIDForUpdate(ctx context.Context, keyID string) (connectors.Connector, error) {
	return store.connectorForUpdate(ctx, "key_id = ?", keyID)
}

func (store *transactionStore) ConnectorByIDForUpdate(ctx context.Context, id string) (connectors.Connector, error) {
	return store.connectorForUpdate(ctx, "id = ?", id)
}

func (store *transactionStore) ConnectorByCredentialForUpdate(ctx context.Context, hash []byte) (connectors.Connector, error) {
	return store.connectorForUpdate(ctx, "credential_hash = ?", hash)
}

func (store *transactionStore) connectorForUpdate(ctx context.Context, query string, argument any) (connectors.Connector, error) {
	var model ConnectorModel
	err := store.lock(ctx).Where(query, argument).First(&model).Error
	if err != nil {
		return connectors.Connector{}, translateError(err)
	}
	return connectorFromModel(model), nil
}

func (store *transactionStore) CreateConnector(ctx context.Context, value connectors.Connector) error {
	return translateError(store.database.WithContext(ctx).Omit(clause.Associations).Create(connectorModel(value)).Error)
}

func (store *transactionStore) SaveConnector(ctx context.Context, value connectors.Connector) error {
	return save(ctx, store.database, connectorModel(value))
}

func (store *transactionStore) UpsertTrust(ctx context.Context, value connectors.Trust) error {
	model := trustModel(value)
	return translateError(store.database.WithContext(ctx).Omit(clause.Associations).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}, {Name: "device_id"}, {Name: "connector_id"}},
		DoUpdates: clause.Assignments(map[string]any{"created_at": value.CreatedAt, "revoked_at": nil}),
	}).Create(model).Error)
}

func (store *transactionStore) TrustedIdentities(ctx context.Context, userID, role, subjectID string) ([]connectors.PublicIdentity, error) {
	type identityRow struct {
		Version   int
		Suite     string
		KeyID     string
		PublicKey string
	}
	var rows []identityRow
	query := store.database.WithContext(ctx).Table("connector_trust").Where("connector_trust.user_id = ? AND connector_trust.revoked_at IS NULL", userID)
	if role == connectors.RelayRoleClient {
		query = query.Select("connectors.identity_version AS version, connectors.identity_suite AS suite, connectors.key_id, connectors.public_key").
			Joins("JOIN connectors ON connectors.id = connector_trust.connector_id AND connectors.user_id = connector_trust.user_id AND connectors.revoked_at IS NULL").
			Where("connector_trust.device_id = ?", subjectID)
	} else {
		query = query.Select("devices.identity_version AS version, devices.identity_suite AS suite, devices.key_id, devices.public_key").
			Joins("JOIN devices ON devices.id = connector_trust.device_id AND devices.user_id = connector_trust.user_id AND devices.revoked_at IS NULL").
			Where("connector_trust.connector_id = ?", subjectID)
	}
	if err := query.Scan(&rows).Error; err != nil {
		return nil, translateError(err)
	}
	result := make([]connectors.PublicIdentity, 0, len(rows))
	for _, row := range rows {
		result = append(result, connectors.PublicIdentity{Version: row.Version, Suite: row.Suite, KeyID: row.KeyID, PublicKey: row.PublicKey})
	}
	return result, nil
}

func (store *transactionStore) CreateRelayTicket(ctx context.Context, value connectors.RelayTicket) error {
	return translateError(store.database.WithContext(ctx).Create(relayTicketModel(value)).Error)
}

func (store *transactionStore) RelayTicketForUpdate(ctx context.Context, hash []byte) (connectors.RelayTicket, error) {
	var model RelayTicketModel
	err := store.lock(ctx).Where("token_hash = ?", hash).First(&model).Error
	if err != nil {
		return connectors.RelayTicket{}, translateError(err)
	}
	return relayTicketFromModel(model), nil
}

func (store *transactionStore) SaveRelayTicket(ctx context.Context, value connectors.RelayTicket) error {
	return save(ctx, store.database, relayTicketModel(value))
}

func (store *transactionStore) AppendAuditEvent(ctx context.Context, value connectors.AuditEvent) error {
	return translateError(store.database.WithContext(ctx).Create(&AuditEventModel{
		UserID: value.UserID, DeviceID: value.DeviceID, ConnectorID: value.ConnectorID,
		PairingID: value.PairingID, EventType: value.EventType, OccurredAt: value.OccurredAt,
	}).Error)
}

func (store *transactionStore) lock(ctx context.Context) *gorm.DB {
	return store.database.WithContext(ctx).Clauses(clause.Locking{Strength: "UPDATE"})
}

func save[T any](ctx context.Context, database *gorm.DB, model *T) error {
	return translateError(database.WithContext(ctx).Omit(clause.Associations).Save(model).Error)
}

func challengeModel(value connectors.Challenge) *ChallengeModel {
	return &ChallengeModel{Hash: value.Hash, Purpose: value.Purpose, UserID: value.UserID, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt, UsedAt: value.UsedAt}
}
func challengeFromModel(value ChallengeModel) connectors.Challenge {
	return connectors.Challenge{Hash: value.Hash, Purpose: value.Purpose, UserID: value.UserID, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt, UsedAt: value.UsedAt}
}

func deviceModel(value connectors.Device) *DeviceModel {
	return &DeviceModel{ID: value.ID, UserID: value.UserID, Name: value.Name, IdentityVersion: value.Identity.Version, IdentitySuite: value.Identity.Suite, KeyID: value.Identity.KeyID, PublicKey: value.Identity.PublicKey, CredentialHash: value.CredentialHash, CredentialExpiresAt: value.CredentialExpiresAt, CreatedAt: value.CreatedAt, ActivatedAt: value.ActivatedAt, RevokedAt: value.RevokedAt}
}
func deviceFromModel(value DeviceModel) connectors.Device {
	return connectors.Device{ID: value.ID, UserID: value.UserID, Name: value.Name, Identity: connectors.PublicIdentity{Version: value.IdentityVersion, Suite: value.IdentitySuite, KeyID: value.KeyID, PublicKey: value.PublicKey}, CredentialHash: value.CredentialHash, CredentialExpiresAt: value.CredentialExpiresAt, CreatedAt: value.CreatedAt, ActivatedAt: value.ActivatedAt, RevokedAt: value.RevokedAt}
}

func connectorModel(value connectors.Connector) *ConnectorModel {
	return &ConnectorModel{ID: value.ID, UserID: value.UserID, Name: value.Name, IdentityVersion: value.Identity.Version, IdentitySuite: value.Identity.Suite, KeyID: value.Identity.KeyID, PublicKey: value.Identity.PublicKey, CredentialHash: value.CredentialHash, CredentialExpiresAt: value.CredentialExpiresAt, CreatedAt: value.CreatedAt, RevokedAt: value.RevokedAt}
}
func connectorFromModel(value ConnectorModel) connectors.Connector {
	return connectors.Connector{ID: value.ID, UserID: value.UserID, Name: value.Name, Identity: connectors.PublicIdentity{Version: value.IdentityVersion, Suite: value.IdentitySuite, KeyID: value.KeyID, PublicKey: value.PublicKey}, CredentialHash: value.CredentialHash, CredentialExpiresAt: value.CredentialExpiresAt, CreatedAt: value.CreatedAt, RevokedAt: value.RevokedAt}
}

func pairingModel(value connectors.Pairing) *PairingModel {
	return &PairingModel{ID: value.ID, SecretHash: value.SecretHash, UserCodeHash: value.UserCodeHash, ConnectorName: value.ConnectorName, ConnectorIdentityVersion: value.ConnectorIdentity.Version, ConnectorIdentitySuite: value.ConnectorIdentity.Suite, ConnectorKeyID: value.ConnectorIdentity.KeyID, ConnectorPublicKey: value.ConnectorIdentity.PublicKey, ConnectorCredentialHash: value.ConnectorCredentialHash, State: value.State, UserID: value.UserID, DeviceID: value.DeviceID, ConnectorID: value.ConnectorID, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt, ConnectorReviewedAt: value.ConnectorReviewedAt, ConfirmedAt: value.ConfirmedAt, CompletedAt: value.CompletedAt}
}
func pairingFromModel(value PairingModel) connectors.Pairing {
	return connectors.Pairing{ID: value.ID, SecretHash: value.SecretHash, UserCodeHash: value.UserCodeHash, ConnectorName: value.ConnectorName, ConnectorIdentity: connectors.PublicIdentity{Version: value.ConnectorIdentityVersion, Suite: value.ConnectorIdentitySuite, KeyID: value.ConnectorKeyID, PublicKey: value.ConnectorPublicKey}, ConnectorCredentialHash: value.ConnectorCredentialHash, State: value.State, UserID: value.UserID, DeviceID: value.DeviceID, ConnectorID: value.ConnectorID, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt, ConnectorReviewedAt: value.ConnectorReviewedAt, ConfirmedAt: value.ConfirmedAt, CompletedAt: value.CompletedAt}
}

func trustModel(value connectors.Trust) *TrustModel {
	return &TrustModel{UserID: value.UserID, DeviceID: value.DeviceID, ConnectorID: value.ConnectorID, CreatedAt: value.CreatedAt, RevokedAt: value.RevokedAt}
}

func relayTicketModel(value connectors.RelayTicket) *RelayTicketModel {
	return &RelayTicketModel{TokenHash: value.TokenHash, UserID: value.UserID, Role: value.Role, SubjectID: value.SubjectID, SubjectKeyID: value.SubjectKeyID, CredentialID: value.CredentialID, AuthorizationExpiresAt: value.AuthorizationExpiresAt, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt, ConsumedAt: value.ConsumedAt}
}
func relayTicketFromModel(value RelayTicketModel) connectors.RelayTicket {
	return connectors.RelayTicket{TokenHash: value.TokenHash, UserID: value.UserID, Role: value.Role, SubjectID: value.SubjectID, SubjectKeyID: value.SubjectKeyID, CredentialID: value.CredentialID, AuthorizationExpiresAt: value.AuthorizationExpiresAt, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt, ConsumedAt: value.ConsumedAt}
}

func translateError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, gorm.ErrRecordNotFound):
		return connectors.ErrNotFound
	case errors.Is(err, gorm.ErrDuplicatedKey), errors.Is(err, gorm.ErrForeignKeyViolated), errors.Is(err, gorm.ErrCheckConstraintViolated):
		return connectors.ErrConflict
	default:
		return err
	}
}
