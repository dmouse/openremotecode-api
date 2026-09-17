package connectors

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type revocationStore struct {
	TransactionStore
	connectors map[string]Connector
	devices    map[string]Device
	audits     []AuditEvent
	auditError error
}

func (store *revocationStore) ConnectorByCredentialForUpdate(_ context.Context, hash []byte) (Connector, error) {
	for _, connector := range store.connectors {
		if bytes.Equal(connector.CredentialHash, hash) {
			return connector, nil
		}
	}
	return Connector{}, ErrNotFound
}

func (store *revocationStore) ConnectorByIDForUpdate(_ context.Context, id string) (Connector, error) {
	if connector, ok := store.connectors[id]; ok {
		return connector, nil
	}
	return Connector{}, ErrNotFound
}

func (store *revocationStore) SaveConnector(_ context.Context, connector Connector) error {
	store.connectors[connector.ID] = connector
	return nil
}

func (store *revocationStore) AppendAuditEvent(_ context.Context, event AuditEvent) error {
	if store.auditError != nil {
		return store.auditError
	}
	store.audits = append(store.audits, event)
	return nil
}

type revocationRepository struct {
	Repository
	store *revocationStore
}

func (repository revocationRepository) WithinTransaction(_ context.Context, operation func(TransactionStore) error) error {
	copy := *repository.store
	copy.connectors = make(map[string]Connector)
	for id, connector := range repository.store.connectors {
		copy.connectors[id] = connector
	}
	copy.devices = make(map[string]Device)
	for id, device := range repository.store.devices {
		copy.devices[id] = device
	}
	if err := operation(&copy); err != nil {
		return err
	}
	*repository.store = copy
	return nil
}

func revocationFixture() (*Service, *revocationStore, string, Admission) {
	now := time.Now().UTC()
	expires := now.Add(time.Hour)
	credential := "orc_" + strings.Repeat("A", 43)
	connector := Connector{ID: "con_a", UserID: "usr_a", Identity: PublicIdentity{KeyID: "key_a"}, CredentialHash: hashSecret(credential), CredentialExpiresAt: &expires}
	store := &revocationStore{connectors: map[string]Connector{
		"con_a": connector,
		"con_b": {ID: "con_b", UserID: "usr_b", CredentialHash: hashSecret("orc_" + strings.Repeat("B", 43)), CredentialExpiresAt: &expires},
	}}
	service := &Service{repository: revocationRepository{store: store}, now: func() time.Time { return now }, authorizeAccount: func(context.Context, string) error { return nil }}
	return service, store, credential, Admission{Role: RelayRoleConnector, UserID: connector.UserID, SubjectID: connector.ID, Identity: connector.Identity}
}

func TestRevokeConnectorIsScopedIdempotentAndInvalidatesAdmission(t *testing.T) {
	service, store, credential, admission := revocationFixture()
	ctx := context.Background()
	if err := service.ValidateConnectorAdmission(ctx, admission); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := service.RevokeConnector(ctx, credential); err != nil {
			t.Fatal(err)
		}
	}
	if store.connectors["con_a"].RevokedAt == nil || store.connectors["con_b"].RevokedAt != nil {
		t.Fatal("revocation crossed connector/account boundary")
	}
	if len(store.audits) != 1 || store.audits[0].EventType != "connector.revoked" || *store.audits[0].UserID != "usr_a" || *store.audits[0].ConnectorID != "con_a" {
		t.Fatal("missing or duplicated scoped audit")
	}
	if err := service.ValidateConnectorAdmission(ctx, admission); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked admission accepted: %v", err)
	}
}

func TestRevokeConnectorRejectsWrongOrExpiredCredentials(t *testing.T) {
	for _, credential := range []string{"", "access-token", "ord_" + strings.Repeat("A", 43), "orc_" + strings.Repeat("C", 43)} {
		service, store, _, _ := revocationFixture()
		if err := service.RevokeConnector(context.Background(), credential); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("invalid credential accepted: %v", err)
		}
		if len(store.audits) != 0 || store.connectors["con_a"].RevokedAt != nil {
			t.Fatal("invalid credential changed state")
		}
	}
	service, store, credential, _ := revocationFixture()
	connector := store.connectors["con_a"]
	expired := time.Now().Add(-time.Hour)
	connector.CredentialExpiresAt = &expired
	store.connectors[connector.ID] = connector
	if err := service.RevokeConnector(context.Background(), credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired credential accepted: %v", err)
	}
}

func TestRevocationRollsBackWhenAuditFails(t *testing.T) {
	service, store, credential, _ := revocationFixture()
	store.auditError = errors.New("database failure")
	if err := service.RevokeConnector(context.Background(), credential); err == nil {
		t.Fatal("expected failure")
	}
	if store.connectors["con_a"].RevokedAt != nil {
		t.Fatal("revocation committed without its audit event")
	}
}

func TestAccountRevocationChecksOwnershipAndInvalidatesAdmission(t *testing.T) {
	service, store, _, admission := revocationFixture()
	ctx := context.Background()
	for _, id := range []string{"con_b", "missing"} {
		if err := service.RevokeAccountConnector(ctx, "usr_a", id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign and missing connectors must be indistinguishable: %v", err)
		}
	}
	if len(store.audits) != 0 || store.connectors["con_b"].RevokedAt != nil {
		t.Fatal("failed authorization changed state")
	}
	for range 2 {
		if err := service.RevokeAccountConnector(ctx, "usr_a", "con_a"); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.audits) != 1 || store.connectors["con_a"].RevokedAt == nil {
		t.Fatal("revocation must be durable and idempotent")
	}
	if err := service.ValidateConnectorAdmission(ctx, admission); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked connector still admitted: %v", err)
	}
}

func TestAccountRevocationFailsClosedAndRollsBackAuditFailure(t *testing.T) {
	service, store, _, _ := revocationFixture()
	ctx := context.Background()
	service.authorizeAccount = func(context.Context, string) error { return ErrUnauthorized }
	if err := service.RevokeAccountConnector(ctx, "usr_a", "con_a"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("disabled account allowed to revoke")
	}
	service.authorizeAccount = func(context.Context, string) error { return nil }
	store.auditError = errors.New("audit unavailable")
	if err := service.RevokeAccountConnector(ctx, "usr_a", "con_a"); err == nil {
		t.Fatal("expected audit failure")
	}
	if store.connectors["con_a"].RevokedAt != nil {
		t.Fatal("committed without audit")
	}
	store.auditError = nil
	connector := store.connectors["con_a"]
	expired := time.Now().Add(-time.Hour)
	connector.CredentialExpiresAt = &expired
	store.connectors[connector.ID] = connector
	if err := service.RevokeAccountConnector(ctx, "usr_a", "con_a"); err != nil {
		t.Fatal("owner cannot remove expired connector")
	}
}

func TestAccountRenamePreservesTrustAndPersistsOnlyForOwner(t *testing.T) {
	service, store, _, admission := revocationFixture()
	ctx := context.Background()
	before := store.connectors["con_a"]
	for _, id := range []string{"con_b", "missing"} {
		if _, err := service.RenameAccountConnector(ctx, "usr_a", id, "Work laptop"); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign/missing rename must fail")
		}
	}
	for _, name := range []string{"", "  ", strings.Repeat("a", 65), strings.Repeat("é", 33)} {
		if _, err := service.RenameAccountConnector(ctx, "usr_a", "con_a", name); !errors.Is(err, ErrInvalidInput) {
			t.Fatal("invalid name accepted")
		}
	}
	for range 2 {
		result, err := service.RenameAccountConnector(ctx, "usr_a", "con_a", "  Work laptop  ")
		if err != nil || result.Name != "Work laptop" {
			t.Fatalf("rename failed: %v", err)
		}
	}
	after := store.connectors["con_a"]
	if after.Identity != before.Identity || !bytes.Equal(after.CredentialHash, before.CredentialHash) || after.RevokedAt != nil {
		t.Fatal("rename changed identity or access")
	}
	if len(store.audits) != 1 || store.audits[0].EventType != "connector.renamed" {
		t.Fatal("missing or duplicated audit")
	}
	if err := service.ValidateConnectorAdmission(ctx, admission); err != nil {
		t.Fatal("rename broke existing admission")
	}
	store.auditError = errors.New("audit unavailable")
	if _, err := service.RenameAccountConnector(ctx, "usr_a", "con_a", "Another name"); err == nil {
		t.Fatal("audit failure accepted")
	}
	if store.connectors["con_a"].Name != "Work laptop" {
		t.Fatal("name committed without audit")
	}
	store.auditError = nil
	if err := service.RevokeAccountConnector(ctx, "usr_a", "con_a"); err != nil {
		t.Fatal(err)
	}
	if _, err := service.RenameAccountConnector(ctx, "usr_a", "con_a", "Revived"); !errors.Is(err, ErrNotFound) {
		t.Fatal("revoked connector renamed")
	}
}

func TestConnectorAdmissionRejectsMismatchedAccountAndIdentity(t *testing.T) {
	service, _, _, admission := revocationFixture()
	for _, modify := range []func(*Admission){
		func(a *Admission) { a.UserID = "usr_b" },
		func(a *Admission) { a.Identity.KeyID = "key_b" },
		func(a *Admission) { a.SubjectID = "con_b" },
		func(a *Admission) { a.Role = RelayRoleClient },
	} {
		candidate := admission
		modify(&candidate)
		if err := service.ValidateConnectorAdmission(context.Background(), candidate); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("mismatched admission accepted: %v", err)
		}
	}
}

func TestOwnConnectorMetadataIsCredentialScopedAndRejectsRevocation(t *testing.T) {
	service, store, credential, _ := revocationFixture()
	ctx := context.Background()
	connector := store.connectors["con_a"]
	connector.CreatedAt = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	store.connectors[connector.ID] = connector
	result, err := service.OwnConnector(ctx, credential)
	if err != nil || result.ID != "con_a" || !result.CreatedAt.Equal(connector.CreatedAt) {
		t.Fatalf("wrong own metadata: %v", err)
	}
	other, err := service.OwnConnector(ctx, "orc_"+strings.Repeat("B", 43))
	if err != nil || other.ID != "con_b" || other.UserID != "usr_b" {
		t.Fatalf("metadata crossed accounts: %v", err)
	}
	for _, token := range []string{"", "ord_" + strings.Repeat("A", 43), "orc_" + strings.Repeat("C", 43)} {
		if _, err := service.OwnConnector(ctx, token); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("invalid credential accepted: %v", err)
		}
	}
	if err := service.RevokeConnector(ctx, credential); err != nil {
		t.Fatal(err)
	}
	if _, err := service.OwnConnector(ctx, credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked credential accepted: %v", err)
	}
	service.authorizeAccount = func(context.Context, string) error { return ErrUnauthorized }
	if _, err := service.OwnConnector(ctx, "orc_"+strings.Repeat("B", 43)); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("disabled account accepted: %v", err)
	}
}
