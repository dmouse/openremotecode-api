package connectors

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

func (store *revocationStore) CreateRelayTicket(context.Context, RelayTicket) error { return nil }

func (store *revocationStore) ConnectorByAnyCredentialForUpdate(_ context.Context, hash []byte) (Connector, error) {
	for _, connector := range store.connectors {
		if bytes.Equal(connector.CredentialHash, hash) ||
			(connector.PendingCredentialHash != nil && bytes.Equal(connector.PendingCredentialHash, hash)) {
			return connector, nil
		}
	}
	return Connector{}, ErrNotFound
}

func rotationFixture(t *testing.T) (*Service, *revocationStore, string, *time.Time) {
	t.Helper()
	service, store, credential, _ := revocationFixture()
	service.random = rand.Reader
	service.connectorCredentialLifetime = defaultConnectorCredentialLifetime
	service.credentialActivationWindow = defaultCredentialActivationWindow
	current := store.connectors["con_a"].CredentialExpiresAt
	return service, store, credential, current
}

func auditTypes(store *revocationStore) []string {
	types := make([]string, 0, len(store.audits))
	for _, event := range store.audits {
		types = append(types, event.EventType)
	}
	return types
}

func TestRotationLeavesTheCurrentCredentialWorkingUntilActivated(t *testing.T) {
	service, store, credential, originalExpiry := rotationFixture(t)
	ctx := context.Background()

	rotation, err := service.RotateConnectorCredential(ctx, credential)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rotation.Credential, "orc_") || rotation.Credential == credential {
		t.Fatalf("rotation did not issue a fresh credential: %q", rotation.Credential)
	}

	// The pending credential grants nothing on its own.
	stored := store.connectors["con_a"]
	if !bytes.Equal(stored.CredentialHash, hashSecret(credential)) {
		t.Fatal("rotation replaced the live credential before activation")
	}
	if stored.CredentialExpiresAt != originalExpiry {
		t.Fatal("rotation changed the live credential's expiry")
	}
	if stored.PendingCredentialHash == nil || !bytes.Equal(stored.PendingCredentialHash, hashSecret(rotation.Credential)) {
		t.Fatal("pending credential was not recorded")
	}

	expiresAt, err := service.ActivateConnectorCredential(ctx, rotation.Credential)
	if err != nil {
		t.Fatal(err)
	}
	// The lifetime starts at activation, not at rotation.
	if want := service.now().UTC().Add(defaultConnectorCredentialLifetime); !expiresAt.Equal(want) {
		t.Fatalf("expiry %v does not start at activation (%v)", expiresAt, want)
	}
	stored = store.connectors["con_a"]
	if !bytes.Equal(stored.CredentialHash, hashSecret(rotation.Credential)) || stored.PendingCredentialHash != nil {
		t.Fatal("activation did not commit the pending credential")
	}

	// The superseded credential is refused once the rotation is committed.
	if _, err := service.RotateConnectorCredential(ctx, credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("superseded credential still accepted: %v", err)
	}
	if want := []string{"connector.credential.rotated", "connector.credential.activated"}; !equalStrings(auditTypes(store), want) {
		t.Fatalf("unexpected audit trail %v", auditTypes(store))
	}
}

func TestUsingTheCurrentCredentialCancelsAnUnactivatedRotation(t *testing.T) {
	service, store, credential, originalExpiry := rotationFixture(t)
	ctx := context.Background()

	rotation, err := service.RotateConnectorCredential(ctx, credential)
	if err != nil {
		t.Fatal(err)
	}
	// The plugin crashed before persisting, so it reconnects on its current credential.
	if _, err := service.IssueConnectorTicket(ctx, credential); err != nil {
		t.Fatal(err)
	}
	stored := store.connectors["con_a"]
	if stored.PendingCredentialHash != nil {
		t.Fatal("reconnecting on the current credential did not cancel the rotation")
	}
	if !bytes.Equal(stored.CredentialHash, hashSecret(credential)) || stored.CredentialExpiresAt != originalExpiry {
		t.Fatal("cancellation disturbed the live credential")
	}
	// The abandoned credential cannot be activated afterwards.
	if _, err := service.ActivateConnectorCredential(ctx, rotation.Credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cancelled rotation still activatable: %v", err)
	}
	if want := []string{"connector.credential.rotated", "connector.credential.rotation_cancelled"}; !equalStrings(auditTypes(store), want) {
		t.Fatalf("unexpected audit trail %v", auditTypes(store))
	}

	// Rotation remains available, so a cancelled attempt is not a dead end.
	if _, err := service.RotateConnectorCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
}

func TestUnactivatedRotationLapsesWithoutInvalidatingAnything(t *testing.T) {
	service, store, credential, originalExpiry := rotationFixture(t)
	ctx := context.Background()
	start := service.now().UTC()

	rotation, err := service.RotateConnectorCredential(ctx, credential)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return start.Add(defaultCredentialActivationWindow + time.Second) }

	if _, err := service.ActivateConnectorCredential(ctx, rotation.Credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("lapsed rotation was activated: %v", err)
	}
	stored := store.connectors["con_a"]
	if !bytes.Equal(stored.CredentialHash, hashSecret(credential)) || stored.CredentialExpiresAt != originalExpiry {
		t.Fatal("a lapsed rotation invalidated the live credential")
	}
	if _, err := service.IssueConnectorTicket(ctx, credential); err != nil {
		t.Fatalf("current credential stopped working after a lapsed rotation: %v", err)
	}
}

func TestActivationIsIdempotentAfterALostResponse(t *testing.T) {
	service, store, credential, _ := rotationFixture(t)
	ctx := context.Background()

	rotation, err := service.RotateConnectorCredential(ctx, credential)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.ActivateConnectorCredential(ctx, rotation.Credential)
	if err != nil {
		t.Fatal(err)
	}
	// The plugin never saw the response and retries with the same credential.
	second, err := service.ActivateConnectorCredential(ctx, rotation.Credential)
	if err != nil {
		t.Fatalf("retried activation rejected: %v", err)
	}
	if !first.Equal(second) {
		t.Fatalf("retry moved the expiry from %v to %v", first, second)
	}
	if got := auditTypes(store); len(got) != 2 {
		t.Fatalf("retry produced a duplicate audit event: %v", got)
	}
}

func TestRotationRejectsInvalidExpiredAndRevokedCredentials(t *testing.T) {
	for _, credential := range []string{"", "access-token", "ord_" + strings.Repeat("A", 43), "orc_" + strings.Repeat("C", 43)} {
		service, store, _, _ := rotationFixture(t)
		if _, err := service.RotateConnectorCredential(context.Background(), credential); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("invalid credential accepted: %v", err)
		}
		if len(store.audits) != 0 || store.connectors["con_a"].PendingCredentialHash != nil {
			t.Fatal("invalid credential changed state")
		}
	}

	service, store, credential, _ := rotationFixture(t)
	expired := service.now().UTC().Add(-time.Second)
	connector := store.connectors["con_a"]
	connector.CredentialExpiresAt = &expired
	store.connectors["con_a"] = connector
	if _, err := service.RotateConnectorCredential(context.Background(), credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired credential rotated: %v", err)
	}

	service, store, credential, _ = rotationFixture(t)
	revoked := service.now().UTC()
	connector = store.connectors["con_a"]
	connector.RevokedAt = &revoked
	store.connectors["con_a"] = connector
	if _, err := service.RotateConnectorCredential(context.Background(), credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked connector rotated: %v", err)
	}
}

func TestRotationDoesNotCrossConnectorBoundaries(t *testing.T) {
	service, store, credential, _ := rotationFixture(t)
	ctx := context.Background()
	if _, err := service.RotateConnectorCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	if other := store.connectors["con_b"]; other.PendingCredentialHash != nil || other.RevokedAt != nil {
		t.Fatal("rotation touched another account's connector")
	}
	for _, event := range store.audits {
		if *event.ConnectorID != "con_a" || *event.UserID != "usr_a" {
			t.Fatalf("audit attributed to the wrong connector: %+v", event)
		}
	}
}

func TestRotationKeepsALiveAdmissionValid(t *testing.T) {
	service, _, credential, _ := rotationFixture(t)
	ctx := context.Background()
	_, _, _, admission := revocationFixture()

	rotation, err := service.RotateConnectorCredential(ctx, credential)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.ValidateConnectorAdmission(ctx, admission); err != nil {
		t.Fatalf("pending rotation closed a live connection: %v", err)
	}
	if _, err := service.ActivateConnectorCredential(ctx, rotation.Credential); err != nil {
		t.Fatal(err)
	}
	if err := service.ValidateConnectorAdmission(ctx, admission); err != nil {
		t.Fatalf("activation closed a live connection: %v", err)
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
