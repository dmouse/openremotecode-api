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

func (store *revocationStore) PairingBySecretForUpdate(_ context.Context, hash []byte) (Pairing, error) {
	for _, pairing := range store.pairings {
		if bytes.Equal(pairing.SecretHash, hash) {
			return pairing, nil
		}
	}
	return Pairing{}, ErrNotFound
}

func (store *revocationStore) PairingByIDForUpdate(_ context.Context, id string) (Pairing, error) {
	if pairing, ok := store.pairings[id]; ok {
		return pairing, nil
	}
	return Pairing{}, ErrNotFound
}

func (store *revocationStore) SavePairing(_ context.Context, pairing Pairing) error {
	store.pairings[pairing.ID] = pairing
	return nil
}

func (store *revocationStore) ConnectorByKeyIDForUpdate(_ context.Context, keyID string) (Connector, error) {
	for _, connector := range store.connectors {
		if connector.Identity.KeyID == keyID {
			return connector, nil
		}
	}
	return Connector{}, ErrNotFound
}

func (store *revocationStore) CreateConnector(_ context.Context, connector Connector) error {
	store.connectors[connector.ID] = connector
	return nil
}

func (store *revocationStore) UpsertTrust(_ context.Context, trust Trust) error {
	store.trusts = append(store.trusts, trust)
	return nil
}

const approvalPairingSecret = "orp_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// approvalFixture is a pairing that dev_a (usr_a) has claimed and is now in verification:
// the state in which the person at OpenCode is shown the safety code.
func approvalFixture(t *testing.T) (*Service, *revocationStore) {
	t.Helper()
	service, store, _ := deviceRevocationFixture()
	service.random = rand.Reader
	service.deviceCredentialKey = []byte(strings.Repeat("k", 32))
	service.deviceCredentialLifetime = 365 * 24 * time.Hour
	service.connectorCredentialLifetime = 90 * 24 * time.Hour
	now := service.now()
	store.pairings = map[string]Pairing{"par_a": {
		ID: "par_a", SecretHash: hashSecret(approvalPairingSecret), State: PairingStateVerification,
		ConnectorName: "Laptop", ConnectorIdentity: PublicIdentity{KeyID: "connector_key_new"},
		ConnectorCredentialHash: hashSecret(deriveConnectorCredential(approvalPairingSecret)),
		UserID:                  stringPointer("usr_a"), DeviceID: stringPointer("dev_a"),
		CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}}
	return service, store
}

// The finding this guards: an account that learned or guessed the user code could claim the
// pairing and confirm it from its own phone, binding someone else's OpenCode to itself.
func TestConfirmationRequiresExplicitConnectorApproval(t *testing.T) {
	service, store := approvalFixture(t)
	ctx := context.Background()
	if _, err := service.PollPairing(ctx, approvalPairingSecret); err != nil {
		t.Fatal(err)
	}
	if store.pairings["par_a"].ConnectorReviewedAt != nil {
		t.Fatal("polling the transcript approved the pairing on its own")
	}
	if _, err := service.ConfirmPairing(ctx, "usr_a", "par_a", "dev_a"); !errors.Is(err, ErrConflict) {
		t.Fatalf("confirmation without approval = %v, want ErrConflict", err)
	}

	for range 2 {
		if err := service.ApprovePairing(ctx, "par_a", approvalPairingSecret, "device_key_a"); err != nil {
			t.Fatalf("approve: %v", err)
		}
	}
	if len(store.audits) != 1 || store.audits[0].EventType != "pairing.connector_approved" {
		t.Fatalf("approval audit missing or duplicated: %+v", store.audits)
	}
	if _, err := service.ConfirmPairing(ctx, "usr_a", "par_a", "dev_a"); err != nil {
		t.Fatalf("confirmation after approval: %v", err)
	}
}

func TestApprovalIsBoundToTheSecretAndTheReviewedDevice(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, pairingID, secret, deviceKeyID string
		want                                 error
	}{
		{"wrong secret", "par_a", "orp_" + strings.Repeat("B", 43), "device_key_a", ErrUnauthorized},
		{"malformed secret", "par_a", "not-a-secret", "device_key_a", ErrUnauthorized},
		{"secret for another pairing", "par_other", approvalPairingSecret, "device_key_a", ErrUnauthorized},
		{"a device the connector was not shown", "par_a", approvalPairingSecret, "device_key_b", ErrConflict},
		{"missing device key", "par_a", approvalPairingSecret, "", ErrInvalidInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, store := approvalFixture(t)
			if err := service.ApprovePairing(ctx, tc.pairingID, tc.secret, tc.deviceKeyID); !errors.Is(err, tc.want) {
				t.Fatalf("approve = %v, want %v", err, tc.want)
			}
			if store.pairings["par_a"].ConnectorReviewedAt != nil || len(store.audits) != 0 {
				t.Fatal("a refused approval changed state")
			}
		})
	}

	service, store := approvalFixture(t)
	pending := store.pairings["par_a"]
	pending.State, pending.DeviceID = PairingStatePending, nil
	store.pairings["par_a"] = pending
	if err := service.ApprovePairing(ctx, "par_a", approvalPairingSecret, "device_key_a"); !errors.Is(err, ErrConflict) {
		t.Fatalf("approval before any device claimed = %v, want ErrConflict", err)
	}
}

// Rejecting in OpenCode cancels the pairing; the phone must then hear that it is over, not
// that it should keep waiting for an approval that will never come.
func TestRejectedPairingReportsExpiredToThePhone(t *testing.T) {
	service, store := approvalFixture(t)
	ctx := context.Background()
	if err := service.CancelPairing(ctx, "par_a", approvalPairingSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := service.ConfirmPairing(ctx, "usr_a", "par_a", "dev_a"); !errors.Is(err, ErrExpired) {
		t.Fatalf("confirmation of a rejected pairing = %v, want ErrExpired", err)
	}
	if err := service.ApprovePairing(ctx, "par_a", approvalPairingSecret, "device_key_a"); !errors.Is(err, ErrExpired) {
		t.Fatalf("approval of a rejected pairing = %v, want ErrExpired", err)
	}
	if store.pairings["par_a"].ConnectorReviewedAt != nil {
		t.Fatal("a rejected pairing was approved")
	}
}

func TestApprovalAfterExpiryFails(t *testing.T) {
	service, store := approvalFixture(t)
	later := service.now().Add(11 * time.Minute)
	service.now = func() time.Time { return later }
	if err := service.ApprovePairing(context.Background(), "par_a", approvalPairingSecret, "device_key_a"); !errors.Is(err, ErrExpired) {
		t.Fatalf("late approval = %v, want ErrExpired", err)
	}
	if store.pairings["par_a"].State != PairingStateExpired {
		t.Fatal("a late approval left the pairing open")
	}
}

// Each confirmation issues a fresh random credential; a retry of the same confirmation gets
// the same one back; and pairing again can never restore a credential the device rotated away.
func TestDeviceCredentialIsRandomPerPairingAndStableAcrossRetries(t *testing.T) {
	service, store := approvalFixture(t)
	ctx := context.Background()
	if err := service.ApprovePairing(ctx, "par_a", approvalPairingSecret, "device_key_a"); err != nil {
		t.Fatal(err)
	}
	first, err := service.ConfirmPairing(ctx, "usr_a", "par_a", "dev_a")
	if err != nil {
		t.Fatal(err)
	}
	if !validToken(first.DeviceCredential, "ord_") {
		t.Fatalf("issued credential is not a device token: %q", first.DeviceCredential)
	}
	if len(store.pairings["par_a"].DeviceCredentialSeed) != deviceCredentialSeedLength {
		t.Fatal("the pairing did not keep the seed its credential came from")
	}
	retried, err := service.ConfirmPairing(ctx, "usr_a", "par_a", "dev_a")
	if err != nil || retried.DeviceCredential != first.DeviceCredential {
		t.Fatalf("retried confirmation returned a different credential: %v", err)
	}

	// The device rotates. Retrying the old confirmation must not hand back the retired value.
	rotated := store.devices["dev_a"]
	rotated.CredentialHash = hashSecret("ord_" + strings.Repeat("R", 43))
	store.devices["dev_a"] = rotated
	if _, err := service.ConfirmPairing(ctx, "usr_a", "par_a", "dev_a"); !errors.Is(err, ErrConflict) {
		t.Fatalf("retry after rotation = %v, want ErrConflict", err)
	}

	// A second pairing for the same device draws a new credential, not the first one again.
	now := service.now()
	store.pairings["par_b"] = Pairing{
		ID: "par_b", SecretHash: hashSecret("orp_" + strings.Repeat("C", 43)), State: PairingStateVerification,
		ConnectorName: "Desktop", ConnectorIdentity: PublicIdentity{KeyID: "connector_key_other"},
		ConnectorCredentialHash: hashSecret(deriveConnectorCredential("orp_" + strings.Repeat("C", 43))),
		UserID:                  stringPointer("usr_a"), DeviceID: stringPointer("dev_a"),
		CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), ConnectorReviewedAt: &now,
	}
	second, err := service.ConfirmPairing(ctx, "usr_a", "par_b", "dev_a")
	if err != nil {
		t.Fatal(err)
	}
	if second.DeviceCredential == first.DeviceCredential {
		t.Fatal("re-pairing restored a previously issued credential")
	}
	if !bytes.Equal(store.devices["dev_a"].CredentialHash, hashSecret(second.DeviceCredential)) {
		t.Fatal("the device does not hold the newly issued credential")
	}
}
