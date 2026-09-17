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

func (store *revocationStore) DeviceByCredentialForUpdate(_ context.Context, hash []byte) (Device, error) {
	for _, device := range store.devices {
		if bytes.Equal(device.CredentialHash, hash) {
			return device, nil
		}
	}
	return Device{}, ErrNotFound
}

func (store *revocationStore) DeviceByAnyCredentialForUpdate(_ context.Context, hash []byte) (Device, error) {
	for _, device := range store.devices {
		if bytes.Equal(device.CredentialHash, hash) ||
			(device.PendingCredentialHash != nil && bytes.Equal(device.PendingCredentialHash, hash)) {
			return device, nil
		}
	}
	return Device{}, ErrNotFound
}

func (store *revocationStore) SaveDevice(_ context.Context, device Device) error {
	store.devices[device.ID] = device
	return nil
}

const (
	deviceID      = "dev_a"
	deviceSession = "ses_a"
)

func deviceFixture(t *testing.T) (*Service, *revocationStore, string, *time.Time) {
	t.Helper()
	service, store, _, _ := revocationFixture()
	service.random = rand.Reader
	service.deviceCredentialLifetime = defaultDeviceCredentialLifetime
	service.credentialActivationWindow = defaultCredentialActivationWindow
	service.authorizeSession = func(context.Context, string, string) error { return nil }

	now := service.now().UTC()
	expires := now.Add(time.Hour)
	activated := now.Add(-time.Hour)
	credential := "ord_" + strings.Repeat("A", 43)
	store.devices = map[string]Device{
		deviceID: {
			ID: deviceID, UserID: "usr_a", Identity: PublicIdentity{KeyID: "dkey_a"},
			CredentialHash: hashSecret(credential), CredentialExpiresAt: &expires, ActivatedAt: &activated,
		},
	}
	return service, store, credential, &expires
}

func TestDeviceRotationLeavesTheCurrentCredentialWorkingUntilActivated(t *testing.T) {
	service, store, credential, originalExpiry := deviceFixture(t)
	ctx := context.Background()

	rotation, err := service.RotateDeviceCredential(ctx, "usr_a", deviceSession, deviceID, credential)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rotation.Credential, "ord_") || rotation.Credential == credential {
		t.Fatalf("rotation did not issue a fresh credential: %q", rotation.Credential)
	}

	stored := store.devices[deviceID]
	if !bytes.Equal(stored.CredentialHash, hashSecret(credential)) || stored.CredentialExpiresAt != originalExpiry {
		t.Fatal("rotation disturbed the live credential before activation")
	}
	if stored.PendingCredentialHash == nil || !bytes.Equal(stored.PendingCredentialHash, hashSecret(rotation.Credential)) {
		t.Fatal("pending credential was not recorded")
	}

	expiresAt, err := service.ActivateDeviceCredential(ctx, "usr_a", deviceSession, deviceID, rotation.Credential)
	if err != nil {
		t.Fatal(err)
	}
	// The lifetime starts at activation, not at rotation.
	if want := service.now().UTC().Add(defaultDeviceCredentialLifetime); !expiresAt.Equal(want) {
		t.Fatalf("expiry %v does not start at activation (%v)", expiresAt, want)
	}
	stored = store.devices[deviceID]
	if !bytes.Equal(stored.CredentialHash, hashSecret(rotation.Credential)) || stored.PendingCredentialHash != nil {
		t.Fatal("activation did not commit the pending credential")
	}
	if _, err := service.RotateDeviceCredential(ctx, "usr_a", deviceSession, deviceID, credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("superseded credential still accepted: %v", err)
	}
}

func TestDeviceRotationRequiresAllThreeFactors(t *testing.T) {
	ctx := context.Background()
	// The device ID is never the sole authority: the account, the session, and the current
	// credential must agree, mirroring ticket issuance.
	for _, tc := range []struct{ name, user, session, device, credential string }{
		{"wrong account", "usr_other", deviceSession, deviceID, ""},
		{"missing session", "usr_a", "", deviceID, ""},
		{"wrong device", "usr_a", deviceSession, "dev_other", ""},
		{"foreign credential", "usr_a", deviceSession, deviceID, "ord_" + strings.Repeat("Z", 43)},
		{"connector credential", "usr_a", deviceSession, deviceID, "orc_" + strings.Repeat("A", 43)},
		{"not a token", "usr_a", deviceSession, deviceID, "device-cookie"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, store, credential, _ := deviceFixture(t)
			if tc.credential != "" {
				credential = tc.credential
			}
			if _, err := service.RotateDeviceCredential(ctx, tc.user, tc.session, tc.device, credential); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("accepted: %v", err)
			}
			if store.devices[deviceID].PendingCredentialHash != nil {
				t.Fatal("a rejected request still staged a rotation")
			}
		})
	}
}

func TestIssuingATicketCancelsAnUnactivatedDeviceRotation(t *testing.T) {
	service, store, credential, originalExpiry := deviceFixture(t)
	ctx := context.Background()

	rotation, err := service.RotateDeviceCredential(ctx, "usr_a", deviceSession, deviceID, credential)
	if err != nil {
		t.Fatal(err)
	}
	// The app was killed before persisting, so it reconnects on its current credential.
	if _, err := service.IssueBrowserTicket(ctx, "usr_a", deviceSession, deviceID, credential, service.now().UTC().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	stored := store.devices[deviceID]
	if stored.PendingCredentialHash != nil {
		t.Fatal("using the current credential did not cancel the rotation")
	}
	if !bytes.Equal(stored.CredentialHash, hashSecret(credential)) || stored.CredentialExpiresAt != originalExpiry {
		t.Fatal("cancellation disturbed the live credential")
	}
	if _, err := service.ActivateDeviceCredential(ctx, "usr_a", deviceSession, deviceID, rotation.Credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cancelled rotation still activatable: %v", err)
	}
	if _, err := service.RotateDeviceCredential(ctx, "usr_a", deviceSession, deviceID, credential); err != nil {
		t.Fatalf("rotation became a dead end: %v", err)
	}
}

func TestUnactivatedDeviceRotationLapsesWithoutInvalidatingAnything(t *testing.T) {
	service, store, credential, originalExpiry := deviceFixture(t)
	ctx := context.Background()
	start := service.now().UTC()

	rotation, err := service.RotateDeviceCredential(ctx, "usr_a", deviceSession, deviceID, credential)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return start.Add(defaultCredentialActivationWindow + time.Second) }

	if _, err := service.ActivateDeviceCredential(ctx, "usr_a", deviceSession, deviceID, rotation.Credential); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("lapsed rotation was activated: %v", err)
	}
	stored := store.devices[deviceID]
	if !bytes.Equal(stored.CredentialHash, hashSecret(credential)) || stored.CredentialExpiresAt != originalExpiry {
		t.Fatal("a lapsed rotation invalidated the live credential")
	}
}

func TestDeviceActivationIsIdempotentAfterALostResponse(t *testing.T) {
	service, _, credential, _ := deviceFixture(t)
	ctx := context.Background()

	rotation, err := service.RotateDeviceCredential(ctx, "usr_a", deviceSession, deviceID, credential)
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.ActivateDeviceCredential(ctx, "usr_a", deviceSession, deviceID, rotation.Credential)
	if err != nil {
		t.Fatal(err)
	}
	// A phone is killed routinely, so a retried activation must not move the expiry.
	second, err := service.ActivateDeviceCredential(ctx, "usr_a", deviceSession, deviceID, rotation.Credential)
	if err != nil {
		t.Fatalf("retried activation rejected: %v", err)
	}
	if !first.Equal(second) {
		t.Fatalf("retry moved the expiry from %v to %v", first, second)
	}
}

func TestDeviceCredentialKeyIsSeparateFromTheUserCodeKey(t *testing.T) {
	base := ServiceOptions{
		PairingCodeKey: []byte(strings.Repeat("p", 32)), ServiceID: "svc", VerificationURI: "https://example.test",
		AuthorizeAccount: func(context.Context, string) error { return nil },
		AuthorizeSession: func(context.Context, string, string) error { return nil },
	}
	seeded, err := NewService(revocationRepository{store: &revocationStore{}}, base)
	if err != nil {
		t.Fatal(err)
	}
	// Unset, it seeds from the pairing key so an existing deployment's devices stay valid.
	if !bytes.Equal(seeded.deviceCredentialKey, seeded.pairingCodeKey) {
		t.Fatal("an unset device key did not seed from the pairing key")
	}

	split := base
	split.DeviceCredentialKey = []byte(strings.Repeat("d", 32))
	separate, err := NewService(revocationRepository{store: &revocationStore{}}, split)
	if err != nil {
		t.Fatal(err)
	}
	// Once separate, rotating one key cannot disturb what the other derives.
	if bytes.Equal(separate.deviceCredentialKey, separate.pairingCodeKey) {
		t.Fatal("the device key was not kept separate")
	}
	if seeded.deriveDeviceCredential("dkey_a") == separate.deriveDeviceCredential("dkey_a") {
		t.Fatal("device credentials did not follow the device key")
	}
	if seeded.hashUserCode("ABCD-EFGH") == nil ||
		!bytes.Equal(seeded.hashUserCode("ABCD-EFGH"), separate.hashUserCode("ABCD-EFGH")) {
		t.Fatal("user code hashing must depend only on the pairing key")
	}

	short := base
	short.DeviceCredentialKey = []byte("too-short")
	if _, err := NewService(revocationRepository{store: &revocationStore{}}, short); err == nil {
		t.Fatal("a short device key was accepted")
	}
}
