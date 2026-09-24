package connectors

import (
	"context"
	"errors"
	"testing"
	"time"
)

func (store *revocationStore) DeviceByIDForUpdate(_ context.Context, id string) (Device, error) {
	if device, ok := store.devices[id]; ok {
		return device, nil
	}
	return Device{}, ErrNotFound
}

func (store *revocationStore) RevokeDeviceTrust(_ context.Context, _ string, deviceID string, _ time.Time) error {
	store.revokedTrust = append(store.revokedTrust, deviceID)
	return nil
}

// deviceRevocationFixture seeds an active device for usr_a and another for usr_b, and
// returns a live client admission for the first.
func deviceRevocationFixture() (*Service, *revocationStore, Admission) {
	service, store, _, _ := revocationFixture()
	now := service.now()
	expires := now.Add(time.Hour)
	pending := now.Add(time.Minute)
	store.devices = map[string]Device{
		"dev_a": {
			ID: "dev_a", UserID: "usr_a", Identity: PublicIdentity{KeyID: "device_key_a"},
			CredentialHash: hashSecret("device-a"), CredentialExpiresAt: &expires,
			PendingCredentialHash: hashSecret("device-a-next"), PendingCredentialExpiresAt: &pending,
			ActivatedAt: &now,
		},
		"dev_b": {
			ID: "dev_b", UserID: "usr_b", Identity: PublicIdentity{KeyID: "device_key_b"},
			CredentialHash: hashSecret("device-b"), CredentialExpiresAt: &expires, ActivatedAt: &now,
		},
	}
	service.authorizeSession = func(context.Context, string, string) error { return nil }
	device := store.devices["dev_a"]
	return service, store, Admission{
		Role: RelayRoleClient, UserID: device.UserID, SubjectID: device.ID,
		SessionID: "asn_a", Identity: device.Identity,
	}
}

func TestAccountDeviceRevocationIsScopedIdempotentAndEndsAdmission(t *testing.T) {
	service, store, admission := deviceRevocationFixture()
	ctx := context.Background()
	if err := service.ValidateAdmission(ctx, admission); err != nil {
		t.Fatalf("active device rejected: %v", err)
	}
	for _, id := range []string{"dev_b", "missing"} {
		if err := service.RevokeAccountDevice(ctx, "usr_a", id); !errors.Is(err, ErrNotFound) {
			t.Fatalf("foreign and missing devices must be indistinguishable: %v", err)
		}
	}
	if len(store.audits) != 0 || store.devices["dev_b"].RevokedAt != nil || len(store.revokedTrust) != 0 {
		t.Fatal("failed authorization changed state")
	}
	for range 2 {
		if err := service.RevokeAccountDevice(ctx, "usr_a", "dev_a"); err != nil {
			t.Fatal(err)
		}
	}
	revoked := store.devices["dev_a"]
	if revoked.RevokedAt == nil || store.devices["dev_b"].RevokedAt != nil {
		t.Fatal("revocation crossed device/account boundary")
	}
	if revoked.PendingCredentialHash != nil || revoked.PendingCredentialExpiresAt != nil {
		t.Fatal("revocation left a pending credential rotation activatable")
	}
	if len(store.revokedTrust) != 1 || store.revokedTrust[0] != "dev_a" {
		t.Fatalf("trust revoked for %v, want exactly dev_a once", store.revokedTrust)
	}
	if len(store.audits) != 1 || store.audits[0].EventType != "device.revoked" ||
		*store.audits[0].UserID != "usr_a" || *store.audits[0].DeviceID != "dev_a" {
		t.Fatal("missing or duplicated scoped audit")
	}
	if err := service.ValidateAdmission(ctx, admission); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("revoked device still admitted: %v", err)
	}
	want := Revocation{UserID: "usr_a", DeviceID: "dev_a"}
	if len(store.announced) == 0 || store.announced[len(store.announced)-1] != want {
		t.Fatalf("announced %+v, want %+v", store.announced, want)
	}
	for _, revocation := range store.announced {
		if revocation.DeviceID == "dev_b" {
			t.Fatal("a refused revocation of another account's device was announced")
		}
	}
}

func TestAccountDeviceRevocationFailsClosedAndRollsBackAuditFailure(t *testing.T) {
	service, store, _ := deviceRevocationFixture()
	ctx := context.Background()
	for _, input := range []struct{ userID, deviceID string }{{"", "dev_a"}, {"usr_a", ""}, {"usr_a", string(make([]byte, 65))}} {
		if err := service.RevokeAccountDevice(ctx, input.userID, input.deviceID); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid input accepted: %v", err)
		}
	}
	service.authorizeAccount = func(context.Context, string) error { return ErrUnauthorized }
	if err := service.RevokeAccountDevice(ctx, "usr_a", "dev_a"); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("disabled account allowed to revoke")
	}
	service.authorizeAccount = func(context.Context, string) error { return nil }
	store.auditError = errors.New("audit unavailable")
	if err := service.RevokeAccountDevice(ctx, "usr_a", "dev_a"); err == nil {
		t.Fatal("expected audit failure")
	}
	if store.devices["dev_a"].RevokedAt != nil || len(store.revokedTrust) != 0 {
		t.Fatal("revocation committed without its audit event")
	}
	if len(store.announced) != 0 {
		t.Fatal("a revocation that did not commit was announced")
	}
}

// A client socket is bound to the session its ticket was issued under, so logging out
// or losing the session ends it, and to the device's current state.
func TestClientAdmissionTracksSessionAndDeviceState(t *testing.T) {
	service, store, admission := deviceRevocationFixture()
	ctx := context.Background()

	service.authorizeSession = func(_ context.Context, userID, sessionID string) error {
		if userID != "usr_a" || sessionID != "asn_a" {
			t.Fatalf("session checked as %q/%q", userID, sessionID)
		}
		return ErrUnauthorized
	}
	if err := service.ValidateAdmission(ctx, admission); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("ended session still admitted: %v", err)
	}
	service.authorizeSession = func(context.Context, string, string) error { return nil }

	for _, modify := range []func(*Admission){
		func(a *Admission) { a.SessionID = "" },
		func(a *Admission) { a.UserID = "usr_b" },
		func(a *Admission) { a.SubjectID = "dev_b" },
		func(a *Admission) { a.Identity.KeyID = "device_key_b" },
		func(a *Admission) { a.Role = "observer" },
	} {
		candidate := admission
		modify(&candidate)
		if err := service.ValidateAdmission(ctx, candidate); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("mismatched client admission accepted: %v", err)
		}
	}

	device := store.devices["dev_a"]
	expired := service.now().Add(-time.Minute)
	device.CredentialExpiresAt = &expired
	store.devices["dev_a"] = device
	if err := service.ValidateAdmission(ctx, admission); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired device credential still admitted: %v", err)
	}
}
