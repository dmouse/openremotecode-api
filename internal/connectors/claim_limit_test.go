package connectors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

type claimFailure struct {
	userID string
	at     time.Time
}

func (store *revocationStore) ChallengeForUpdate(_ context.Context, hash []byte) (Challenge, error) {
	if challenge, ok := store.challenges[hex.EncodeToString(hash)]; ok {
		return challenge, nil
	}
	return Challenge{}, ErrNotFound
}

func (store *revocationStore) SaveChallenge(_ context.Context, challenge Challenge) error {
	store.challenges[hex.EncodeToString(challenge.Hash)] = challenge
	return nil
}

func (store *revocationStore) PairingByCodeForUpdate(_ context.Context, hash []byte) (Pairing, error) {
	for _, pairing := range store.pairings {
		if string(pairing.UserCodeHash) == string(hash) {
			return pairing, nil
		}
	}
	return Pairing{}, ErrNotFound
}

func (store *revocationStore) DeviceByKeyIDForUpdate(_ context.Context, keyID string) (Device, error) {
	for _, device := range store.devices {
		if device.Identity.KeyID == keyID {
			return device, nil
		}
	}
	return Device{}, ErrNotFound
}

func (store *revocationStore) CreateDevice(_ context.Context, device Device) error {
	store.devices[device.ID] = device
	return nil
}

func (store *revocationStore) ClaimFailuresForUpdate(_ context.Context, userID string, accountSince, globalSince time.Time) (ClaimFailureCounts, error) {
	var counts ClaimFailureCounts
	for _, failure := range store.failures {
		if failure.userID == userID && failure.at.After(accountSince) {
			if counts.Account == 0 || failure.at.Before(counts.AccountOldest) {
				counts.AccountOldest = failure.at
			}
			counts.Account++
		}
		if failure.at.After(globalSince) {
			counts.Global++
		}
	}
	return counts, nil
}

func (store *revocationStore) RecordClaimFailure(_ context.Context, userID string, at, purgeBefore time.Time) error {
	kept := store.failures[:0:0]
	for _, failure := range store.failures {
		if failure.at.After(purgeBefore) {
			kept = append(kept, failure)
		}
	}
	store.failures = append(kept, claimFailure{userID: userID, at: at})
	return nil
}

type claimFixture struct {
	service *Service
	store   *revocationStore
	key     *ecdsa.PrivateKey
	device  PublicIdentity
	code    string
}

// newClaimFixture has one pending pairing whose user code is fixture.code, and a device key
// for usr_a that has never paired.
func newClaimFixture(t *testing.T) *claimFixture {
	t.Helper()
	service, store, _, _ := revocationFixture()
	service.random = rand.Reader
	service.pairingCodeKey = []byte("claim-limit-pairing-code-key-32-bytes!!")
	service.challengeLifetime = defaultChallengeLifetime
	service.accountClaimFailureLimit, service.accountClaimFailureWindow = defaultAccountClaimFailureLimit, defaultAccountClaimFailureWindow
	service.globalClaimFailureLimit, service.globalClaimFailureWindow = defaultGlobalClaimFailureLimit, defaultGlobalClaimFailureWindow
	store.devices, store.challenges = map[string]Device{}, map[string]Challenge{}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), key.X, key.Y) //nolint:staticcheck // the wire format is the uncompressed point
	digest := sha256.Sum256(publicKey)
	device := PublicIdentity{Version: 1, Suite: hpkeSuiteID,
		KeyID: base64.RawURLEncoding.EncodeToString(digest[:]), PublicKey: base64.RawURLEncoding.EncodeToString(publicKey)}
	now := service.now()
	const code = "ABCD-EFGH"
	store.pairings = map[string]Pairing{"par_a": {
		ID: "par_a", UserCodeHash: service.hashUserCode(code), State: PairingStatePending,
		ConnectorName: "Laptop", ConnectorIdentity: PublicIdentity{KeyID: "connector_key"},
		CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}}
	return &claimFixture{service: service, store: store, key: key, device: device, code: code}
}

// claim issues a fresh device challenge for usr_a, signs it, and claims with code.
func (fixture *claimFixture) claim(t *testing.T, code string) (IdentityProof, error) {
	t.Helper()
	userID := "usr_a"
	challenge, err := fixture.service.IssueChallenge(context.Background(), ChallengePurposeDevice, &userID)
	if err != nil {
		t.Fatal(err)
	}
	proof := fixture.sign(t, challenge.Challenge)
	_, err = fixture.service.ClaimPairing(context.Background(), ClaimPairingInput{
		UserID: userID, UserCode: code, DeviceName: "Phone", Identity: fixture.device, Proof: proof,
	})
	return proof, err
}

func (fixture *claimFixture) sign(t *testing.T, challenge string) IdentityProof {
	t.Helper()
	identity := fixture.device
	message, err := json.Marshal([]any{"opencode-remote/identity-proof/v1", challenge, identity.Version, identity.Suite, identity.KeyID, identity.PublicKey})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, fixture.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return IdentityProof{Challenge: challenge, Signature: base64.RawURLEncoding.EncodeToString(signature)}
}

func (store *revocationStore) CreateChallenge(_ context.Context, challenge Challenge) error {
	store.challenges[hex.EncodeToString(challenge.Hash)] = challenge
	return nil
}

// A wrong code must cost its challenge and be counted, even though the claim fails: that is
// what makes each guess expensive and the per-account cap enforceable.
func TestWrongCodeSpendsTheChallengeAndIsCounted(t *testing.T) {
	fixture := newClaimFixture(t)
	proof, err := fixture.claim(t, "ZZZZ-ZZZZ")
	if !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("wrong code = %v, want ErrInvalidCode", err)
	}
	if errors.Is(err, ErrUnauthorized) {
		t.Fatal("a wrong code must not read as an authorization failure")
	}
	if challenge := fixture.store.challenges[hex.EncodeToString(hashSecret(proof.Challenge))]; challenge.UsedAt == nil {
		t.Fatal("a wrong code left its challenge reusable")
	}
	if len(fixture.store.failures) != 1 || fixture.store.failures[0].userID != "usr_a" {
		t.Fatalf("failure not recorded: %+v", fixture.store.failures)
	}
	_, err = fixture.service.ClaimPairing(context.Background(), ClaimPairingInput{
		UserID: "usr_a", UserCode: fixture.code, DeviceName: "Phone", Identity: fixture.device, Proof: proof,
	})
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("reusing a spent challenge = %v, want ErrUnauthorized", err)
	}
	if _, err := fixture.claim(t, fixture.code); err != nil {
		t.Fatalf("the correct code with a fresh challenge: %v", err)
	}
	if len(fixture.store.failures) != 1 {
		t.Fatal("a successful claim was counted as a failure")
	}
}

func TestAccountClaimFailureCap(t *testing.T) {
	fixture := newClaimFixture(t)
	start := fixture.service.now()
	// This test outlives a real pairing's ten minutes; only the failure window is under test.
	pairing := fixture.store.pairings["par_a"]
	pairing.ExpiresAt = start.Add(2 * time.Hour)
	fixture.store.pairings["par_a"] = pairing
	for index := range defaultAccountClaimFailureLimit {
		at := start.Add(time.Duration(index) * time.Minute)
		fixture.service.now = func() time.Time { return at }
		if _, err := fixture.claim(t, "ZZZZ-ZZZZ"); !errors.Is(err, ErrInvalidCode) {
			t.Fatalf("guess %d = %v", index, err)
		}
	}
	// Even the right code is refused once the account is over its budget; the check runs
	// before the lookup, so the refusal says nothing about the code.
	later := start.Add(20 * time.Minute)
	fixture.service.now = func() time.Time { return later }
	proof, err := fixture.claim(t, fixture.code)
	var exceeded AttemptsExceededError
	if !errors.As(err, &exceeded) || !errors.Is(err, ErrTooManyAttempts) {
		t.Fatalf("claim over the account cap = %v, want AttemptsExceededError", err)
	}
	if want := 40 * time.Minute; exceeded.RetryAfter != want {
		t.Fatalf("retry after = %v, want %v (when the oldest failure leaves the window)", exceeded.RetryAfter, want)
	}
	if challenge := fixture.store.challenges[hex.EncodeToString(hashSecret(proof.Challenge))]; challenge.UsedAt != nil {
		t.Fatal("a refused claim spent its challenge")
	}
	if fixture.store.pairings["par_a"].State != PairingStatePending {
		t.Fatal("a refused claim changed the pairing")
	}
	// Another account is unaffected by this one's failures.
	counts, _ := fixture.store.ClaimFailuresForUpdate(context.Background(), "usr_b", later.Add(-time.Hour), later.Add(-time.Minute))
	if counts.Account != 0 {
		t.Fatal("failures leaked across accounts")
	}
	// Once the oldest failure ages out, the account may try again.
	recovered := start.Add(time.Hour + time.Second)
	fixture.service.now = func() time.Time { return recovered }
	if _, err := fixture.claim(t, fixture.code); err != nil {
		t.Fatalf("claim after the window: %v", err)
	}
}

// The global cap bounds the total guessing rate however many accounts an attacker holds.
func TestGlobalClaimFailureCap(t *testing.T) {
	fixture := newClaimFixture(t)
	now := fixture.service.now()
	for index := range defaultGlobalClaimFailureLimit {
		fixture.store.failures = append(fixture.store.failures,
			claimFailure{userID: fmt.Sprintf("usr_attacker_%d", index), at: now.Add(-30 * time.Second)})
	}
	var exceeded AttemptsExceededError
	if _, err := fixture.claim(t, fixture.code); !errors.As(err, &exceeded) || exceeded.RetryAfter != time.Minute {
		t.Fatalf("claim over the global cap = %v, want AttemptsExceededError after 1m", err)
	}
	// Failures older than the global window no longer count.
	later := now.Add(31 * time.Second)
	fixture.service.now = func() time.Time { return later }
	if _, err := fixture.claim(t, fixture.code); err != nil {
		t.Fatalf("claim after the global window: %v", err)
	}
}

func TestRecordingAFailurePurgesExpiredOnes(t *testing.T) {
	fixture := newClaimFixture(t)
	now := fixture.service.now()
	fixture.store.failures = []claimFailure{{userID: "usr_old", at: now.Add(-2 * time.Hour)}, {userID: "usr_recent", at: now.Add(-time.Minute)}}
	if _, err := fixture.claim(t, "ZZZZ-ZZZZ"); !errors.Is(err, ErrInvalidCode) {
		t.Fatal(err)
	}
	if len(fixture.store.failures) != 2 || fixture.store.failures[0].userID != "usr_recent" {
		t.Fatalf("expired failures were not purged: %+v", fixture.store.failures)
	}
}
