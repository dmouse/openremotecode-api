//go:build integration

package postgres_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"opencode-remote/server/internal/connectors"
	connectorshttp "opencode-remote/server/internal/connectors/httpapi"
	connectorspostgres "opencode-remote/server/internal/connectors/postgres"
	identitypostgres "opencode-remote/server/internal/identity/postgres"
	"opencode-remote/server/internal/platform/database"
	"opencode-remote/server/internal/platform/httpserver"
	"opencode-remote/server/internal/relay"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const defaultIntegrationDatabaseURL = "postgres://opencode_remote:local-development-only@127.0.0.1:5432/opencode_remote?sslmode=disable"

func TestPersistentPairingAndSingleUseTickets(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_TEST_URL")
	if databaseURL == "" {
		databaseURL = defaultIntegrationDatabaseURL
	}
	adminDatabase, adminSQL, err := database.Open(databaseURL)
	if err != nil {
		t.Skipf("PostgreSQL integration database unavailable: %v", err)
	}
	defer adminSQL.Close()

	schema := fmt.Sprintf("pairing_test_%d", time.Now().UnixNano())
	if err := adminDatabase.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	defer func() {
		if err := adminDatabase.Exec("DROP SCHEMA " + schema + " CASCADE").Error; err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	}()

	isolatedURL, err := withSearchPath(databaseURL, schema)
	if err != nil {
		t.Fatalf("create isolated database URL: %v", err)
	}
	databaseConnection, sqlDatabase, err := database.Open(isolatedURL)
	if err != nil {
		t.Fatalf("open isolated database: %v", err)
	}
	defer sqlDatabase.Close()
	ctx := context.Background()
	if err := identitypostgres.Migrate(ctx, databaseConnection); err != nil {
		t.Fatalf("migrate identity schema: %v", err)
	}
	if err := connectorspostgres.Migrate(ctx, databaseConnection); err != nil {
		t.Fatalf("migrate connector schema: %v", err)
	}
	if err := connectorspostgres.Migrate(ctx, databaseConnection); err != nil {
		t.Fatalf("repeat connector migration: %v", err)
	}
	if err := databaseConnection.Exec("DROP INDEX connector_pairings_active_key_id_key").Error; err != nil {
		t.Fatalf("drop active pairing index for upgrade fixture: %v", err)
	}
	legacyKeyID := strings.Repeat("l", 43)
	legacyCreatedAt := time.Date(2026, 8, 31, 4, 0, 0, 0, time.UTC)
	legacyPairings := []connectorspostgres.PairingModel{
		{
			ID: "par_legacy_upgrade_000001", SecretHash: bytesOf(1), UserCodeHash: bytesOf(2),
			ConnectorName: "Legacy one", ConnectorIdentityVersion: 1, ConnectorIdentitySuite: "legacy",
			ConnectorKeyID: legacyKeyID, ConnectorPublicKey: "legacy-one", ConnectorCredentialHash: bytesOf(3),
			State: connectors.PairingStatePending, CreatedAt: legacyCreatedAt, ExpiresAt: legacyCreatedAt.Add(time.Hour),
		},
		{
			ID: "par_legacy_upgrade_000002", SecretHash: bytesOf(4), UserCodeHash: bytesOf(5),
			ConnectorName: "Legacy two", ConnectorIdentityVersion: 1, ConnectorIdentitySuite: "legacy",
			ConnectorKeyID: legacyKeyID, ConnectorPublicKey: "legacy-two", ConnectorCredentialHash: bytesOf(6),
			State: connectors.PairingStateVerification, CreatedAt: legacyCreatedAt.Add(time.Minute), ExpiresAt: legacyCreatedAt.Add(time.Hour),
		},
	}
	if err := databaseConnection.Create(&legacyPairings).Error; err != nil {
		t.Fatalf("create duplicate legacy pairings: %v", err)
	}
	if err := connectorspostgres.Migrate(ctx, databaseConnection); err != nil {
		t.Fatalf("migrate duplicate legacy pairings: %v", err)
	}
	var activeLegacyPairings int64
	if err := databaseConnection.Model(&connectorspostgres.PairingModel{}).
		Where("connector_key_id = ? AND state NOT IN ?", legacyKeyID, []string{connectors.PairingStateCompleted, connectors.PairingStateExpired}).
		Count(&activeLegacyPairings).Error; err != nil {
		t.Fatalf("count migrated legacy pairings: %v", err)
	}
	if activeLegacyPairings != 1 {
		t.Fatalf("migration retained %d active legacy pairings, want 1", activeLegacyPairings)
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := "usr_pairing_integration_01"
	if err := databaseConnection.Create(&identitypostgres.UserModel{
		ID: userID, Email: "pairing@example.test", NormalizedEmail: "pairing@example.test",
		PasswordHash: stringPointer("not-used"), Status: "active", CreatedAt: now,
	}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	service, err := connectors.NewService(connectorspostgres.NewStore(databaseConnection), connectors.ServiceOptions{
		Now:             func() time.Time { return now },
		PairingCodeKey:  []byte("integration-pairing-code-key-at-least-32-bytes"),
		ServiceID:       "integration",
		VerificationURI: "https://app.example.test/pair",
		AuthorizeAccount: func(ctx context.Context, candidateUserID string) error {
			var count int64
			if err := databaseConnection.WithContext(ctx).Model(&identitypostgres.UserModel{}).
				Where("id = ? AND status = ?", candidateUserID, "active").Count(&count).Error; err != nil {
				return err
			}
			if count != 1 {
				return connectors.ErrUnauthorized
			}
			return nil
		},
		AuthorizeSession: func(context.Context, string, string) error { return nil },
	})
	if err != nil {
		t.Fatalf("create connector service: %v", err)
	}

	connectorIdentity, connectorKey := generateIdentity(t)
	connectorChallenge, err := service.IssueChallenge(ctx, connectors.ChallengePurposeConnector, nil)
	if err != nil {
		t.Fatalf("issue connector challenge: %v", err)
	}
	pairing, err := service.BeginPairing(ctx, connectors.BeginPairingInput{
		Name: "Integration connector", Identity: connectorIdentity,
		Proof: signProof(t, connectorKey, connectorIdentity, connectorChallenge.Challenge),
	})
	if err != nil {
		t.Fatalf("begin pairing: %v", err)
	}
	competingChallenge, err := service.IssueChallenge(ctx, connectors.ChallengePurposeConnector, nil)
	if err != nil {
		t.Fatalf("issue competing connector challenge: %v", err)
	}
	_, err = service.BeginPairing(ctx, connectors.BeginPairingInput{
		Name: "Competing connector", Identity: connectorIdentity,
		Proof: signProof(t, connectorKey, connectorIdentity, competingChallenge.Challenge),
	})
	if !errors.Is(err, connectors.ErrConflict) {
		t.Fatalf("second active pairing for one connector key must fail, got %v", err)
	}
	if err := service.CancelPairing(ctx, pairing.PairingID, "orp_"+strings.Repeat("A", 43)); !errors.Is(err, connectors.ErrUnauthorized) {
		t.Fatalf("pairing cancellation with the wrong secret must fail, got %v", err)
	}
	if err := service.CancelPairing(ctx, pairing.PairingID, pairing.PairingSecret); err != nil {
		t.Fatalf("cancel pairing: %v", err)
	}
	if err := service.CancelPairing(ctx, pairing.PairingID, pairing.PairingSecret); err != nil {
		t.Fatalf("repeat pairing cancellation: %v", err)
	}
	cancelled, err := service.PollPairing(ctx, pairing.PairingSecret)
	if err != nil || cancelled.Status != connectors.PairingStateExpired {
		t.Fatalf("poll cancelled pairing: result=%#v err=%v", cancelled, err)
	}
	replacementChallenge, err := service.IssueChallenge(ctx, connectors.ChallengePurposeConnector, nil)
	if err != nil {
		t.Fatalf("issue replacement connector challenge: %v", err)
	}
	pairing, err = service.BeginPairing(ctx, connectors.BeginPairingInput{
		Name: "Integration connector", Identity: connectorIdentity,
		Proof: signProof(t, connectorKey, connectorIdentity, replacementChallenge.Challenge),
	})
	if err != nil {
		t.Fatalf("begin replacement pairing: %v", err)
	}

	deviceIdentity, deviceKey := generateIdentity(t)
	deviceChallenge, err := service.IssueChallenge(ctx, connectors.ChallengePurposeDevice, &userID)
	if err != nil {
		t.Fatalf("issue device challenge: %v", err)
	}
	claim, err := service.ClaimPairing(ctx, connectors.ClaimPairingInput{
		UserID: userID, UserCode: pairing.UserCode, DeviceName: "Integration browser",
		Identity: deviceIdentity, Proof: signProof(t, deviceKey, deviceIdentity, deviceChallenge.Challenge),
	})
	if err != nil {
		t.Fatalf("claim pairing: %v", err)
	}
	if claim.Transcript.ConnectorIdentity != connectorIdentity || claim.Transcript.DeviceIdentity != deviceIdentity {
		t.Fatal("pairing transcript did not bind both proven identities")
	}
	if _, err := service.ConfirmPairing(ctx, userID, pairing.PairingID, claim.DeviceID); !errors.Is(err, connectors.ErrConflict) {
		t.Fatalf("confirmation before connector transcript review must fail, got %v", err)
	}

	poll, err := service.PollPairing(ctx, pairing.PairingSecret)
	if err != nil || poll.Status != connectors.PairingStateVerification || poll.Transcript == nil {
		t.Fatalf("poll verification state: result=%#v err=%v", poll, err)
	}
	if err := databaseConnection.Model(&identitypostgres.UserModel{}).Where("id = ?", userID).Update("status", "disabled").Error; err != nil {
		t.Fatalf("disable account before confirmation: %v", err)
	}
	if _, err := service.ConfirmPairing(ctx, userID, pairing.PairingID, claim.DeviceID); !errors.Is(err, connectors.ErrUnauthorized) {
		t.Fatalf("disabled account confirmation must fail, got %v", err)
	}
	if err := databaseConnection.Model(&identitypostgres.UserModel{}).Where("id = ?", userID).Update("status", "active").Error; err != nil {
		t.Fatalf("reactivate account before confirmation: %v", err)
	}
	type confirmationOutcome struct {
		result connectors.ConfirmPairingResult
		err    error
	}
	confirmationResults := make(chan confirmationOutcome, 2)
	for range 2 {
		go func() {
			result, confirmErr := service.ConfirmPairing(ctx, userID, pairing.PairingID, claim.DeviceID)
			confirmationResults <- confirmationOutcome{result: result, err: confirmErr}
		}()
	}
	firstConfirmation := <-confirmationResults
	secondConfirmation := <-confirmationResults
	close(confirmationResults)
	if firstConfirmation.err != nil || secondConfirmation.err != nil {
		t.Fatalf("concurrent confirmation failed: first=%v second=%v", firstConfirmation.err, secondConfirmation.err)
	}
	if firstConfirmation.result.DeviceCredential != secondConfirmation.result.DeviceCredential {
		t.Fatal("concurrent confirmation returned different device credentials")
	}
	confirmed := firstConfirmation.result
	completed, err := service.PollPairing(ctx, pairing.PairingSecret)
	if err != nil || completed.Status != connectors.PairingStateCompleted || completed.ConnectorCredential == "" {
		t.Fatalf("complete pairing: result=%#v err=%v", completed, err)
	}
	if completed.LinkedAt == nil || !completed.LinkedAt.Equal(now) {
		t.Fatal("completed pairing omitted its original linking date")
	}
	repeated, err := service.PollPairing(ctx, pairing.PairingSecret)
	if err != nil || repeated.ConnectorCredential != completed.ConnectorCredential {
		t.Fatal("completed pairing did not redeliver the same connector credential")
	}
	if repeated.LinkedAt == nil || !repeated.LinkedAt.Equal(*completed.LinkedAt) {
		t.Fatal("repeated pairing changed its linking date")
	}

	browserTicket, err := service.IssueBrowserTicket(ctx, userID, "asn_integration_session_01", claim.DeviceID, confirmed.DeviceCredential, now.Add(15*time.Minute))
	if err != nil {
		t.Fatalf("issue browser ticket: %v", err)
	}
	connectorTicket, err := service.IssueConnectorTicket(ctx, completed.ConnectorCredential)
	if err != nil {
		t.Fatalf("issue connector ticket: %v", err)
	}
	browserAdmission, err := service.ConsumeRelayTicket(ctx, browserTicket.Ticket)
	if err != nil || browserAdmission.Role != connectors.RelayRoleClient || len(browserAdmission.TrustedIdentities) != 1 || browserAdmission.TrustedIdentities[0] != connectorIdentity {
		t.Fatalf("consume browser ticket: admission=%#v err=%v", browserAdmission, err)
	}
	connectorAdmission, err := service.ConsumeRelayTicket(ctx, connectorTicket.Ticket)
	if err != nil || connectorAdmission.Role != connectors.RelayRoleConnector || len(connectorAdmission.TrustedIdentities) != 1 || connectorAdmission.TrustedIdentities[0] != deviceIdentity {
		t.Fatalf("consume connector ticket: admission=%#v err=%v", connectorAdmission, err)
	}
	if _, err := service.ConsumeRelayTicket(ctx, browserTicket.Ticket); !errors.Is(err, connectors.ErrUnauthorized) {
		t.Fatalf("reused relay ticket must fail, got %v", err)
	}

	concurrentTicket, err := service.IssueConnectorTicket(ctx, completed.ConnectorCredential)
	if err != nil {
		t.Fatalf("issue concurrent ticket: %v", err)
	}
	var wait sync.WaitGroup
	results := make(chan error, 2)
	wait.Add(2)
	for range 2 {
		go func() {
			defer wait.Done()
			_, consumeErr := service.ConsumeRelayTicket(ctx, concurrentTicket.Ticket)
			results <- consumeErr
		}()
	}
	wait.Wait()
	close(results)
	successes, failures := 0, 0
	for consumeErr := range results {
		if consumeErr == nil {
			successes++
		} else if errors.Is(consumeErr, connectors.ErrUnauthorized) {
			failures++
		} else {
			t.Fatalf("unexpected concurrent consume error: %v", consumeErr)
		}
	}
	if successes != 1 || failures != 1 {
		t.Fatalf("single-use race returned successes=%d failures=%d", successes, failures)
	}

	disabledAccountTicket, err := service.IssueConnectorTicket(ctx, completed.ConnectorCredential)
	if err != nil {
		t.Fatalf("issue ticket before account disablement: %v", err)
	}
	if err := databaseConnection.Model(&identitypostgres.UserModel{}).Where("id = ?", userID).Update("status", "disabled").Error; err != nil {
		t.Fatalf("disable account: %v", err)
	}
	if _, err := service.ConsumeRelayTicket(ctx, disabledAccountTicket.Ticket); !errors.Is(err, connectors.ErrUnauthorized) {
		t.Fatalf("disabled account ticket consumption must fail, got %v", err)
	}
	if _, err := service.IssueConnectorTicket(ctx, completed.ConnectorCredential); !errors.Is(err, connectors.ErrUnauthorized) {
		t.Fatalf("disabled account ticket issuance must fail, got %v", err)
	}
	if err := databaseConnection.Model(&identitypostgres.UserModel{}).Where("id = ?", userID).Update("status", "active").Error; err != nil {
		t.Fatalf("reactivate account: %v", err)
	}
	if err := connectorspostgres.Migrate(ctx, databaseConnection); err != nil {
		t.Fatalf("repeat connector migration with populated schema: %v", err)
	}

	// Exercise the public revocation API against PostgreSQL and an already connected relay.
	unusedTicket, err := service.IssueConnectorTicket(ctx, completed.ConnectorCredential)
	if err != nil {
		t.Fatal(err)
	}
	liveTicket, err := service.IssueConnectorTicket(ctx, completed.ConnectorCredential)
	if err != nil {
		t.Fatal(err)
	}
	relayHandler := relay.NewHandler(service, relay.HandlerConfig{Now: func() time.Time { return now }})
	connectorHandler := connectorshttp.NewHandler(nil, service, connectorshttp.Config{})
	router := httpserver.NewRouter(nil)
	router.GET("/v1/relay", gin.WrapH(relayHandler))
	connectorHandler.RegisterRoutes(router)
	httpServer := httptest.NewServer(router)
	defer httpServer.Close()
	defer relayHandler.Close()
	metadataRequest, err := http.NewRequest(http.MethodGet, httpServer.URL+"/v1/connectors/self", nil)
	if err != nil {
		t.Fatal(err)
	}
	metadataRequest.Header.Set("Authorization", "Bearer "+completed.ConnectorCredential)
	metadataResponse, err := httpServer.Client().Do(metadataRequest)
	if err != nil {
		t.Fatal(err)
	}
	var metadata struct {
		ConnectorID string    `json:"connectorId"`
		LinkedAt    time.Time `json:"linkedAt"`
	}
	err = json.NewDecoder(metadataResponse.Body).Decode(&metadata)
	metadataResponse.Body.Close()
	if err != nil || metadataResponse.StatusCode != http.StatusOK || metadata.ConnectorID != completed.ConnectorID || !metadata.LinkedAt.Equal(*completed.LinkedAt) {
		t.Fatalf("own connector metadata failed: %v", err)
	}
	dialer := *websocket.DefaultDialer
	dialer.Subprotocols = []string{"opencode-remote.v1", "ticket." + liveTicket.Ticket}
	socket, _, err := dialer.Dial("ws"+strings.TrimPrefix(httpServer.URL, "http")+"/v1/relay", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	if err := socket.WriteJSON(map[string]any{
		"protocolVersion": 2, "type": "connector.hello", "pluginVersion": "0.1.0",
		"identity": connectorIdentity, "nonce": strings.Repeat("n", 22),
		"capabilities": []string{"session.list"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := socket.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		request, err := http.NewRequest(http.MethodPost, httpServer.URL+"/v1/connectors/self/revoke", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+completed.ConnectorCredential)
		response, err := httpServer.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("revoke connector status = %d", response.StatusCode)
		}
	}
	_ = socket.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := socket.ReadMessage(); !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("revoked live socket was not closed: %v", err)
	}
	if _, err := service.IssueConnectorTicket(ctx, completed.ConnectorCredential); !errors.Is(err, connectors.ErrUnauthorized) {
		t.Fatalf("revoked credential issued a ticket: %v", err)
	}
	if _, err := service.ConsumeRelayTicket(ctx, unusedTicket.Ticket); !errors.Is(err, connectors.ErrUnauthorized) {
		t.Fatalf("pre-revocation ticket accepted: %v", err)
	}
	if _, err := service.PollPairing(ctx, pairing.PairingSecret); !errors.Is(err, connectors.ErrUnauthorized) {
		t.Fatalf("completed pairing resurrected revoked credential: %v", err)
	}
	visible, err := service.ListConnectors(ctx, userID)
	if err != nil || len(visible) != 0 {
		t.Fatalf("revoked connector remains visible: %v", err)
	}
	var revocationAudits int64
	if err := databaseConnection.Model(&connectorspostgres.AuditEventModel{}).
		Where("connector_id = ? AND event_type = ?", completed.ConnectorID, "connector.revoked").Count(&revocationAudits).Error; err != nil {
		t.Fatal(err)
	}
	if revocationAudits != 1 {
		t.Fatalf("revocation audit count = %d", revocationAudits)
	}

	var stored connectorspostgres.PairingModel
	if err := databaseConnection.Where("id = ?", pairing.PairingID).First(&stored).Error; err != nil {
		t.Fatalf("load stored pairing: %v", err)
	}
	serialized, _ := json.Marshal(stored)
	for _, secret := range []string{pairing.PairingSecret, pairing.UserCode, completed.ConnectorCredential, confirmed.DeviceCredential, browserTicket.Ticket} {
		if strings.Contains(string(serialized), secret) {
			t.Fatal("database pairing model retained a raw secret")
		}
	}
}

func generateIdentity(t *testing.T) (connectors.PublicIdentity, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), key.PublicKey.X, key.PublicKey.Y)
	digest := sha256.Sum256(publicKey)
	return connectors.PublicIdentity{
		Version:   1,
		Suite:     "HPKE-Auth-P256-HKDF-SHA256-AES-256-GCM",
		KeyID:     base64.RawURLEncoding.EncodeToString(digest[:]),
		PublicKey: base64.RawURLEncoding.EncodeToString(publicKey),
	}, key
}

func signProof(t *testing.T, key *ecdsa.PrivateKey, identity connectors.PublicIdentity, challenge string) connectors.IdentityProof {
	t.Helper()
	message, err := json.Marshal([]any{"opencode-remote/identity-proof/v1", challenge, identity.Version, identity.Suite, identity.KeyID, identity.PublicKey})
	if err != nil {
		t.Fatalf("encode proof message: %v", err)
	}
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return connectors.IdentityProof{Challenge: challenge, Signature: base64.RawURLEncoding.EncodeToString(signature)}
}

func bytesOf(value byte) []byte { return bytes.Repeat([]byte{value}, sha256.Size) }

func withSearchPath(databaseURL, schema string) (string, error) {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

// stringPointer builds an optional column value. users.password_hash is nullable
// now that federated accounts exist, so fixtures must say which they mean.
func stringPointer(value string) *string { return &value }
