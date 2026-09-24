//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"opencode-remote/server/internal/connectors"
	connectorshttp "opencode-remote/server/internal/connectors/httpapi"
	connectorspostgres "opencode-remote/server/internal/connectors/postgres"
	"opencode-remote/server/internal/identity"
	identitypostgres "opencode-remote/server/internal/identity/postgres"
	"opencode-remote/server/internal/platform/database"
	"opencode-remote/server/internal/platform/httpserver"

	"gorm.io/gorm"
)

// An account cannot pair a device or obtain relay admission until its email is
// verified. Today that holds by inheritance — a pending account never receives a
// token, and every authorization query filters status = 'active' in SQL — but nothing
// asserted it, so it could regress silently behind a new route or a relaxed WHERE.
//
// The fixture is deliberately hostile: the pending account holds a manually inserted
// session and access token that are valid in every respect except account status, so
// a status check is the only thing that can reject it.
func TestPendingAccountCannotReachConnectorRoutes(t *testing.T) {
	databaseConnection := newCrossModuleDatabase(t)
	now := time.Now().UTC().Truncate(time.Microsecond)
	userID := "usr_pending_pairing_00001"
	if err := databaseConnection.Create(&identitypostgres.UserModel{
		ID:              userID,
		Email:           "pending@example.test",
		NormalizedEmail: "pending@example.test",
		PasswordHash:    stringPointer("not-used"),
		Status:          identity.AccountStatusPending,
		CreatedAt:       now,
	}).Error; err != nil {
		t.Fatalf("create pending user: %v", err)
	}
	sessionID := "asn_pending_pairing_0001"
	accessToken := seedAccessToken(t, databaseConnection, userID, sessionID, now)

	identityService, err := identity.NewService(
		identitypostgres.NewStore(databaseConnection),
		noopPasswords{},
		noopMailer{},
		identity.ServiceOptions{Now: func() time.Time { return now }},
	)
	if err != nil {
		t.Fatalf("create identity service: %v", err)
	}
	connectorService, err := connectors.NewService(
		connectorspostgres.NewStore(databaseConnection),
		connectors.ServiceOptions{
			Now:             func() time.Time { return now },
			PairingCodeKey:  []byte("integration-pairing-code-key-at-least-32-bytes"),
			ServiceID:       "integration",
			VerificationURI: "https://app.example.test/pair",
			// Wired exactly as cmd/server/setup.go wires them, so the test exercises
			// the real authorization path rather than a permissive stand-in.
			AuthorizeAccount: func(ctx context.Context, candidateUserID string) error {
				if err := identityService.AuthorizeAccount(ctx, candidateUserID); err != nil {
					return connectors.ErrUnauthorized
				}
				return nil
			},
			AuthorizeSession: func(ctx context.Context, candidateUserID, candidateSessionID string) error {
				if err := identityService.AuthorizeSession(ctx, candidateUserID, candidateSessionID); err != nil {
					return connectors.ErrUnauthorized
				}
				return nil
			},
		},
	)
	if err != nil {
		t.Fatalf("create connector service: %v", err)
	}
	router := httpserver.NewRouter(nil)
	connectorshttp.NewHandler(identityService, connectorService, connectorshttp.Config{
		Now: func() time.Time { return now },
	}).RegisterRoutes(router)

	// Routes that derive an account from a bearer access token. Each must reject a
	// pending account with 401.
	accountRoutes := map[string]struct {
		body string
		// provesFixture marks routes where an active account demonstrably gets past
		// the identity check, which is what shows the test is not just passing on a
		// broken fixture.
		provesFixture bool
	}{
		"POST /v1/connector-pairings/claim":       {body: `{"userCode":"ABCD-EFGH","deviceName":"Phone","identity":{},"proof":{}}`, provesFixture: true},
		"POST /v1/devices/challenge":              {body: `{}`, provesFixture: true},
		"GET /v1/connectors":                      {provesFixture: true},
		"HEAD /v1/connectors":                     {provesFixture: true},
		"POST /v1/connectors/:connectorID/revoke": {body: `{}`, provesFixture: true},
		"POST /v1/connectors/:connectorID/rename": {body: `{"name":"Renamed"}`, provesFixture: true},
		// Device inventory and account-owned revocation (ADR 0017). An unknown device is 404
		// for an active account, which gets it past the identity check.
		"GET /v1/devices":                   {provesFixture: true},
		"HEAD /v1/devices":                  {provesFixture: true},
		"POST /v1/devices/:deviceID/revoke": {body: `{}`, provesFixture: true},
		// These two answer 401 for an active account as well, each for its own
		// legitimate reason, so neither can demonstrate the fixture: confirming
		// reports a pairing that is unknown or not yours as unauthorized rather than
		// disclosing which, and relay admission additionally requires a paired device
		// cookie. The pending half is what this test owns for them; the active paths
		// are covered by the pairing lifecycle test.
		"POST /v1/connector-pairings/:pairingID/confirm": {body: `{"deviceId":"dev_unknown_device_0001"}`},
		"POST /v1/relay/tickets":                         {body: `{}`},
		// Device credential rotation authenticates the account, the session, and the current
		// device cookie together. Like relay admission, the missing cookie makes an active
		// account answer 401 as well, so neither can demonstrate the fixture; the pending
		// half is what this test owns for them.
		"POST /v1/devices/self/rotate":          {body: `{"deviceId":"dev_unknown_device_0001"}`},
		"POST /v1/devices/self/rotate/activate": {body: `{"deviceId":"dev_unknown_device_0001"}`},
	}
	// Routes that authenticate a connector credential instead of an account. A
	// pending account's token is irrelevant to them.
	connectorCredentialRoutes := map[string]struct{}{
		"POST /v1/connector-pairings/challenge":         {},
		"POST /v1/connector-pairings":                   {},
		"POST /v1/connector-pairings/:pairingID/poll":   {},
		"POST /v1/connector-pairings/:pairingID/cancel": {},
		// Authenticated by the pairing secret only the connector holds (ADR 0018).
		"POST /v1/connector-pairings/:pairingID/approve": {},
		"POST /v1/connectors/self/revoke":                {},
		"POST /v1/connectors/self/rotate":                {},
		// Authenticated by the pending credential a rotation issued, which is likewise
		// a connector credential and never an account token.
		"POST /v1/connectors/self/rotate/activate": {},
		"GET /v1/connectors/self":                  {},
		"HEAD /v1/connectors/self":                 {},
	}

	// Enumerating the router rather than spot-checking means a newly added route
	// shows up here as an unclassified failure instead of an untested gap.
	for _, route := range router.Routes() {
		key := route.Method + " " + route.Path
		_, account := accountRoutes[key]
		_, credential := connectorCredentialRoutes[key]
		if account == credential {
			t.Fatalf("route %q is unclassified: decide whether it authenticates an account, then add it here", key)
		}
	}

	for key, route := range accountRoutes {
		method, path, found := strings.Cut(key, " ")
		if !found {
			t.Fatalf("malformed route key %q", key)
		}
		// Concrete identifiers in place of the route parameters.
		path = strings.ReplaceAll(path, ":pairingID", "par_unknown_pairing_0001")
		path = strings.ReplaceAll(path, ":connectorID", "con_unknown_connector_01")
		path = strings.ReplaceAll(path, ":deviceID", "dev_unknown_device_0001")

		t.Run("pending is rejected by "+key, func(t *testing.T) {
			response := performAuthorizedRequest(router, method, path, route.body, accessToken)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusUnauthorized, response.Body)
			}
		})
	}

	// Flip the single field under test. The same routes must now get past the
	// identity check, proving the rejections above came from the status filter.
	if err := databaseConnection.Model(&identitypostgres.UserModel{}).
		Where("id = ?", userID).
		Updates(map[string]any{"status": identity.AccountStatusActive, "email_verified_at": now}).Error; err != nil {
		t.Fatalf("activate user: %v", err)
	}
	for key, route := range accountRoutes {
		if !route.provesFixture {
			continue
		}
		method, path, _ := strings.Cut(key, " ")
		path = strings.ReplaceAll(path, ":pairingID", "par_unknown_pairing_0001")
		path = strings.ReplaceAll(path, ":connectorID", "con_unknown_connector_01")
		path = strings.ReplaceAll(path, ":deviceID", "dev_unknown_device_0001")

		t.Run("active is admitted by "+key, func(t *testing.T) {
			response := performAuthorizedRequest(router, method, path, route.body, accessToken)
			if response.Code == http.StatusUnauthorized {
				t.Fatalf("an active account was rejected, so the fixture proves nothing: %s", response.Body)
			}
		})
	}
}

func newCrossModuleDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	databaseURL := os.Getenv("DATABASE_TEST_URL")
	if databaseURL == "" {
		databaseURL = defaultIntegrationDatabaseURL
	}
	adminDatabase, adminSQL, err := database.Open(databaseURL)
	if err != nil {
		t.Skipf("PostgreSQL integration database unavailable: %v", err)
	}
	t.Cleanup(func() { adminSQL.Close() })

	schema := fmt.Sprintf("pending_account_test_%d", time.Now().UnixNano())
	if err := adminDatabase.Exec("CREATE SCHEMA " + schema).Error; err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		if err := adminDatabase.Exec("DROP SCHEMA " + schema + " CASCADE").Error; err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})
	isolatedURL, err := withSearchPath(databaseURL, schema)
	if err != nil {
		t.Fatalf("create isolated database URL: %v", err)
	}
	databaseConnection, sqlDatabase, err := database.Open(isolatedURL)
	if err != nil {
		t.Fatalf("open isolated database: %v", err)
	}
	t.Cleanup(func() { sqlDatabase.Close() })
	ctx := context.Background()
	if err := identitypostgres.Migrate(ctx, databaseConnection); err != nil {
		t.Fatalf("migrate identity schema: %v", err)
	}
	if err := connectorspostgres.Migrate(ctx, databaseConnection); err != nil {
		t.Fatalf("migrate connector schema: %v", err)
	}
	return databaseConnection
}

// seedAccessToken inserts a session bypassing the service, so the token it returns is
// valid in every respect except the status of the account behind it.
func seedAccessToken(t *testing.T, databaseConnection *gorm.DB, userID, sessionID string, now time.Time) string {
	t.Helper()
	material := sha256.Sum256([]byte("seed-access-token:" + sessionID))
	accessToken := "ora_" + base64.RawURLEncoding.EncodeToString(material[:])
	accessHash := sha256.Sum256([]byte(accessToken))
	if err := databaseConnection.Create(&identitypostgres.SessionModel{
		ID:                   sessionID,
		UserID:               userID,
		AccessTokenHash:      accessHash[:],
		AccessTokenExpiresAt: now.Add(time.Hour),
		RefreshExpiresAt:     now.Add(24 * time.Hour),
		ClientName:           "Seeded fixture",
		CreatedAt:            now,
		LastRefreshedAt:      now,
	}).Error; err != nil {
		t.Fatalf("seed session: %v", err)
	}
	return accessToken
}

func performAuthorizedRequest(
	handler http.Handler,
	method, path, body, accessToken string,
) *httptest.ResponseRecorder {
	var request *http.Request
	if body == "" {
		request = httptest.NewRequest(method, path, nil)
	} else {
		request = httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
	}
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("Authorization", "Bearer "+accessToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type noopPasswords struct{}

func (noopPasswords) Hash(context.Context, string) (string, error) { return "not-used", nil }

func (noopPasswords) Verify(context.Context, string, string) (bool, error) { return false, nil }

type noopMailer struct{}

func (noopMailer) SendVerificationCode(context.Context, string, string) error { return nil }

func (noopMailer) SendRegistrationNotice(context.Context, string) error { return nil }
