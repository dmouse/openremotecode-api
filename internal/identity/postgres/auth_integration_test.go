//go:build integration

package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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

	"opencode-remote/server/internal/identity"
	"opencode-remote/server/internal/identity/httpapi"
	identitypostgres "opencode-remote/server/internal/identity/postgres"
	"opencode-remote/server/internal/platform/database"
	"opencode-remote/server/internal/platform/httpserver"

	"gorm.io/gorm"
)

const defaultIntegrationDatabaseURL = "postgres://opencode_remote:local-development-only@127.0.0.1:5432/opencode_remote?sslmode=disable"

// newIsolatedDatabase gives each test its own migrated schema, so tests never see
// one another's rows.
func newIsolatedDatabase(t *testing.T) *gorm.DB {
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

	schema := fmt.Sprintf("identity_test_%d", time.Now().UnixNano())
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
	isolatedDatabase, isolatedSQL, err := database.Open(isolatedURL)
	if err != nil {
		t.Fatalf("open isolated database: %v", err)
	}
	t.Cleanup(func() { isolatedSQL.Close() })
	if err := identitypostgres.Migrate(context.Background(), isolatedDatabase); err != nil {
		t.Fatalf("migrate isolated database: %v", err)
	}
	// Migration is additive and must stay repeatable.
	if err := identitypostgres.Migrate(context.Background(), isolatedDatabase); err != nil {
		t.Fatalf("repeat migration: %v", err)
	}
	return isolatedDatabase
}

func TestAuthenticationLifecycle(t *testing.T) {
	isolatedDatabase := newIsolatedDatabase(t)
	invalidUser := identitypostgres.UserModel{
		ID:              "usr_invalid_constraint_01",
		Email:           "invalid-status@example.test",
		NormalizedEmail: "invalid-status@example.test",
		PasswordHash:    stringPointer("not-a-real-hash"),
		Status:          "unexpected",
		CreatedAt:       time.Now().UTC(),
	}
	if err := isolatedDatabase.Create(&invalidUser).Error; err == nil {
		t.Fatal("expected account status database constraint to reject invalid state")
	}

	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	mailer := &recordingMailer{codes: map[string]string{}}
	service, err := identity.NewService(
		identitypostgres.NewStore(isolatedDatabase),
		testPasswords{},
		mailer,
		identity.ServiceOptions{Now: func() time.Time { return now }},
	)
	if err != nil {
		t.Fatalf("create identity service: %v", err)
	}
	handler := httpserver.NewRouter(nil)
	httpapi.NewHandler(service, httpapi.Config{
		AllowedOrigins:      []string{"http://app.test"},
		Now:                 func() time.Time { return now },
		RegistrationEnabled: true,
	}).RegisterRoutes(handler)

	registration := performJSONRequest(t, handler, http.MethodPost, "/v1/auth/register", `{
		"email":"Person@Example.COM",
		"password":"correct horse battery staple",
		"clientName":"Integration browser"
	}`, nil)
	if registration.Code != http.StatusCreated {
		t.Fatalf("register: expected status %d, got %d: %s", http.StatusCreated, registration.Code, registration.Body.String())
	}
	// A pending account has no session, so registration must set no cookie at all.
	if cookies := registration.Result().Cookies(); len(cookies) != 0 {
		t.Fatalf("register: pending response set cookies: %#v", cookies)
	}
	challenge := decodeChallengeResponse(t, registration)
	if challenge.User.Status != identity.AccountStatusPending || challenge.User.EmailVerified {
		t.Fatalf("register: unexpected account state %#v", challenge.User)
	}
	var pendingUser identitypostgres.UserModel
	if err := isolatedDatabase.Where("normalized_email = ?", "person@example.com").First(&pendingUser).Error; err != nil {
		t.Fatalf("load pending user: %v", err)
	}
	if pendingUser.Status != identity.AccountStatusPending || pendingUser.EmailVerifiedAt != nil {
		t.Fatalf("stored account is not pending: %#v", pendingUser)
	}

	// A pending account is excluded from every authorization path by the status
	// filters in SQL, even holding an otherwise-valid, unexpired, unrevoked session.
	pendingAccessToken := seedSession(t, isolatedDatabase, pendingUser.ID, "asn_pending_fixture_0001", now)
	if _, err := service.AuthenticateAccess(context.Background(), pendingAccessToken); !errors.Is(err, identity.ErrUnauthorized) {
		t.Fatalf("pending account authenticated: %v", err)
	}
	if err := service.AuthorizeAccount(context.Background(), pendingUser.ID); !errors.Is(err, identity.ErrUnauthorized) {
		t.Fatalf("pending account authorized: %v", err)
	}
	if err := service.AuthorizeSession(context.Background(), pendingUser.ID, "asn_pending_fixture_0001"); !errors.Is(err, identity.ErrUnauthorized) {
		t.Fatalf("pending session authorized: %v", err)
	}
	pendingAccount := performJSONRequest(t, handler, http.MethodGet, "/v1/account", "",
		map[string]string{"Authorization": "Bearer " + pendingAccessToken})
	if pendingAccount.Code != http.StatusUnauthorized {
		t.Fatalf("pending account access: expected status %d, got %d", http.StatusUnauthorized, pendingAccount.Code)
	}

	// Registering the same address again is answered identically, and creates nothing.
	duplicate := performJSONRequest(t, handler, http.MethodPost, "/v1/auth/register", `{
		"email":"person@example.com",
		"password":"another secure password",
		"clientName":"Integration browser"
	}`, nil)
	if duplicate.Code != http.StatusCreated {
		t.Fatalf("duplicate registration: expected status %d, got %d", http.StatusCreated, duplicate.Code)
	}
	decoy := decodeChallengeResponse(t, duplicate)
	if decoy.User.Status != challenge.User.Status || decoy.VerificationTicket == "" ||
		decoy.User.EmailVerified != challenge.User.EmailVerified || decoy.User.EmailBounced {
		t.Fatalf("duplicate registration is distinguishable: %#v vs %#v", decoy, challenge)
	}
	var userCount int64
	if err := isolatedDatabase.Model(&identitypostgres.UserModel{}).
		Where("normalized_email = ?", "person@example.com").Count(&userCount).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if userCount != 1 {
		t.Fatalf("duplicate registration created %d accounts", userCount)
	}

	// Only the right code activates the account, and only then is a session issued.
	code := mailer.codeFor(t, "Person@Example.COM")
	wrongCode := performJSONRequest(t, handler, http.MethodPost, "/v1/auth/verify-email",
		`{"verificationTicket":"`+challenge.VerificationTicket+`","code":"000000"}`, nil)
	if wrongCode.Code != http.StatusBadRequest {
		t.Fatalf("wrong code: expected status %d, got %d", http.StatusBadRequest, wrongCode.Code)
	}
	var storedVerification identitypostgres.EmailVerificationModel
	if err := isolatedDatabase.Where("user_id = ?", pendingUser.ID).First(&storedVerification).Error; err != nil {
		t.Fatalf("load verification: %v", err)
	}
	if storedVerification.Attempts != 1 {
		t.Fatalf("wrong code did not durably record an attempt: %d", storedVerification.Attempts)
	}
	if len(storedVerification.CodeHash) != sha256.Size || len(storedVerification.TicketHash) != sha256.Size {
		t.Fatal("verification secrets are not stored as hashes")
	}

	verification := performJSONRequest(t, handler, http.MethodPost, "/v1/auth/verify-email",
		`{"verificationTicket":"`+challenge.VerificationTicket+`","code":"`+code+`"}`, nil)
	if verification.Code != http.StatusOK {
		t.Fatalf("verify email: expected status %d, got %d: %s", http.StatusOK, verification.Code, verification.Body.String())
	}
	registerCookie := responseCookie(t, verification, "opencode_remote_refresh")
	if !registerCookie.HttpOnly || registerCookie.SameSite != http.SameSiteStrictMode || registerCookie.Path != "/v1/auth" {
		t.Fatalf("verify email: unsafe refresh cookie attributes: %#v", registerCookie)
	}
	registrationDocument := decodeAuthResponse(t, verification)
	if strings.Contains(verification.Body.String(), registerCookie.Value) {
		t.Fatal("verification body contains refresh credential")
	}
	// The challenge row is consumed, and the decoy ticket was never backed by one.
	if err := isolatedDatabase.Where("user_id = ?", pendingUser.ID).
		First(&identitypostgres.EmailVerificationModel{}).Error; err == nil {
		t.Fatal("the verification row survived a successful verification")
	}
	decoyVerify := performJSONRequest(t, handler, http.MethodPost, "/v1/auth/verify-email",
		`{"verificationTicket":"`+decoy.VerificationTicket+`","code":"`+code+`"}`, nil)
	if decoyVerify.Code != http.StatusBadRequest {
		t.Fatalf("decoy verification: expected status %d, got %d", http.StatusBadRequest, decoyVerify.Code)
	}

	account := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/v1/account",
		"",
		map[string]string{"Authorization": "Bearer " + registrationDocument.AccessToken},
	)
	if account.Code != http.StatusOK {
		t.Fatalf("account: expected status %d, got %d: %s", http.StatusOK, account.Code, account.Body.String())
	}
	registrationPrincipal, err := service.AuthenticateAccess(context.Background(), registrationDocument.AccessToken)
	if err != nil {
		t.Fatalf("authenticate registration access: %v", err)
	}
	if err := service.AuthorizeAccount(context.Background(), registrationPrincipal.Account.ID); err != nil {
		t.Fatalf("authorize active account: %v", err)
	}
	if err := service.AuthorizeSession(context.Background(), registrationPrincipal.Account.ID, registrationPrincipal.SessionID); err != nil {
		t.Fatalf("authorize active session: %v", err)
	}

	wrongPassword := performJSONRequest(t, handler, http.MethodPost, "/v1/auth/login", `{
		"email":"person@example.com",
		"password":"wrong password",
		"clientName":"Integration browser"
	}`, nil)
	if wrongPassword.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: expected status %d, got %d", http.StatusUnauthorized, wrongPassword.Code)
	}

	login := performJSONRequest(t, handler, http.MethodPost, "/v1/auth/login", `{
		"email":"person@example.com",
		"password":"correct horse battery staple",
		"clientName":"Second browser"
	}`, nil)
	if login.Code != http.StatusOK {
		t.Fatalf("login: expected status %d, got %d: %s", http.StatusOK, login.Code, login.Body.String())
	}
	loginCookie := responseCookie(t, login, "opencode_remote_refresh")
	loginDocument := decodeAuthResponse(t, login)
	loginPrincipal, err := service.AuthenticateAccess(context.Background(), loginDocument.AccessToken)
	if err != nil {
		t.Fatalf("authenticate login access: %v", err)
	}

	refresh := performCookieRequest(t, handler, "/v1/auth/refresh", registerCookie)
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh: expected status %d, got %d: %s", http.StatusOK, refresh.Code, refresh.Body.String())
	}
	rotatedDocument := decodeAuthResponse(t, refresh)
	rotatedCookie := responseCookie(t, refresh, "opencode_remote_refresh")
	if rotatedCookie.Value == registerCookie.Value {
		t.Fatal("refresh credential did not rotate")
	}
	if rotatedDocument.AccessToken == registrationDocument.AccessToken {
		t.Fatal("access credential did not rotate")
	}

	reuse := performCookieRequest(t, handler, "/v1/auth/refresh", registerCookie)
	if reuse.Code != http.StatusUnauthorized {
		t.Fatalf("refresh reuse: expected status %d, got %d", http.StatusUnauthorized, reuse.Code)
	}
	revokedAccount := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/v1/account",
		"",
		map[string]string{"Authorization": "Bearer " + rotatedDocument.AccessToken},
	)
	if revokedAccount.Code != http.StatusUnauthorized {
		t.Fatalf("reused family access: expected status %d, got %d", http.StatusUnauthorized, revokedAccount.Code)
	}

	logout := performCookieRequest(t, handler, "/v1/auth/logout", loginCookie)
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout: expected status %d, got %d", http.StatusNoContent, logout.Code)
	}
	loggedOutAccount := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/v1/account",
		"",
		map[string]string{"Authorization": "Bearer " + loginDocument.AccessToken},
	)
	if loggedOutAccount.Code != http.StatusUnauthorized {
		t.Fatalf("logged-out access: expected status %d, got %d", http.StatusUnauthorized, loggedOutAccount.Code)
	}
	if err := service.AuthorizeSession(context.Background(), registrationPrincipal.Account.ID, loginPrincipal.SessionID); !errors.Is(err, identity.ErrUnauthorized) {
		t.Fatalf("logged-out session authorization: expected unauthorized, got %v", err)
	}

	concurrentLogin := performJSONRequest(t, handler, http.MethodPost, "/v1/auth/login", `{
		"email":"person@example.com",
		"password":"correct horse battery staple",
		"clientName":"Concurrent refresh browser"
	}`, nil)
	if concurrentLogin.Code != http.StatusOK {
		t.Fatalf("concurrent login: expected status %d, got %d", http.StatusOK, concurrentLogin.Code)
	}
	concurrentCookie := responseCookie(t, concurrentLogin, "opencode_remote_refresh")
	responses := make(chan *httptest.ResponseRecorder, 2)
	var refreshes sync.WaitGroup
	refreshes.Add(2)
	for range 2 {
		go func() {
			defer refreshes.Done()
			responses <- performCookieRequest(t, handler, "/v1/auth/refresh", concurrentCookie)
		}()
	}
	refreshes.Wait()
	close(responses)
	statusCounts := map[int]int{}
	var concurrentlyRotatedAccess string
	for response := range responses {
		statusCounts[response.Code]++
		if response.Code == http.StatusOK {
			concurrentlyRotatedAccess = decodeAuthResponse(t, response).AccessToken
		}
	}
	if statusCounts[http.StatusOK] != 1 || statusCounts[http.StatusUnauthorized] != 1 {
		t.Fatalf("concurrent refresh statuses: %#v", statusCounts)
	}
	concurrentlyRevokedAccount := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/v1/account",
		"",
		map[string]string{"Authorization": "Bearer " + concurrentlyRotatedAccess},
	)
	if concurrentlyRevokedAccount.Code != http.StatusUnauthorized {
		t.Fatalf("concurrent refresh family access: expected status %d, got %d", http.StatusUnauthorized, concurrentlyRevokedAccount.Code)
	}

	expiringLogin := performJSONRequest(t, handler, http.MethodPost, "/v1/auth/login", `{
		"email":"person@example.com",
		"password":"correct horse battery staple",
		"clientName":"Expiring browser"
	}`, nil)
	if expiringLogin.Code != http.StatusOK {
		t.Fatalf("expiring login: expected status %d, got %d", http.StatusOK, expiringLogin.Code)
	}
	expiringCookie := responseCookie(t, expiringLogin, "opencode_remote_refresh")
	expiringDocument := decodeAuthResponse(t, expiringLogin)
	now = now.Add(31 * 24 * time.Hour)
	expiredAccount := performJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/v1/account",
		"",
		map[string]string{"Authorization": "Bearer " + expiringDocument.AccessToken},
	)
	if expiredAccount.Code != http.StatusUnauthorized {
		t.Fatalf("expired access: expected status %d, got %d", http.StatusUnauthorized, expiredAccount.Code)
	}
	expiredRefresh := performCookieRequest(t, handler, "/v1/auth/refresh", expiringCookie)
	if expiredRefresh.Code != http.StatusUnauthorized {
		t.Fatalf("expired refresh: expected status %d, got %d", http.StatusUnauthorized, expiredRefresh.Code)
	}

	if err := isolatedDatabase.Model(&identitypostgres.UserModel{}).
		Where("normalized_email = ?", "person@example.com").
		Update("status", identity.AccountStatusDisabled).Error; err != nil {
		t.Fatalf("disable account: %v", err)
	}
	if err := service.AuthorizeAccount(context.Background(), registrationPrincipal.Account.ID); !errors.Is(err, identity.ErrUnauthorized) {
		t.Fatalf("disabled account authorization: expected unauthorized, got %v", err)
	}
	disabledLogin := performJSONRequest(t, handler, http.MethodPost, "/v1/auth/login", `{
		"email":"person@example.com",
		"password":"correct horse battery staple",
		"clientName":"Disabled browser"
	}`, nil)
	if disabledLogin.Code != http.StatusUnauthorized {
		t.Fatalf("disabled login: expected status %d, got %d", http.StatusUnauthorized, disabledLogin.Code)
	}

	var reuseEvents int64
	if err := isolatedDatabase.Model(&identitypostgres.AuditEventModel{}).
		Where("event_type = ?", "auth.refresh_reuse_detected").
		Count(&reuseEvents).Error; err != nil {
		t.Fatalf("count refresh reuse events: %v", err)
	}
	if reuseEvents != 2 {
		t.Fatalf("expected two refresh reuse events, got %d", reuseEvents)
	}

	var storedUser identitypostgres.UserModel
	if err := isolatedDatabase.Where("normalized_email = ?", "person@example.com").First(&storedUser).Error; err != nil {
		t.Fatalf("load stored user: %v", err)
	}
	if storedUser.PasswordHash == nil ||
		*storedUser.PasswordHash == "correct horse battery staple" {
		t.Fatal("password was stored in plaintext")
	}
	var storedSessions []identitypostgres.SessionModel
	if err := isolatedDatabase.Find(&storedSessions).Error; err != nil {
		t.Fatalf("load stored sessions: %v", err)
	}
	for _, session := range storedSessions {
		if len(session.AccessTokenHash) != sha256.Size {
			t.Fatalf("session %s has a %d-byte access hash", session.ID, len(session.AccessTokenHash))
		}
	}
	var storedRefreshCredentials []identitypostgres.RefreshCredentialModel
	if err := isolatedDatabase.Find(&storedRefreshCredentials).Error; err != nil {
		t.Fatalf("load stored refresh credentials: %v", err)
	}
	for _, credential := range storedRefreshCredentials {
		if len(credential.TokenHash) != sha256.Size {
			t.Fatalf("refresh credential has a %d-byte hash", len(credential.TokenHash))
		}
	}
}

func TestEmailVerificationPersistence(t *testing.T) {
	isolatedDatabase := newIsolatedDatabase(t)
	now := time.Date(2026, 8, 31, 1, 0, 0, 0, time.UTC)
	mailer := &recordingMailer{codes: map[string]string{}}
	service, err := identity.NewService(
		identitypostgres.NewStore(isolatedDatabase),
		testPasswords{},
		mailer,
		identity.ServiceOptions{Now: func() time.Time { return now }},
	)
	if err != nil {
		t.Fatalf("create identity service: %v", err)
	}

	outcome, err := service.Register(context.Background(), identity.RegisterInput{
		Email:      "person@example.com",
		Password:   "correct horse battery staple",
		ClientName: "Integration client",
	})
	if err != nil || outcome.Verification == nil {
		t.Fatalf("register: %v", err)
	}
	challenge := *outcome.Verification

	t.Run("ticket hashes are unique", func(t *testing.T) {
		var existing identitypostgres.EmailVerificationModel
		if err := isolatedDatabase.Where("user_id = ?", challenge.Account.ID).First(&existing).Error; err != nil {
			t.Fatalf("load verification: %v", err)
		}
		second := identitypostgres.UserModel{
			ID:              "usr_second_account_000001",
			Email:           "second@example.com",
			NormalizedEmail: "second@example.com",
			PasswordHash:    stringPointer("not-a-real-hash"),
			Status:          identity.AccountStatusPending,
			CreatedAt:       now,
		}
		if err := isolatedDatabase.Create(&second).Error; err != nil {
			t.Fatalf("create second user: %v", err)
		}
		collision := existing
		collision.UserID = second.ID
		if err := isolatedDatabase.Create(&collision).Error; err == nil {
			t.Fatal("a duplicate ticket hash was accepted")
		}
		if err := isolatedDatabase.Delete(&second).Error; err != nil {
			t.Fatalf("delete second user: %v", err)
		}
	})

	// Verify and resend both lock the row FOR UPDATE, so they serialize rather than
	// racing: whichever runs second finds the challenge already gone or rotated.
	t.Run("concurrent verify and resend serialize", func(t *testing.T) {
		code := mailer.codeFor(t, "person@example.com")
		now = now.Add(identityResendInterval)
		type result struct {
			name string
			err  error
		}
		results := make(chan result, 2)
		var attempts sync.WaitGroup
		attempts.Add(2)
		go func() {
			defer attempts.Done()
			_, err := service.VerifyEmail(context.Background(), identity.VerifyEmailInput{
				Ticket: challenge.Ticket,
				Code:   code,
			})
			results <- result{name: "verify", err: err}
		}()
		go func() {
			defer attempts.Done()
			_, err := service.ResendVerification(context.Background(), challenge.Ticket)
			results <- result{name: "resend", err: err}
		}()
		attempts.Wait()
		close(results)

		succeeded := 0
		for outcome := range results {
			if outcome.err == nil {
				succeeded++
			} else if !errors.Is(outcome.err, identity.ErrInvalidVerificationCode) &&
				!errors.Is(outcome.err, identity.ErrVerificationThrottled) {
				t.Fatalf("%s failed unexpectedly: %v", outcome.name, outcome.err)
			}
		}
		if succeeded != 1 {
			t.Fatalf("%d of the two concurrent operations succeeded, want exactly 1", succeeded)
		}
	})

	t.Run("verifications cascade with the user", func(t *testing.T) {
		var user identitypostgres.UserModel
		if err := isolatedDatabase.Where("normalized_email = ?", "person@example.com").First(&user).Error; err != nil {
			t.Fatalf("load user: %v", err)
		}
		// Leave a challenge in place regardless of which concurrent path won above.
		if err := isolatedDatabase.Save(&identitypostgres.EmailVerificationModel{
			UserID:     user.ID,
			TicketHash: hashOf("cascade-ticket"),
			CodeHash:   hashOf("cascade-code"),
			ClientName: "Integration client",
			ExpiresAt:  now.Add(time.Hour),
			CreatedAt:  now,
		}).Error; err != nil {
			t.Fatalf("seed verification: %v", err)
		}
		if err := isolatedDatabase.Delete(&user).Error; err != nil {
			t.Fatalf("delete user: %v", err)
		}
		var remaining int64
		if err := isolatedDatabase.Model(&identitypostgres.EmailVerificationModel{}).
			Where("user_id = ?", user.ID).Count(&remaining).Error; err != nil {
			t.Fatalf("count verifications: %v", err)
		}
		if remaining != 0 {
			t.Fatalf("%d verification rows outlived the user", remaining)
		}
	})
}

func hashOf(value string) []byte {
	hash := sha256.Sum256([]byte(value))
	return hash[:]
}

// identityResendInterval mirrors the service's unexported minimumResendInterval.
// Tests here live outside the package, so the wait has to be stated rather than read.
const identityResendInterval = 30 * time.Second

// recordingMailer stands in for delivery so the test can read the code the user
// would have received.
type recordingMailer struct {
	mutex   sync.Mutex
	codes   map[string]string
	notices []string
}

func (mailer *recordingMailer) SendVerificationCode(_ context.Context, to, code string) error {
	mailer.mutex.Lock()
	defer mailer.mutex.Unlock()
	mailer.codes[to] = code
	return nil
}

func (mailer *recordingMailer) SendRegistrationNotice(_ context.Context, to string) error {
	mailer.mutex.Lock()
	defer mailer.mutex.Unlock()
	mailer.notices = append(mailer.notices, to)
	return nil
}

func (mailer *recordingMailer) codeFor(t *testing.T, to string) string {
	t.Helper()
	mailer.mutex.Lock()
	defer mailer.mutex.Unlock()
	code, ok := mailer.codes[to]
	if !ok {
		t.Fatalf("no verification code was mailed to %s", to)
	}
	return code
}

// seedSession inserts an otherwise-valid session directly, bypassing the service, so
// that a status check is the only thing that can reject it.
func seedSession(t *testing.T, database *gorm.DB, userID, sessionID string, now time.Time) string {
	t.Helper()
	// Build a token of the shape the service accepts, then store exactly the hash it
	// will derive from it, so the fixture is valid in every respect but account status.
	material := sha256.Sum256([]byte("seed-access-token:" + sessionID))
	accessToken := "ora_" + base64.RawURLEncoding.EncodeToString(material[:])
	accessHash := sha256.Sum256([]byte(accessToken))
	if err := database.Create(&identitypostgres.SessionModel{
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

type testPasswords struct{}

func (testPasswords) Hash(_ context.Context, password string) (string, error) {
	hash := sha256.Sum256([]byte(password))
	return "test$" + hex.EncodeToString(hash[:]), nil
}

func (testPasswords) Verify(ctx context.Context, password, encodedHash string) (bool, error) {
	actual, _ := (testPasswords{}).Hash(ctx, password)
	return actual == encodedHash, nil
}

type authResponse struct {
	AccessToken string `json:"accessToken"`
}

type accountDocument struct {
	ID            string `json:"id"`
	Status        string `json:"status"`
	EmailVerified bool   `json:"emailVerified"`
	EmailBounced  bool   `json:"emailBounced"`
}

type challengeResponse struct {
	User               accountDocument `json:"user"`
	VerificationTicket string          `json:"verificationTicket"`
}

func decodeChallengeResponse(t *testing.T, response *httptest.ResponseRecorder) challengeResponse {
	t.Helper()
	var document challengeResponse
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode verification challenge: %v", err)
	}
	if document.VerificationTicket == "" {
		t.Fatalf("response has no verification ticket: %s", response.Body)
	}
	if strings.Contains(response.Body.String(), "accessToken") {
		t.Fatal("a verification challenge carries an access token")
	}
	return document
}

func decodeAuthResponse(t *testing.T, response *httptest.ResponseRecorder) authResponse {
	t.Helper()
	var document authResponse
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode authentication response: %v", err)
	}
	if document.AccessToken == "" {
		t.Fatal("authentication response has no access token")
	}
	return document
}

func performJSONRequest(
	t *testing.T,
	handler http.Handler,
	method string,
	path string,
	body string,
	headers map[string]string,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("Origin", "http://app.test")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func performCookieRequest(
	t *testing.T,
	handler http.Handler,
	path string,
	cookie *http.Cookie,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("Origin", "http://app.test")
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func responseCookie(
	t *testing.T,
	response *httptest.ResponseRecorder,
	name string,
) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	t.Fatalf("response has no %s cookie", name)
	return nil
}

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
