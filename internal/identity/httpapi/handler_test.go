package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"opencode-remote/server/internal/identity"
	"opencode-remote/server/internal/platform/httpserver"
)

func newTestHandler(service AuthenticationService, config Config) http.Handler {
	router := httpserver.NewRouter(config.Logger)
	NewHandler(service, config).RegisterRoutes(router)
	return router
}

type stubAuthenticationService struct {
	registerCalls int
	loginCalls    int
	googleCalls   int
	verifyCalls   int
	resendCalls   int

	// Set these to drive a successful response; otherwise each call returns the
	// sentinel its route maps to.
	outcome     identity.AuthOutcome
	challenge   identity.VerificationChallenge
	credentials identity.Credentials
	err         error
	// googleInput records what the route forwarded, so a test can assert the
	// transport passes the token through unchanged.
	googleInput identity.GoogleAuthInput
}

func (service *stubAuthenticationService) Register(
	context.Context,
	identity.RegisterInput,
) (identity.AuthOutcome, error) {
	service.registerCalls++
	if service.err != nil {
		return identity.AuthOutcome{}, service.err
	}
	if service.outcome.Credentials == nil && service.outcome.Verification == nil {
		return identity.AuthOutcome{}, identity.ErrInvalidInput
	}
	return service.outcome, nil
}

func (service *stubAuthenticationService) Login(
	context.Context,
	identity.LoginInput,
) (identity.AuthOutcome, error) {
	service.loginCalls++
	if service.err != nil {
		return identity.AuthOutcome{}, service.err
	}
	if service.outcome.Credentials == nil && service.outcome.Verification == nil {
		return identity.AuthOutcome{}, identity.ErrInvalidCredentials
	}
	return service.outcome, nil
}

func (service *stubAuthenticationService) AuthenticateWithGoogle(
	_ context.Context,
	input identity.GoogleAuthInput,
) (identity.Credentials, error) {
	service.googleCalls++
	service.googleInput = input
	if service.err != nil {
		return identity.Credentials{}, service.err
	}
	if service.credentials.AccessToken == "" {
		return identity.Credentials{}, identity.ErrInvalidGoogleToken
	}
	return service.credentials, nil
}

func (service *stubAuthenticationService) VerifyEmail(
	context.Context,
	identity.VerifyEmailInput,
) (identity.AuthOutcome, error) {
	service.verifyCalls++
	if service.err != nil {
		return identity.AuthOutcome{}, service.err
	}
	if service.outcome.Credentials == nil && service.outcome.Verification == nil {
		return identity.AuthOutcome{}, identity.ErrInvalidVerificationCode
	}
	return service.outcome, nil
}

func (service *stubAuthenticationService) ResendVerification(
	context.Context,
	string,
) (identity.VerificationChallenge, error) {
	service.resendCalls++
	if service.err != nil {
		return identity.VerificationChallenge{}, service.err
	}
	if service.challenge.Ticket == "" {
		return identity.VerificationChallenge{}, identity.ErrInvalidVerificationCode
	}
	return service.challenge, nil
}

func (*stubAuthenticationService) Refresh(
	context.Context,
	string,
) (identity.Credentials, error) {
	return identity.Credentials{}, identity.ErrInvalidRefresh
}

func (*stubAuthenticationService) Logout(context.Context, string) error { return nil }

func (*stubAuthenticationService) CurrentAccount(
	context.Context,
	string,
) (identity.Account, error) {
	return identity.Account{}, identity.ErrUnauthorized
}

func TestHandlerRejectsUnknownJSONFields(t *testing.T) {
	service := &stubAuthenticationService{}
	handler := newTestHandler(service, Config{AllowedOrigins: []string{"http://app.test"}, RegistrationEnabled: true})
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"email":"person@example.com","password":"secret","clientName":"Browser","unexpected":true}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://app.test")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, response.Code)
	}
	if service.loginCalls != 0 {
		t.Fatal("service must not receive invalid transport input")
	}
}

func TestDisabledRegistrationRejectsRequests(t *testing.T) {
	service := &stubAuthenticationService{}
	handler := newTestHandler(service, Config{AllowedOrigins: []string{"http://app.test"}})
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/register",
		strings.NewReader(`{"email":"person@example.com","password":"a secure password","clientName":"Browser"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://app.test")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status %d, got %d", http.StatusServiceUnavailable, response.Code)
	}
	if service.registerCalls != 0 {
		t.Fatal("disabled registration must not call the service")
	}
}

func TestHandlerRejectsCrossOriginAuthentication(t *testing.T) {
	service := &stubAuthenticationService{}
	handler := newTestHandler(service, Config{AllowedOrigins: []string{"http://app.test"}})
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"email":"person@example.com","password":"secret","clientName":"Browser"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("expected status %d, got %d", http.StatusForbidden, response.Code)
	}
	if service.loginCalls != 0 {
		t.Fatal("service must not receive cross-origin input")
	}
}

func TestEmptyOriginAllowlistAcceptsNativeLoginOnly(t *testing.T) {
	for _, test := range []struct {
		name       string
		origin     string
		fetchSite  string
		wantStatus int
		wantCalls  int
	}{
		{name: "native", wantStatus: http.StatusUnauthorized, wantCalls: 1},
		{name: "former testing client", origin: "http://127.0.0.1:5173", wantStatus: http.StatusForbidden},
		{name: "foreign origin", origin: "https://attacker.example", wantStatus: http.StatusForbidden},
		{name: "cross-site without origin", fetchSite: "cross-site", wantStatus: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &stubAuthenticationService{}
			handler := newTestHandler(service, Config{})
			request := httptest.NewRequest(http.MethodPost, "/v1/auth/login",
				strings.NewReader(`{"email":"person@example.com","password":"secret","clientName":"Mobile"}`))
			request.Header.Set("Content-Type", "application/json")
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.fetchSite != "" {
				request.Header.Set("Sec-Fetch-Site", test.fetchSite)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.wantStatus || service.loginCalls != test.wantCalls {
				t.Fatalf("status = %d, service calls = %d; want %d, %d",
					response.Code, service.loginCalls, test.wantStatus, test.wantCalls)
			}
		})
	}
}

func TestLoginRateLimit(t *testing.T) {
	service := &stubAuthenticationService{}
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	handler := newTestHandler(service, Config{
		AllowedOrigins: []string{"http://app.test"},
		Now:            func() time.Time { return now },
	})

	for attempt := 1; attempt <= 11; attempt++ {
		if attempt == 11 {
			now = now.Add(58*time.Second + 600*time.Millisecond)
		}
		request := httptest.NewRequest(
			http.MethodPost,
			"/v1/auth/login",
			strings.NewReader(`{"email":"person@example.com","password":"secret","clientName":"Browser"}`),
		)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Origin", "http://app.test")
		request.RemoteAddr = "192.0.2.1:3000"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if attempt <= 10 && response.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected status %d, got %d", attempt, http.StatusUnauthorized, response.Code)
		}
		if attempt == 11 {
			if response.Code != http.StatusTooManyRequests {
				t.Fatalf("expected status %d, got %d", http.StatusTooManyRequests, response.Code)
			}
			if response.Header().Get("Retry-After") != "2" {
				t.Fatalf("unexpected Retry-After %q", response.Header().Get("Retry-After"))
			}
		}
	}
	if service.loginCalls != 10 {
		t.Fatalf("expected 10 service calls, got %d", service.loginCalls)
	}
}

func TestCurrentAccountRequiresOneBearerCredential(t *testing.T) {
	service := &stubAuthenticationService{}
	handler := newTestHandler(service, Config{})
	request := httptest.NewRequest(http.MethodGet, "/v1/account", nil)
	request.Header.Add("Authorization", "Bearer first")
	request.Header.Add("Authorization", "Bearer second")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, response.Code)
	}
	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatal("expected Bearer challenge")
	}
}

func TestSecureRefreshCookieIsHostBound(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	handler := NewHandler(&stubAuthenticationService{}, Config{
		CookieSecure: true,
		Now:          func() time.Time { return now },
	})
	response := httptest.NewRecorder()
	handler.setRefreshCookie(response, identity.Credentials{
		RefreshToken:          "refresh-token",
		RefreshTokenExpiresAt: now.Add(time.Hour),
	})
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one cookie, got %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != secureRefreshCookieName || cookie.Path != "/" || !cookie.Secure || !cookie.HttpOnly {
		t.Fatalf("secure refresh cookie is not host-bound: %#v", cookie)
	}
}

func TestClientAddressTrustsOnlyConfiguredProxies(t *testing.T) {
	_, trustedProxy, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("parse trusted proxy: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/login", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.7")
	if address := clientAddress(request, []*net.IPNet{trustedProxy}); address != "192.0.2.10" {
		t.Fatalf("untrusted peer spoofed client address as %q", address)
	}

	request.RemoteAddr = "10.0.0.4:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.3")
	if address := clientAddress(request, []*net.IPNet{trustedProxy}); address != "198.51.100.7" {
		t.Fatalf("expected forwarded client address, got %q", address)
	}
}

func TestHandlerReturnsGenericInternalError(t *testing.T) {
	service := &failingAuthenticationService{stubAuthenticationService: stubAuthenticationService{}}
	handler := newTestHandler(service, Config{AllowedOrigins: []string{"http://app.test"}})
	request := httptest.NewRequest(
		http.MethodPost,
		"/v1/auth/login",
		strings.NewReader(`{"email":"person@example.com","password":"secret","clientName":"Browser"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://app.test")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, response.Code)
	}
	if strings.Contains(response.Body.String(), "sensitive") {
		t.Fatalf("response leaked internal error: %s", response.Body.String())
	}
}

// A pending account has nothing to refresh, so no response that carries a
// verification challenge may set a refresh cookie — on any route.
func TestVerificationChallengeResponsesCarryNoCookie(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	challenge := identity.VerificationChallenge{
		Account: identity.Account{
			ID:        "usr_pending_account_000001",
			Email:     "person@example.com",
			Status:    identity.AccountStatusPending,
			CreatedAt: now,
		},
		Ticket:          "vft_ticket",
		TicketExpiresAt: now.Add(10 * time.Minute),
	}
	for _, test := range []struct {
		name       string
		path       string
		body       string
		wantStatus int
	}{
		{
			name:       "register",
			path:       "/v1/auth/register",
			body:       `{"email":"person@example.com","password":"a secure password","clientName":"Mobile"}`,
			wantStatus: http.StatusCreated,
		},
		{
			name:       "login against a pending account",
			path:       "/v1/auth/login",
			body:       `{"email":"person@example.com","password":"a secure password","clientName":"Mobile"}`,
			wantStatus: http.StatusOK,
		},
		{
			name:       "resend",
			path:       "/v1/auth/resend-verification",
			body:       `{"verificationTicket":"vft_ticket"}`,
			wantStatus: http.StatusOK,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &stubAuthenticationService{
				outcome:   identity.AuthOutcome{Verification: &challenge},
				challenge: challenge,
			}
			handler := newTestHandler(service, Config{
				AllowedOrigins:      []string{"http://app.test"},
				RegistrationEnabled: true,
				Now:                 func() time.Time { return now },
			})
			response := performRequest(handler, test.path, test.body)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", response.Code, test.wantStatus, response.Body)
			}
			if cookies := response.Result().Cookies(); len(cookies) != 0 {
				t.Fatalf("pending response set %d cookies: %#v", len(cookies), cookies)
			}
			var document struct {
				VerificationTicket string `json:"verificationTicket"`
				AccessToken        string `json:"accessToken"`
				User               struct {
					Status string `json:"status"`
				} `json:"user"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if document.VerificationTicket != challenge.Ticket {
				t.Fatalf("verification ticket = %q", document.VerificationTicket)
			}
			if document.AccessToken != "" {
				t.Fatal("pending response carries an access token")
			}
			if document.User.Status != identity.AccountStatusPending {
				t.Fatalf("account status = %q", document.User.Status)
			}
		})
	}
}

// Verifying is the one path that turns a challenge into a session, so it is the one
// path where the cookie must appear.
func TestVerifyEmailSuccessIssuesSession(t *testing.T) {
	now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
	credentials := identity.Credentials{
		Account: identity.Account{
			ID:              "usr_verified_account_00001",
			Email:           "person@example.com",
			Status:          identity.AccountStatusActive,
			EmailVerifiedAt: &now,
			CreatedAt:       now,
		},
		AccessToken:           "ora_access",
		AccessTokenExpiresAt:  now.Add(15 * time.Minute),
		RefreshToken:          "orr_refresh",
		RefreshTokenExpiresAt: now.Add(24 * time.Hour),
	}
	service := &stubAuthenticationService{
		outcome: identity.AuthOutcome{Credentials: &credentials},
	}
	handler := newTestHandler(service, Config{
		AllowedOrigins: []string{"http://app.test"},
		Now:            func() time.Time { return now },
	})
	response := performRequest(
		handler,
		"/v1/auth/verify-email",
		`{"verificationTicket":"vft_ticket","code":"123456"}`,
	)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body)
	}
	if service.verifyCalls != 1 {
		t.Fatalf("service calls = %d, want 1", service.verifyCalls)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != credentials.RefreshToken {
		t.Fatalf("expected one refresh cookie, got %#v", cookies)
	}
	if strings.Contains(response.Body.String(), credentials.RefreshToken) {
		t.Fatal("response body contains the refresh credential")
	}
}

func TestVerificationErrorsMapToStatuses(t *testing.T) {
	for _, test := range []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "wrong code",
			err:        identity.ErrInvalidVerificationCode,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_verification_code",
		},
		{
			name:       "resend cooldown",
			err:        identity.ErrVerificationThrottled,
			wantStatus: http.StatusTooManyRequests,
			wantCode:   "rate_limited",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &stubAuthenticationService{err: test.err}
			handler := newTestHandler(service, Config{AllowedOrigins: []string{"http://app.test"}})
			response := performRequest(
				handler,
				"/v1/auth/verify-email",
				`{"verificationTicket":"vft_ticket","code":"123456"}`,
			)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			var document struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if document.Code != test.wantCode {
				t.Fatalf("error code = %q, want %q", document.Code, test.wantCode)
			}
		})
	}
}

func TestVerificationRoutesAreRateLimited(t *testing.T) {
	for _, test := range []struct {
		name    string
		path    string
		body    string
		allowed int
	}{
		{
			name:    "verify email",
			path:    "/v1/auth/verify-email",
			body:    `{"verificationTicket":"vft_ticket","code":"123456"}`,
			allowed: 10,
		},
		{
			name:    "resend verification",
			path:    "/v1/auth/resend-verification",
			body:    `{"verificationTicket":"vft_ticket"}`,
			allowed: 3,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC)
			service := &stubAuthenticationService{}
			handler := newTestHandler(service, Config{
				AllowedOrigins: []string{"http://app.test"},
				Now:            func() time.Time { return now },
			})
			for attempt := 1; attempt <= test.allowed; attempt++ {
				if response := performRequest(handler, test.path, test.body); response.Code == http.StatusTooManyRequests {
					t.Fatalf("attempt %d was rate limited early", attempt)
				}
			}
			if response := performRequest(handler, test.path, test.body); response.Code != http.StatusTooManyRequests {
				t.Fatalf("attempt %d: status = %d, want %d", test.allowed+1, response.Code, http.StatusTooManyRequests)
			}
		})
	}
}

func performRequest(handler http.Handler, path, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://app.test")
	request.RemoteAddr = "192.0.2.10:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type failingAuthenticationService struct {
	stubAuthenticationService
}

func (*failingAuthenticationService) Login(
	context.Context,
	identity.LoginInput,
) (identity.AuthOutcome, error) {
	return identity.AuthOutcome{}, errors.New("sensitive database detail")
}

const googleRequestBody = `{"idToken":"header.payload.signature","clientName":"Open Remote Code Mobile"}`

func TestGoogleSignInIssuesSessionAndCookie(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	service := &stubAuthenticationService{credentials: identity.Credentials{
		Account: identity.Account{
			ID:        "usr_google_account_00001",
			Email:     "person@example.com",
			Status:    identity.AccountStatusActive,
			CreatedAt: now,
		},
		AccessToken:           "ora_access",
		AccessTokenExpiresAt:  now.Add(15 * time.Minute),
		RefreshToken:          "orr_refresh",
		RefreshTokenExpiresAt: now.Add(24 * time.Hour),
	}}
	handler := newTestHandler(service, Config{
		AllowedOrigins: []string{"http://app.test"},
		Now:            func() time.Time { return now },
	})

	response := performRequest(handler, "/v1/auth/google", googleRequestBody)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
	}
	if service.googleInput.IDToken != "header.payload.signature" {
		t.Fatalf("forwarded token = %q, want it passed through unchanged", service.googleInput.IDToken)
	}
	if service.googleInput.ClientName != "Open Remote Code Mobile" {
		t.Fatalf("forwarded client name = %q", service.googleInput.ClientName)
	}

	var document credentialsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if document.AccessToken != "ora_access" {
		t.Fatalf("access token = %q, want ora_access", document.AccessToken)
	}
	// The refresh credential must arrive the same way it does on the password path,
	// so the client's storage and rotation code needs no federated special case.
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != "orr_refresh" || !cookies[0].HttpOnly {
		t.Fatalf("google sign-in did not set the refresh cookie: %#v", cookies)
	}
}

// A verification challenge would leave the client waiting for a code that is never
// sent. The federated route must only ever answer with a session or an error.
func TestGoogleSignInNeverReturnsAVerificationChallenge(t *testing.T) {
	service := &stubAuthenticationService{}
	handler := newTestHandler(service, Config{AllowedOrigins: []string{"http://app.test"}})

	response := performRequest(handler, "/v1/auth/google", googleRequestBody)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
	if strings.Contains(response.Body.String(), "verificationTicket") {
		t.Fatalf("google response carried a verification ticket: %s", response.Body.String())
	}
}

func TestGoogleErrorsMapToStatuses(t *testing.T) {
	for name, test := range map[string]struct {
		err        error
		wantStatus int
		wantCode   string
	}{
		"invalid token": {
			err:        identity.ErrInvalidGoogleToken,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_google_token",
		},
		"link required": {
			err:        identity.ErrAccountLinkRequired,
			wantStatus: http.StatusConflict,
			wantCode:   "account_link_required",
		},
		"identity conflict": {
			err:        identity.ErrIdentityAlreadyLinked,
			wantStatus: http.StatusConflict,
			wantCode:   "account_identity_conflict",
		},
		"not configured": {
			err:        identity.ErrGoogleUnavailable,
			wantStatus: http.StatusServiceUnavailable,
			wantCode:   "google_signin_unavailable",
		},
		"disabled account": {
			err:        identity.ErrInvalidCredentials,
			wantStatus: http.StatusUnauthorized,
			wantCode:   "invalid_credentials",
		},
		"invalid client name": {
			err:        identity.ErrInvalidInput,
			wantStatus: http.StatusBadRequest,
			wantCode:   "invalid_request",
		},
	} {
		t.Run(name, func(t *testing.T) {
			service := &stubAuthenticationService{err: test.err}
			handler := newTestHandler(service, Config{AllowedOrigins: []string{"http://app.test"}})

			response := performRequest(handler, "/v1/auth/google", googleRequestBody)

			if response.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, test.wantStatus)
			}
			var document struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if document.Code != test.wantCode {
				t.Fatalf("error code = %q, want %q", document.Code, test.wantCode)
			}
			if len(response.Result().Cookies()) != 0 {
				t.Fatal("a failed google sign-in must not set a cookie")
			}
		})
	}
}

// The route needs its own budget: sharing login's would let either route exhaust
// the other's, so a burst of bad passwords would lock out Google sign-in too.
func TestGoogleRateLimitIsIndependentOfLogin(t *testing.T) {
	now := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	service := &stubAuthenticationService{}
	handler := newTestHandler(service, Config{
		AllowedOrigins: []string{"http://app.test"},
		Now:            func() time.Time { return now },
	})

	for range 10 {
		performRequest(handler, "/v1/auth/google", googleRequestBody)
	}
	if response := performRequest(handler, "/v1/auth/google", googleRequestBody); response.Code != http.StatusTooManyRequests {
		t.Fatalf("eleventh google request status = %d, want %d", response.Code, http.StatusTooManyRequests)
	}
	// Login must still have its full allowance.
	login := performRequest(handler, "/v1/auth/login",
		`{"email":"person@example.com","password":"secret","clientName":"Mobile"}`)
	if login.Code == http.StatusTooManyRequests {
		t.Fatal("exhausting the google budget must not rate limit password login")
	}
}

// The federated route sits inside the same /v1/auth group and must inherit its
// origin gate rather than quietly opting out of it.
func TestGoogleSignInRejectsCrossOriginRequests(t *testing.T) {
	service := &stubAuthenticationService{}
	handler := newTestHandler(service, Config{AllowedOrigins: []string{"http://app.test"}})
	request := httptest.NewRequest(http.MethodPost, "/v1/auth/google", strings.NewReader(googleRequestBody))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "https://attacker.example")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
	if service.googleCalls != 0 {
		t.Fatal("service must not receive cross-origin input")
	}
}

// Google sign-in is not gated on RegistrationEnabled: that switch governs the
// mailed-code flow, and turning it off must not lock out accounts that already
// exist. An operator disables this route by unsetting the audiences instead.
func TestGoogleSignInIgnoresRegistrationSwitch(t *testing.T) {
	service := &stubAuthenticationService{}
	handler := newTestHandler(service, Config{
		AllowedOrigins:      []string{"http://app.test"},
		RegistrationEnabled: false,
	})

	response := performRequest(handler, "/v1/auth/google", googleRequestBody)

	if response.Code == http.StatusServiceUnavailable {
		t.Fatal("disabled registration must not disable google sign-in")
	}
	if service.googleCalls != 1 {
		t.Fatalf("service received %d google calls, want 1", service.googleCalls)
	}
}
