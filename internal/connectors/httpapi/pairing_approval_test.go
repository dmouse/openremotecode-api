package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"opencode-remote/server/internal/connectors"
)

type approvalService struct {
	ConnectorService
	err                            error
	pairingID, secret, deviceKeyID string
}

func (service *approvalService) ApprovePairing(_ context.Context, pairingID, secret, deviceKeyID string) error {
	service.pairingID, service.secret, service.deviceKeyID = pairingID, secret, deviceKeyID
	return service.err
}

func TestApprovePairingHTTPContract(t *testing.T) {
	const secret = "orp_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	for _, tc := range []struct {
		name, token, body, origin string
		err                       error
		status                    int
	}{
		{name: "connector approves", token: "Pairing " + secret, body: `{"deviceKeyId":"device_key"}`, status: 204},
		{name: "missing secret", body: `{"deviceKeyId":"device_key"}`, status: 401},
		{name: "account token instead of pairing secret", token: "Bearer account-access", body: `{"deviceKeyId":"device_key"}`, status: 401},
		{name: "browser origin", token: "Pairing " + secret, body: `{"deviceKeyId":"device_key"}`, origin: "https://app.test", status: 403},
		{name: "unknown field", token: "Pairing " + secret, body: `{"deviceKeyId":"device_key","userId":"usr_x"}`, status: 400},
		{name: "different device", token: "Pairing " + secret, body: `{"deviceKeyId":"other"}`, err: connectors.ErrConflict, status: 409},
		{name: "rejected or expired", token: "Pairing " + secret, body: `{"deviceKeyId":"device_key"}`, err: connectors.ErrExpired, status: 410},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &approvalService{err: tc.err}
			request := httptest.NewRequest(http.MethodPost, "/v1/connector-pairings/par_target/approve", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			if tc.token != "" {
				request.Header.Set("Authorization", tc.token)
			}
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			response := httptest.NewRecorder()
			newTestHandler(accountRevocationAuth{}, service, Config{AllowedOrigins: []string{"https://app.test"}}).ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d", response.Code, tc.status)
			}
			if tc.status == 204 && (service.pairingID != "par_target" || service.secret != secret || service.deviceKeyID != "device_key") {
				t.Fatalf("approval reached the service with the wrong binding: %+v", service)
			}
			if (tc.status == 401 || tc.status == 403) && service.pairingID != "" {
				t.Fatal("an unauthenticated approval reached the service")
			}
		})
	}
}

type claimService struct {
	ConnectorService
	err error
}

func (service *claimService) ClaimPairing(context.Context, connectors.ClaimPairingInput) (connectors.ClaimPairingResult, error) {
	return connectors.ClaimPairingResult{}, service.err
}

// A mistyped code must be 404: clients treat 401 as a lost session and sign the user out.
func TestClaimPairingErrorContract(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		status     int
		code       string
		retryAfter string
	}{
		{name: "wrong code", err: connectors.ErrInvalidCode, status: 404, code: "invalid_code"},
		{name: "account over its budget", err: connectors.AttemptsExceededError{RetryAfter: 90*time.Second + time.Millisecond}, status: 429, code: "too_many_attempts", retryAfter: "91"},
		{name: "service over its budget", err: connectors.AttemptsExceededError{RetryAfter: time.Minute}, status: 429, code: "too_many_attempts", retryAfter: "60"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/connector-pairings/claim", strings.NewReader(
				`{"userCode":"ABCD-EFGH","deviceName":"Phone","identity":{"version":1,"suite":"s","keyId":"k","publicKey":"p"},"proof":{"challenge":"c","signature":"s"}}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", "Bearer account-access")
			response := httptest.NewRecorder()
			newTestHandler(accountRevocationAuth{}, &claimService{err: tc.err}, Config{}).ServeHTTP(response, request)
			if response.Code != tc.status || !strings.Contains(response.Body.String(), `"code":"`+tc.code+`"`) {
				t.Fatalf("response = %d %s, want %d %s", response.Code, response.Body.String(), tc.status, tc.code)
			}
			if response.Header().Get("Retry-After") != tc.retryAfter {
				t.Fatalf("Retry-After = %q, want %q", response.Header().Get("Retry-After"), tc.retryAfter)
			}
		})
	}
}
