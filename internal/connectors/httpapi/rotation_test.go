package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"opencode-remote/server/internal/connectors"
)

type rotationService struct {
	ConnectorService
	rotateCalls   []string
	activateCalls []string
	rotateErr     error
	activateErr   error
	activateBy    time.Time
	expiresAt     time.Time
}

func (service *rotationService) RotateConnectorCredential(_ context.Context, credential string) (connectors.RotationResult, error) {
	service.rotateCalls = append(service.rotateCalls, credential)
	if service.rotateErr != nil {
		return connectors.RotationResult{}, service.rotateErr
	}
	return connectors.RotationResult{Credential: "orc_" + strings.Repeat("N", 43), ActivateBy: service.activateBy}, nil
}

func (service *rotationService) ActivateConnectorCredential(_ context.Context, credential string) (time.Time, error) {
	service.activateCalls = append(service.activateCalls, credential)
	if service.activateErr != nil {
		return time.Time{}, service.activateErr
	}
	return service.expiresAt, nil
}

func rotationRequest(t *testing.T, service *rotationService, path, token string, browserOrigin bool) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, nil)
	if token != "" {
		request.Header.Set("Authorization", token)
	}
	if browserOrigin {
		request.Header.Set("Origin", "https://example.test")
	}
	response := httptest.NewRecorder()
	newTestHandler(accountRevocationAuth{}, service, Config{}).ServeHTTP(response, request)
	return response
}

func TestRotateConnectorHTTPContract(t *testing.T) {
	activateBy := time.Date(2026, 3, 5, 12, 0, 0, 0, time.UTC)
	credential := "orc_" + strings.Repeat("A", 43)

	service := &rotationService{activateBy: activateBy}
	response := rotationRequest(t, service, "/v1/connectors/self/rotate", "Bearer "+credential, false)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", response.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 2 || !strings.HasPrefix(body["credential"], "orc_") || body["activateBy"] != activateBy.Format(time.RFC3339Nano) {
		t.Fatalf("wrong rotation contract: %v", body)
	}
	if len(service.rotateCalls) != 1 || service.rotateCalls[0] != credential {
		t.Fatalf("service saw %v", service.rotateCalls)
	}

	// The credential authenticates the call; an absent one never reaches the service.
	service = &rotationService{activateBy: activateBy}
	if response := rotationRequest(t, service, "/v1/connectors/self/rotate", "", false); response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
	if len(service.rotateCalls) != 0 {
		t.Fatal("unauthenticated request reached the service")
	}

	// Rotation is a plugin route, so a browser origin is refused before the service.
	service = &rotationService{activateBy: activateBy}
	if response := rotationRequest(t, service, "/v1/connectors/self/rotate", "Bearer "+credential, true); response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
	if len(service.rotateCalls) != 0 {
		t.Fatal("cross-origin request reached the service")
	}

	// A rejected credential is reported without distinguishing why.
	service = &rotationService{rotateErr: connectors.ErrUnauthorized}
	if response := rotationRequest(t, service, "/v1/connectors/self/rotate", "Bearer "+credential, false); response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}

func TestActivateConnectorHTTPContract(t *testing.T) {
	expiresAt := time.Date(2026, 6, 1, 9, 30, 0, 0, time.UTC)
	pending := "orc_" + strings.Repeat("N", 43)

	service := &rotationService{expiresAt: expiresAt}
	response := rotationRequest(t, service, "/v1/connectors/self/rotate/activate", "Bearer "+pending, false)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body) != 1 || body["credentialExpiresAt"] != expiresAt.Format(time.RFC3339Nano) {
		t.Fatalf("wrong activation contract: %v", body)
	}
	// Activation is authenticated by the pending credential, not the live one.
	if len(service.activateCalls) != 1 || service.activateCalls[0] != pending {
		t.Fatalf("service saw %v", service.activateCalls)
	}

	service = &rotationService{expiresAt: expiresAt}
	if response := rotationRequest(t, service, "/v1/connectors/self/rotate/activate", "", false); response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
	if len(service.activateCalls) != 0 {
		t.Fatal("unauthenticated request reached the service")
	}

	// A lapsed or already-cancelled rotation is rejected as unauthorized.
	service = &rotationService{activateErr: connectors.ErrUnauthorized}
	if response := rotationRequest(t, service, "/v1/connectors/self/rotate/activate", "Bearer "+pending, false); response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", response.Code)
	}
}
