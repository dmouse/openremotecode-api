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

type deviceRevocationService struct {
	ConnectorService
	err      error
	userID   string
	deviceID string
}

func (service *deviceRevocationService) RevokeAccountDevice(_ context.Context, userID, deviceID string) error {
	service.userID, service.deviceID = userID, deviceID
	return service.err
}

func (service *deviceRevocationService) ListDevices(_ context.Context, userID string) ([]connectors.Device, error) {
	service.userID = userID
	return []connectors.Device{{
		ID: "dev_phone", UserID: userID, Name: "Phone",
		Identity:       connectors.PublicIdentity{Version: 1, Suite: "suite", KeyID: "key", PublicKey: "public"},
		CredentialHash: []byte("secret-hash"), CreatedAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
	}}, service.err
}

func TestAccountDeviceRevocationHTTPContract(t *testing.T) {
	for _, tc := range []struct {
		name, token, origin, site, cookie string
		err                               error
		status                            int
	}{
		{name: "native owner", token: "Bearer account-access", status: 204},
		{name: "owner without the device cookie", token: "Bearer account-access", status: 204},
		{name: "allowed browser", token: "Bearer account-access", origin: "https://app.test", status: 204},
		{name: "missing auth", status: 401},
		{name: "device cookie alone", cookie: "ord_" + strings.Repeat("A", 43), status: 401},
		{name: "connector credential rejected", token: "Bearer orc_secret", status: 401},
		{name: "foreign or absent", token: "Bearer account-access", err: connectors.ErrNotFound, status: 404},
		{name: "invalid", token: "Bearer account-access", err: connectors.ErrInvalidInput, status: 400},
		{name: "untrusted origin", token: "Bearer account-access", origin: "https://other.test", status: 403},
		{name: "cross site", token: "Bearer account-access", site: "cross-site", status: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &deviceRevocationService{err: tc.err}
			request := httptest.NewRequest(http.MethodPost, "/v1/devices/dev_target/revoke", nil)
			request.Header.Set("Authorization", tc.token)
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("Sec-Fetch-Site", tc.site)
			if tc.cookie != "" {
				request.AddCookie(&http.Cookie{Name: secureDeviceCookieName, Value: tc.cookie})
			}
			response := httptest.NewRecorder()
			newTestHandler(accountRevocationAuth{}, service, Config{AllowedOrigins: []string{"https://app.test"}, CookieSecure: true}).ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d", response.Code, tc.status)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing cache protection")
			}
			if tc.status == 204 && (response.Body.Len() != 0 || service.userID != "usr_owner" || service.deviceID != "dev_target") {
				t.Fatal("incorrect account-scoped revocation")
			}
			if (tc.status == 401 || tc.status == 403) && service.userID != "" {
				t.Fatal("unauthorized request reached service")
			}
		})
	}
}

func TestListDevicesHTTPContract(t *testing.T) {
	service := &deviceRevocationService{}
	request := httptest.NewRequest(http.MethodGet, "/v1/devices", nil)
	request.Header.Set("Authorization", "Bearer account-access")
	response := httptest.NewRecorder()
	newTestHandler(accountRevocationAuth{}, service, Config{}).ServeHTTP(response, request)
	if response.Code != http.StatusOK || service.userID != "usr_owner" {
		t.Fatalf("status = %d, user = %q", response.Code, service.userID)
	}
	if strings.Contains(response.Body.String(), "secret-hash") || strings.Contains(response.Body.String(), "usr_owner") {
		t.Fatal("device inventory leaked credential or account fields")
	}
	var body struct {
		Devices []map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Devices) != 1 || body.Devices[0]["id"] != "dev_phone" || len(body.Devices[0]) != 4 {
		t.Fatalf("wrong device inventory contract: %v", body.Devices)
	}

	unauthenticated := httptest.NewRecorder()
	newTestHandler(accountRevocationAuth{}, &deviceRevocationService{}, Config{}).
		ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodGet, "/v1/devices", nil))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", unauthenticated.Code)
	}
}
