package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"opencode-remote/server/internal/connectors"
	"opencode-remote/server/internal/identity"
	"opencode-remote/server/internal/platform/httpserver"
)

func newTestHandler(authentication AuthenticationService, service ConnectorService, config Config) http.Handler {
	router := httpserver.NewRouter(config.Logger)
	NewHandler(authentication, service, config).RegisterRoutes(router)
	return router
}

type revocationService struct {
	ConnectorService
	credential  string
	err         error
	userID      string
	connectorID string
}

func (service *revocationService) RevokeAccountConnector(_ context.Context, userID, connectorID string) error {
	service.userID, service.connectorID = userID, connectorID
	return service.err
}

func (service *revocationService) RenameAccountConnector(_ context.Context, userID, connectorID, name string) (connectors.Connector, error) {
	service.userID, service.connectorID = userID, connectorID
	return connectors.Connector{ID: connectorID, Name: name}, service.err
}

func TestAccountRenameHTTPContract(t *testing.T) {
	for _, tc := range []struct {
		name, token, body string
		err               error
		status            int
	}{
		{name: "owner", token: "Bearer account-access", body: `{"name":"Work laptop"}`, status: 200},
		{name: "missing auth", body: `{"name":"Work laptop"}`, status: 401},
		{name: "foreign", token: "Bearer account-access", body: `{"name":"Work laptop"}`, err: connectors.ErrNotFound, status: 404},
		{name: "spoofed account", token: "Bearer account-access", body: `{"name":"Work laptop","userId":"usr_other"}`, status: 400},
		{name: "invalid JSON", token: "Bearer account-access", body: `{`, status: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &revocationService{err: tc.err}
			request := httptest.NewRequest(http.MethodPost, "/v1/connectors/con_target/rename", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Authorization", tc.token)
			response := httptest.NewRecorder()
			newTestHandler(accountRevocationAuth{}, service, Config{}).ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d", response.Code, tc.status)
			}
			if tc.status == 200 {
				var body map[string]string
				if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if body["name"] != "Work laptop" || body["connectorId"] != "con_target" || service.userID != "usr_owner" || len(body) != 2 {
					t.Fatal("wrong rename contract")
				}
			}
		})
	}
}

type accountRevocationAuth struct{}

func (accountRevocationAuth) AuthenticateAccess(_ context.Context, token string) (identity.AccessPrincipal, error) {
	if token != "account-access" {
		return identity.AccessPrincipal{}, errors.New("unauthorized")
	}
	return identity.AccessPrincipal{Account: identity.Account{ID: "usr_owner"}}, nil
}

func TestAccountConnectorRevocationHTTPContract(t *testing.T) {
	for _, tc := range []struct {
		name, token, origin, site string
		err                       error
		status                    int
	}{
		{name: "native owner", token: "Bearer account-access", status: 204},
		{name: "allowed browser", token: "Bearer account-access", origin: "https://app.test", status: 204},
		{name: "missing auth", status: 401},
		{name: "connector credential rejected", token: "Bearer orc_secret", status: 401},
		{name: "foreign or absent", token: "Bearer account-access", err: connectors.ErrNotFound, status: 404},
		{name: "untrusted origin", token: "Bearer account-access", origin: "https://other.test", status: 403},
		{name: "cross site", token: "Bearer account-access", site: "cross-site", status: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &revocationService{err: tc.err}
			request := httptest.NewRequest(http.MethodPost, "/v1/connectors/con_target/revoke", nil)
			request.Header.Set("Authorization", tc.token)
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("Sec-Fetch-Site", tc.site)
			response := httptest.NewRecorder()
			newTestHandler(accountRevocationAuth{}, service, Config{AllowedOrigins: []string{"https://app.test"}}).ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d", response.Code, tc.status)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing cache protection")
			}
			if tc.status == 204 && (response.Body.Len() != 0 || service.userID != "usr_owner" || service.connectorID != "con_target") {
				t.Fatal("incorrect account-scoped revocation")
			}
			if (tc.status == 401 || tc.status == 403) && service.userID != "" {
				t.Fatal("unauthorized request reached service")
			}
		})
	}
}

func (service *revocationService) RevokeConnector(_ context.Context, credential string) error {
	service.credential = credential
	return service.err
}

func (service *revocationService) OwnConnector(_ context.Context, credential string) (connectors.Connector, error) {
	service.credential = credential
	return connectors.Connector{ID: "con_test", CreatedAt: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC), CredentialHash: []byte("secret-hash")}, service.err
}

func TestOwnConnectorHTTPContract(t *testing.T) {
	for _, tc := range []struct {
		name, token, origin string
		err                 error
		status              int
	}{
		{name: "own metadata", token: "Bearer connector-secret", status: http.StatusOK},
		{name: "missing credential", status: http.StatusUnauthorized},
		{name: "revoked credential", token: "Bearer revoked", err: connectors.ErrUnauthorized, status: http.StatusUnauthorized},
		{name: "browser rejected", token: "Bearer connector-secret", origin: "https://app.test", status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &revocationService{err: tc.err}
			request := httptest.NewRequest(http.MethodGet, "/v1/connectors/self", nil)
			request.Header.Set("Authorization", tc.token)
			request.Header.Set("Origin", tc.origin)
			response := httptest.NewRecorder()
			newTestHandler(nil, service, Config{}).ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status = %d", response.Code)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing cache protection")
			}
			if tc.status != http.StatusOK {
				return
			}
			var body map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 2 || body["connectorId"] != "con_test" || body["linkedAt"] != "2026-09-01T12:00:00Z" {
				t.Fatalf("unexpected metadata document: %v", body)
			}
		})
	}
}

func TestRevokeOwnConnectorHTTPContract(t *testing.T) {
	for _, tc := range []struct {
		name, authorization, origin, site string
		serviceError                      error
		status                            int
	}{
		{name: "success", authorization: "Bearer connector-secret", status: http.StatusNoContent},
		{name: "missing credential", status: http.StatusUnauthorized},
		{name: "wrong scheme", authorization: "Pairing secret", status: http.StatusUnauthorized},
		{name: "invalid credential", authorization: "Bearer invalid", serviceError: connectors.ErrUnauthorized, status: http.StatusUnauthorized},
		{name: "browser origin", authorization: "Bearer connector-secret", origin: "https://app.test", status: http.StatusForbidden},
		{name: "cross-site", authorization: "Bearer connector-secret", site: "cross-site", status: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &revocationService{err: tc.serviceError}
			handler := newTestHandler(nil, service, Config{})
			request := httptest.NewRequest(http.MethodPost, "/v1/connectors/self/revoke", nil)
			request.Header.Set("Authorization", tc.authorization)
			request.Header.Set("Origin", tc.origin)
			request.Header.Set("Sec-Fetch-Site", tc.site)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status = %d, want %d", response.Code, tc.status)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("missing cache protection")
			}
			if tc.status == http.StatusNoContent && (response.Body.Len() != 0 || service.credential != "connector-secret") {
				t.Fatal("invalid success contract")
			}
			if tc.status == http.StatusForbidden && service.credential != "" {
				t.Fatal("browser request reached revocation service")
			}
		})
	}
}
