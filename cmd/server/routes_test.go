package main

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisteredRoutesKeepAuthenticationAndDevelopmentGates(t *testing.T) {
	for _, developmentRelay := range []bool{false, true} {
		router, closeRelay := RegisterRoutes(Config{DevelopmentRelayEnabled: developmentRelay}, Services{}, nil,
			slog.New(slog.NewTextHandler(io.Discard, nil)))
		t.Cleanup(closeRelay)
		devStatus := http.StatusNotFound
		if developmentRelay {
			devStatus = http.StatusBadRequest // Route is present, but this is not a WebSocket upgrade.
		}
		for _, test := range []struct {
			method, path string
			status       int
		}{
			{http.MethodGet, "/health/live", http.StatusOK},
			{http.MethodHead, "/health/live", http.StatusOK},
			{http.MethodGet, "/v1/account", http.StatusUnauthorized},
			{http.MethodHead, "/v1/account", http.StatusUnauthorized},
			{http.MethodGet, "/v1/connectors", http.StatusUnauthorized},
			{http.MethodGet, "/v1/connectors/self", http.StatusUnauthorized},
			{http.MethodPost, "/v1/connectors/self/revoke", http.StatusUnauthorized},
			{http.MethodPost, "/v1/connectors/con_target/revoke", http.StatusUnauthorized},
			{http.MethodPost, "/v1/connectors/con_target/rename", http.StatusUnauthorized},
			{http.MethodPost, "/v1/connector-pairings/pair_target/confirm", http.StatusUnauthorized},
			{http.MethodPost, "/v1/connector-pairings/pair_target/poll", http.StatusUnauthorized},
			{http.MethodPost, "/v1/connector-pairings/pair_target/cancel", http.StatusUnauthorized},
			{http.MethodPost, "/v1/devices/challenge", http.StatusUnauthorized},
			{http.MethodPost, "/v1/relay/tickets", http.StatusUnauthorized},
			{http.MethodGet, "/v1/relay", http.StatusUnauthorized},
			{http.MethodPost, "/v1/relay", http.StatusMethodNotAllowed},
			{http.MethodPost, "/v1/auth/register", http.StatusServiceUnavailable},
			{http.MethodGet, "/v1/auth/login", http.StatusMethodNotAllowed},
			{http.MethodPost, "/v1/auth/login/", http.StatusNotFound},
			{http.MethodGet, "/dev/relay", devStatus},
		} {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
			if response.Code != test.status {
				t.Errorf("%s %s (development relay %t): got %d, want %d", test.method, test.path, developmentRelay, response.Code, test.status)
			}
		}
	}
}
