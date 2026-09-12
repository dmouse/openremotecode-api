package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLiveness(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	response := httptest.NewRecorder()
	NewHandler(func(context.Context) error {
		return errors.New("readiness must not affect liveness")
	}).ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, response.Code)
	}
	if response.Body.String() != "{\"status\":\"ok\"}\n" {
		t.Fatalf("unexpected body %q", response.Body.String())
	}
}

func TestReadiness(t *testing.T) {
	tests := []struct {
		name       string
		check      ReadinessCheck
		statusCode int
		body       string
	}{
		{
			name:       "ready",
			check:      func(context.Context) error { return nil },
			statusCode: http.StatusOK,
			body:       "{\"status\":\"ready\"}\n",
		},
		{
			name: "dependency unavailable",
			check: func(context.Context) error {
				return errors.New("sensitive dependency detail")
			},
			statusCode: http.StatusServiceUnavailable,
			body:       "{\"status\":\"unavailable\"}\n",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
			response := httptest.NewRecorder()
			NewHandler(test.check).ServeHTTP(response, request)

			if response.Code != test.statusCode {
				t.Fatalf("expected status %d, got %d", test.statusCode, response.Code)
			}
			if response.Body.String() != test.body {
				t.Fatalf("unexpected body %q", response.Body.String())
			}
		})
	}
}

func TestHealthEndpointsRejectUnsupportedMethods(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/health/live", nil)
	response := httptest.NewRecorder()
	NewHandler(func(context.Context) error { return nil }).ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf(
			"expected status %d, got %d",
			http.StatusMethodNotAllowed,
			response.Code,
		)
	}
}
