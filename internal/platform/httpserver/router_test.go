package httpserver

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRouterPreservesPathValuesAndMethodBoundaries(t *testing.T) {
	router := NewRouter(nil)
	router.POST("/pairings/:pairingID/confirm", WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("pairingID") != "pair_test" {
			t.Error("pairing identifier was lost at the Gin boundary")
		}
		w.WriteHeader(http.StatusNoContent)
	})))
	for _, test := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "/pairings/pair_test/confirm", http.StatusNoContent},
		{http.MethodGet, "/pairings/pair_test/confirm", http.StatusMethodNotAllowed},
		{http.MethodPost, "/pairings/pair_test/confirm/", http.StatusNotFound},
		{http.MethodPost, "/Pairings/pair_test/confirm", http.StatusNotFound},
		{http.MethodPost, "/pairings//pair_test/confirm", http.StatusNotFound},
		{http.MethodPost, "/unknown", http.StatusNotFound},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(test.method, test.path, nil))
			if response.Code != test.status || response.Header().Get("Location") != "" {
				t.Fatalf("unexpected routing response: %d", response.Code)
			}
			if test.status == http.StatusMethodNotAllowed && response.Header().Get("Allow") != "POST" {
				t.Fatal("method rejection lost the Allow header")
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("response is missing security headers")
			}
		})
	}
}

func TestRouterDoesNotTrustForwardedClientIP(t *testing.T) {
	router := NewRouter(nil)
	router.GET("/client", func(c *gin.Context) {
		if c.ClientIP() != "192.0.2.10" {
			t.Error("Gin trusted an unconfigured proxy")
		}
	})
	request := httptest.NewRequest(http.MethodGet, "/client", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.1")
	request.Header.Set("X-Real-IP", "198.51.100.2")
	router.ServeHTTP(httptest.NewRecorder(), request)
}

func TestRouterRecoveryDoesNotLeakRequestOrPanic(t *testing.T) {
	var logs bytes.Buffer
	router := NewRouter(slog.New(slog.NewJSONHandler(&logs, nil)))
	router.POST("/panic", func(c *gin.Context) { panic("sensitive-panic") })
	request := httptest.NewRequest(http.MethodPost, "/panic?ticket=sensitive-ticket", strings.NewReader("sensitive-body"))
	request.Header.Set("Authorization", "Bearer sensitive-token")
	request.Header.Set("Cookie", "session=sensitive-cookie")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || !strings.Contains(logs.String(), "HTTP handler panic") {
		t.Fatal("panic did not produce a generic error and diagnostic category")
	}
	if strings.Contains(logs.String()+response.Body.String(), "sensitive-") {
		t.Fatal("request or panic content leaked")
	}
}
