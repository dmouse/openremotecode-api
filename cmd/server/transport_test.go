package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"opencode-remote/server/internal/platform/httpserver"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

func TestTransportConfigurationFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name, cert, key    string
		development, valid bool
	}{
		{name: "production without certificates"},
		{name: "production certificate only", cert: "missing.pem"},
		{name: "production key only", key: "missing.pem"},
		{name: "unreadable certificates", cert: "missing.pem", key: "missing-key.pem"},
		{name: "development explicit HTTP", development: true, valid: true},
		{name: "development partial TLS", development: true, cert: "missing.pem"},
		{name: "development invalid TLS never falls back", development: true, cert: "missing.pem", key: "missing-key.pem"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, err := loadTransportTLS(test.development, test.cert, test.key)
			if (err == nil) != test.valid || config != nil {
				t.Fatalf("unexpected configuration result: %v", err)
			}
		})
	}
}

func TestTLSListenerServesHTTPSAndWSSAndRejectsPlaintext(t *testing.T) {
	certFile, keyFile, roots := transportCertificate(t)
	config, err := loadTransportTLS(false, certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	upgrader := websocket.Upgrader{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.TLS == nil {
			t.Error("plaintext reached API handler")
			return
		}
		if r.URL.Path == "/v1/relay" {
			connection, err := upgrader.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer connection.Close()
			_ = connection.WriteMessage(websocket.TextMessage, []byte("transport-test"))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	router := httpserver.NewRouter(nil)
	router.GET("/health/live", gin.WrapH(handler))
	router.GET("/v1/relay", gin.WrapH(handler))
	address := startTransportServer(t, config, router)
	clientTLS := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	transport := &http.Transport{TLSClientConfig: clientTLS}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get("https://" + address + "/health/live")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("HTTPS health failed")
	}
	dialer := websocket.Dialer{TLSClientConfig: clientTLS, HandshakeTimeout: time.Second}
	connection, _, err := dialer.Dial("wss://"+address+"/v1/relay", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	_, message, err := connection.ReadMessage()
	if err != nil || string(message) != "transport-test" {
		t.Fatal("WSS failed", err)
	}

	response, err = client.Get("http://" + address + "/health/live")
	if err == nil {
		response.Body.Close()
		if response.StatusCode < 400 {
			t.Fatal("plaintext HTTP was accepted")
		}
	}
	if requests.Load() != 2 {
		t.Fatal("plaintext request reached the API")
	}
	legacyTLS := clientTLS.Clone()
	legacyTLS.MinVersion, legacyTLS.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	if connection, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, legacyTLS); err == nil {
		connection.Close()
		t.Fatal("obsolete TLS version was accepted")
	}
}

func TestInvalidTLSFilesNeverFallBackToHTTP(t *testing.T) {
	certFile, _, _ := transportCertificate(t)
	_, otherKey, _ := transportCertificate(t)
	invalid := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalid, []byte("invalid certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, development := range []bool{false, true} {
		for _, cert := range []string{certFile, invalid} {
			config, err := loadTransportTLS(development, cert, otherKey)
			if err == nil || config != nil {
				t.Fatal("invalid or mismatched certificate pair was accepted")
			}
		}
	}
}

func TestDevelopmentListenerAllowsExplicitHTTP(t *testing.T) {
	config, err := loadTransportTLS(true, "", "")
	if err != nil {
		t.Fatal(err)
	}
	address := startTransportServer(t, config, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	client := &http.Client{Timeout: time.Second}
	response, err := client.Get("http://" + address)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatal("development HTTP failed")
	}
}

func startTransportServer(t *testing.T, config *tls.Config, handler http.Handler) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{TLSConfig: config, Handler: handler, ReadHeaderTimeout: time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	done := make(chan error, 1)
	go func() { done <- serveAPI(server, listener) }()
	t.Cleanup(func() {
		server.Close()
		if err := <-done; !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	})
	return listener.Addr().String()
}

func transportCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	directory := t.TempDir()
	certFile, keyFile := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certPEM)
	return certFile, keyFile, roots
}
