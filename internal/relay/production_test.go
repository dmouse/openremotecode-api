package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"opencode-remote/server/internal/connectors"

	"github.com/gorilla/websocket"
)

type fixedAdmissionService struct {
	admission connectors.Admission
	revoked   *atomic.Bool
}

func (service fixedAdmissionService) ConsumeRelayTicket(context.Context, string) (connectors.Admission, error) {
	return service.admission, nil
}

func (service fixedAdmissionService) ValidateConnectorAdmission(context.Context, connectors.Admission) error {
	if service.revoked != nil && service.revoked.Load() {
		return connectors.ErrUnauthorized
	}
	return nil
}

func TestProductionRelayClosesIdleRevokedConnector(t *testing.T) {
	identity := testIdentity(strings.Repeat("r", 43))
	revoked := &atomic.Bool{}
	handler := NewHandler(fixedAdmissionService{revoked: revoked, admission: connectors.Admission{
		UserID: "usr_test", Role: connectors.RelayRoleConnector, SubjectID: "con_test",
		Identity:               connectors.PublicIdentity{Version: identity.Version, Suite: identity.Suite, KeyID: identity.KeyID, PublicKey: identity.PublicKey},
		AuthorizationExpiresAt: time.Now().Add(5 * time.Minute),
	}}, HandlerConfig{})
	server := httptest.NewServer(handler)
	t.Cleanup(func() { handler.Close(); server.Close() })
	dialer := *websocket.DefaultDialer
	dialer.Subprotocols = []string{relayWebSocketProtocol, "ticket.ort_test"}
	connection, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.WriteJSON(helloMessage{ProtocolVersion: protocolVersion, Type: "connector.hello", Nonce: testNonce(), PluginVersion: "0.1.0", Identity: identity}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	revoked.Store(true)
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := connection.ReadMessage(); !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("expected a server close after revocation, got %v", err)
	}
}

func TestProductionRelayClosesAtAuthorizationLeaseExpiry(t *testing.T) {
	keyID := strings.Repeat("c", 43)
	identity := testIdentity(keyID)
	handler := NewHandler(fixedAdmissionService{admission: connectors.Admission{
		UserID: "usr_test", Role: connectors.RelayRoleConnector, SubjectID: "con_test",
		Identity: connectors.PublicIdentity{
			Version: identity.Version, Suite: identity.Suite, KeyID: identity.KeyID, PublicKey: identity.PublicKey,
		},
		AuthorizationExpiresAt: time.Now().Add(200 * time.Millisecond),
	}}, HandlerConfig{AllowedOrigins: []string{"http://app.test"}})
	server := httptest.NewServer(handler)
	t.Cleanup(func() {
		handler.Close()
		server.Close()
	})

	dialer := *websocket.DefaultDialer
	dialer.Subprotocols = []string{relayWebSocketProtocol, "ticket.ort_test"}
	header := http.Header{}
	header.Set("Origin", "http://app.test")
	connection, response, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), header)
	if err != nil {
		if response != nil {
			t.Fatalf("connect production relay: %v (status %d)", err, response.StatusCode)
		}
		t.Fatalf("connect production relay: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.WriteJSON(helloMessage{
		ProtocolVersion: protocolVersion,
		Type:            "connector.hello",
		Nonce:           testNonce(),
		PluginVersion:   "0.1.0",
		Identity:        identity,
	}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if _, _, err := connection.ReadMessage(); err != nil {
		t.Fatalf("read relay ready: %v", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := connection.ReadMessage(); err == nil {
		t.Fatal("expected relay connection to close at authorization lease expiry")
	}
}

func TestSecureHubRegisterNotifiesConnectorOfClientPresence(t *testing.T) {
	connectorPeer := &securePeer{
		userID: "usr_test", role: connectors.RelayRoleConnector, keyID: "connector",
		hello:   []byte(`{"type":"connector.hello"}`),
		trusted: map[string]struct{}{"client": {}}, send: make(chan []byte, 4), done: make(chan struct{}),
	}
	clientPeer := &securePeer{
		userID: "usr_test", role: connectors.RelayRoleClient, keyID: "client",
		hello:   []byte(`{"type":"client.hello"}`),
		trusted: map[string]struct{}{"connector": {}}, send: make(chan []byte, 4), done: make(chan struct{}),
	}
	hub := newSecureHub()
	if err := hub.register(connectorPeer); err != nil {
		t.Fatalf("register connector: %v", err)
	}
	if err := hub.register(clientPeer); err != nil {
		t.Fatalf("register client: %v", err)
	}

	select {
	case message := <-connectorPeer.send:
		if string(message) != string(clientPeer.hello) {
			t.Fatalf("expected connector to receive client hello, got %s", message)
		}
	default:
		t.Fatal("connector did not receive client presence")
	}
}

func TestSecureHubRegisterNotifiesLateConnectorOfExistingClient(t *testing.T) {
	connectorPeer := &securePeer{
		userID: "usr_test", role: connectors.RelayRoleConnector, keyID: "connector",
		hello:   []byte(`{"type":"connector.hello"}`),
		trusted: map[string]struct{}{"client": {}}, send: make(chan []byte, 4), done: make(chan struct{}),
	}
	clientPeer := &securePeer{
		userID: "usr_test", role: connectors.RelayRoleClient, keyID: "client",
		hello:   []byte(`{"type":"client.hello"}`),
		trusted: map[string]struct{}{"connector": {}}, send: make(chan []byte, 4), done: make(chan struct{}),
	}
	hub := newSecureHub()
	// The client registers first (e.g. the connector restarted while the phone stayed connected).
	if err := hub.register(clientPeer); err != nil {
		t.Fatalf("register client: %v", err)
	}
	if err := hub.register(connectorPeer); err != nil {
		t.Fatalf("register connector: %v", err)
	}

	select {
	case message := <-connectorPeer.send:
		if string(message) != string(clientPeer.hello) {
			t.Fatalf("expected late-connecting connector to receive client hello, got %s", message)
		}
	default:
		t.Fatal("late-connecting connector did not receive client presence")
	}
}

func TestSecureHubUnregisterNotifiesConnectorOfClientOffline(t *testing.T) {
	connectorPeer := &securePeer{
		userID: "usr_test", role: connectors.RelayRoleConnector, keyID: "connector",
		hello:   []byte(`{"type":"connector.hello"}`),
		trusted: map[string]struct{}{"client": {}}, send: make(chan []byte, 4), done: make(chan struct{}),
	}
	clientPeer := &securePeer{
		userID: "usr_test", role: connectors.RelayRoleClient, keyID: "client",
		hello:   []byte(`{"type":"client.hello"}`),
		trusted: map[string]struct{}{"connector": {}}, send: make(chan []byte, 4), done: make(chan struct{}),
	}
	hub := newSecureHub()
	if err := hub.register(connectorPeer); err != nil {
		t.Fatalf("register connector: %v", err)
	}
	if err := hub.register(clientPeer); err != nil {
		t.Fatalf("register client: %v", err)
	}
	<-connectorPeer.send // discard the client-presence message from register

	hub.unregister(clientPeer)

	select {
	case message := <-connectorPeer.send:
		var offline struct {
			Type  string `json:"type"`
			KeyID string `json:"keyId"`
		}
		if err := json.Unmarshal(message, &offline); err != nil {
			t.Fatalf("decode client offline: %v", err)
		}
		if offline.Type != "client.offline" || offline.KeyID != clientPeer.keyID {
			t.Fatalf("expected client.offline for %q, got %#v", clientPeer.keyID, offline)
		}
	default:
		t.Fatal("connector did not receive client offline notice")
	}
}

func TestSecureHubDisconnectsOnlyTheSlowRecipient(t *testing.T) {
	sender := &securePeer{
		userID: "usr_test", role: connectors.RelayRoleClient, keyID: "client",
		trusted: map[string]struct{}{"connector": {}}, send: make(chan []byte, 1), done: make(chan struct{}),
	}
	recipient := &securePeer{
		userID: "usr_test", role: connectors.RelayRoleConnector, keyID: "connector",
		trusted: map[string]struct{}{"client": {}}, send: make(chan []byte, 1), done: make(chan struct{}),
	}
	recipient.send <- []byte("queue is full")
	hub := newSecureHub()
	hub.peers[securePeerID(recipient.userID, recipient.keyID)] = recipient

	if !hub.route(sender, recipient.keyID, []byte("new frame")) {
		t.Fatal("authorized sender was disconnected with the slow recipient")
	}
	select {
	case <-recipient.done:
	default:
		t.Fatal("slow recipient was not disconnected")
	}
}
