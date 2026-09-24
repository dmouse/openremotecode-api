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

func (service fixedAdmissionService) ValidateAdmission(context.Context, connectors.Admission) error {
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
	}}, HandlerConfig{RevalidationInterval: 200 * time.Millisecond})
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

// A revoked device, or a client whose session ended, must lose its socket as promptly
// as a revoked connector does, not at the end of its authorization lease.
func TestProductionRelayClosesIdleRevokedClient(t *testing.T) {
	identity := testIdentity(strings.Repeat("d", 43))
	revoked := &atomic.Bool{}
	handler := NewHandler(fixedAdmissionService{revoked: revoked, admission: connectors.Admission{
		UserID: "usr_test", Role: connectors.RelayRoleClient, SubjectID: "dev_test", SessionID: "asn_test",
		Identity:               connectors.PublicIdentity{Version: identity.Version, Suite: identity.Suite, KeyID: identity.KeyID, PublicKey: identity.PublicKey},
		AuthorizationExpiresAt: time.Now().Add(5 * time.Minute),
	}}, HandlerConfig{RevalidationInterval: 200 * time.Millisecond})
	server := httptest.NewServer(handler)
	t.Cleanup(func() { handler.Close(); server.Close() })
	dialer := *websocket.DefaultDialer
	dialer.Subprotocols = []string{relayWebSocketProtocol, "ticket.ort_test"}
	connection, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.WriteJSON(helloMessage{ProtocolVersion: protocolVersion, Type: "client.hello", Nonce: testNonce(), Identity: identity}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := connection.ReadMessage(); err != nil {
		t.Fatal(err)
	}
	revoked.Store(true)
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, _, err := connection.ReadMessage(); !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
		t.Fatalf("expected a server close after device revocation, got %v", err)
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

func TestRelayReadyMessageCarriesAuthorizationExpiry(t *testing.T) {
	expiresAt := time.Now().Add(5 * time.Minute).Truncate(time.Millisecond)
	message := relayReadyMessage(connectors.Admission{
		Role:                   connectors.RelayRoleClient,
		Identity:               connectors.PublicIdentity{KeyID: "client"},
		AuthorizationExpiresAt: expiresAt,
	})
	var decoded struct {
		Type                   string    `json:"type"`
		AuthorizationExpiresAt time.Time `json:"authorizationExpiresAt"`
	}
	if err := json.Unmarshal(message, &decoded); err != nil {
		t.Fatalf("decode relay.ready: %v", err)
	}
	if decoded.Type != "relay.ready" {
		t.Fatalf("expected type relay.ready, got %q", decoded.Type)
	}
	if !decoded.AuthorizationExpiresAt.Equal(expiresAt) {
		t.Fatalf("expected authorizationExpiresAt %v, got %v", expiresAt, decoded.AuthorizationExpiresAt)
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

func TestSecureHubRegisterReplacesSameIdentityConnection(t *testing.T) {
	connectorPeer := &securePeer{
		userID: "usr_test", role: connectors.RelayRoleConnector, keyID: "connector",
		hello:   []byte(`{"type":"connector.hello"}`),
		trusted: map[string]struct{}{"client": {}}, send: make(chan []byte, 4), done: make(chan struct{}),
	}
	oldClientPeer := &securePeer{
		userID: "usr_test", role: connectors.RelayRoleClient, keyID: "client",
		hello:   []byte(`{"type":"client.hello","generation":"old"}`),
		trusted: map[string]struct{}{"connector": {}}, send: make(chan []byte, 4), done: make(chan struct{}),
	}
	newClientPeer := &securePeer{
		userID: "usr_test", role: connectors.RelayRoleClient, keyID: "client",
		hello:   []byte(`{"type":"client.hello","generation":"new"}`),
		trusted: map[string]struct{}{"connector": {}}, send: make(chan []byte, 4), done: make(chan struct{}),
	}
	hub := newSecureHub()
	if err := hub.register(connectorPeer); err != nil {
		t.Fatalf("register connector: %v", err)
	}
	if err := hub.register(oldClientPeer); err != nil {
		t.Fatalf("register old client: %v", err)
	}
	<-connectorPeer.send // discard the old client's presence message from register

	// A proactive renewal registers a new connection for the same identity
	// before the old one has unregistered.
	if err := hub.register(newClientPeer); err != nil {
		t.Fatalf("register renewed client: %v", err)
	}
	<-connectorPeer.send // discard the renewed client's presence message from register
	<-newClientPeer.send // discard the connector's presence message from register

	select {
	case <-oldClientPeer.done:
	default:
		t.Fatal("registering a replacement did not stop the superseded connection")
	}

	if hub.peers[securePeerID("usr_test", "client")] != newClientPeer {
		t.Fatal("the renewed connection did not take over the identity's registration")
	}

	if !hub.route(connectorPeer, "client", []byte("frame")) {
		t.Fatal("routing to the identity failed right after a renewal swap")
	}
	select {
	case message := <-newClientPeer.send:
		if string(message) != "frame" {
			t.Fatalf("expected the renewed connection to receive the routed frame, got %s", message)
		}
	default:
		t.Fatal("the renewed connection did not receive the frame routed to its identity")
	}

	// The superseded connection's own teardown (its serve loop unwinding
	// after stop()) must not emit a spurious offline notice or clobber the
	// replacement -- simulate that here via the same unregister call its
	// deferred cleanup would make.
	hub.unregister(oldClientPeer)

	select {
	case message := <-connectorPeer.send:
		t.Fatalf("superseded connection's teardown emitted an unexpected message: %s", message)
	default:
	}
	if hub.peers[securePeerID("usr_test", "client")] != newClientPeer {
		t.Fatal("the superseded connection's teardown clobbered the renewed registration")
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
