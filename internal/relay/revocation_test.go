package relay

import (
	"context"
	"errors"
	"net"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"opencode-remote/server/internal/connectors"

	"github.com/gorilla/websocket"
)

// scriptedAdmissions admits by ticket and answers every periodic check with failure's value.
type scriptedAdmissions struct {
	admissions map[string]connectors.Admission
	failure    *atomic.Pointer[error]
	checks     *atomic.Int64
}

func (service scriptedAdmissions) ConsumeRelayTicket(_ context.Context, ticket string) (connectors.Admission, error) {
	admission, ok := service.admissions[ticket]
	if !ok {
		return connectors.Admission{}, connectors.ErrUnauthorized
	}
	return admission, nil
}

func (service scriptedAdmissions) ValidateAdmission(context.Context, connectors.Admission) error {
	service.checks.Add(1)
	if err := service.failure.Load(); err != nil {
		return *err
	}
	return nil
}

type revocationFixture struct {
	hub                *Hub
	service            scriptedAdmissions
	phone, connector   *websocket.Conn
	phoneID, connectID publicIdentity
}

func newRevocationFixture(t *testing.T, interval time.Duration) *revocationFixture {
	t.Helper()
	phoneID, connectorID := testIdentity(strings.Repeat("p", 43)), testIdentity(strings.Repeat("c", 43))
	admission := func(role, subject string, self, peer publicIdentity) connectors.Admission {
		return connectors.Admission{UserID: "usr_a", Role: role, SubjectID: subject, SessionID: "asn_a",
			Identity: connectors.PublicIdentity(self), TrustedIdentities: []connectors.PublicIdentity{connectors.PublicIdentity(peer)},
			AuthorizationExpiresAt: time.Now().Add(time.Hour)}
	}
	fixture := &revocationFixture{hub: NewHub(), phoneID: phoneID, connectID: connectorID,
		service: scriptedAdmissions{admissions: map[string]connectors.Admission{
			"ort_phone":     admission(connectors.RelayRoleClient, "dev_a", phoneID, connectorID),
			"ort_connector": admission(connectors.RelayRoleConnector, "con_a", connectorID, phoneID),
		}, failure: &atomic.Pointer[error]{}, checks: &atomic.Int64{}}}
	handler := NewHandler(fixture.service, HandlerConfig{Hub: fixture.hub, RevalidationInterval: interval})
	server := newTestServer(t, handler)
	dial := func(ticket string, hello helloMessage) *websocket.Conn {
		dialer := websocket.Dialer{Subprotocols: []string{relayWebSocketProtocol, "ticket." + ticket}}
		connection, _, err := dialer.Dial("ws"+strings.TrimPrefix(server, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.Close() })
		if err := connection.WriteJSON(hello); err != nil {
			t.Fatal(err)
		}
		return connection
	}
	fixture.connector = dial("ort_connector", helloMessage{ProtocolVersion: protocolVersion, Type: "connector.hello",
		PluginVersion: "test", Identity: connectorID, Nonce: testNonce()})
	fixture.phone = dial("ort_phone", helloMessage{ProtocolVersion: protocolVersion, Type: "client.hello",
		Identity: phoneID, Nonce: testNonce()})
	waitForType(t, fixture.connector, "client.hello")
	waitForType(t, fixture.phone, "connector.hello")
	return fixture
}

func waitForType(t *testing.T, connection *websocket.Conn, want string) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer func() { _ = connection.SetReadDeadline(time.Time{}) }()
	for {
		var message struct {
			Type string `json:"type"`
		}
		if err := connection.ReadJSON(&message); err != nil {
			t.Fatalf("waiting for %s: %v", want, err)
		}
		if message.Type == want {
			return
		}
	}
}

func expectClosed(t *testing.T, connection *websocket.Conn, within time.Duration) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(within))
	for {
		if _, _, err := connection.ReadMessage(); err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				t.Fatalf("expected a server close within %s, got %v", within, err)
			}
			return
		}
	}
}

// A committed revocation closes exactly the sockets it covers at once, without waiting for
// the periodic check, and the connector hears that the phone went offline.
func TestHubDisconnectClosesCoveredSocketsImmediately(t *testing.T) {
	fixture := newRevocationFixture(t, time.Hour)
	if closed := fixture.hub.Disconnect(connectors.Revocation{UserID: "usr_other", DeviceID: "dev_a"}); closed != 0 {
		t.Fatalf("another account's revocation closed %d sockets", closed)
	}
	if closed := fixture.hub.Disconnect(connectors.Revocation{UserID: "usr_a", DeviceID: "dev_a"}); closed != 1 {
		t.Fatalf("device revocation closed %d sockets, want 1", closed)
	}
	expectClosed(t, fixture.phone, time.Second)
	waitForType(t, fixture.connector, "client.offline")

	if closed := fixture.hub.Disconnect(connectors.Revocation{UserID: "usr_a", ConnectorID: "con_a"}); closed != 1 {
		t.Fatalf("connector revocation closed %d sockets, want 1", closed)
	}
	expectClosed(t, fixture.connector, time.Second)
}

func TestSessionAndAccountRevocationsCloseTheirSockets(t *testing.T) {
	fixture := newRevocationFixture(t, time.Hour)
	fixture.hub.Disconnect(connectors.Revocation{UserID: "usr_a", SessionID: "asn_a"})
	expectClosed(t, fixture.phone, time.Second)

	fixture = newRevocationFixture(t, time.Hour)
	if closed := fixture.hub.Disconnect(connectors.Revocation{UserID: "usr_a"}); closed != 2 {
		t.Fatalf("account revocation closed %d sockets, want both", closed)
	}
	expectClosed(t, fixture.phone, time.Second)
	expectClosed(t, fixture.connector, time.Second)
}

// A database outage must not disconnect every socket at once; only an authorization failure
// closes one. The lease still bounds a socket whose checks keep failing.
func TestTransientCheckFailureKeepsTheSocketOpen(t *testing.T) {
	fixture := newRevocationFixture(t, 50*time.Millisecond)
	transient := errors.New("database unavailable")
	fixture.service.failure.Store(&transient)
	before := fixture.service.checks.Load()
	time.Sleep(400 * time.Millisecond)
	if fixture.service.checks.Load() <= before {
		t.Fatal("the socket was not rechecked")
	}
	// Still open: a read just times out rather than seeing a close.
	_ = fixture.phone.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, _, err := fixture.phone.ReadMessage()
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("a transient failure closed the socket: %v", err)
	}

	// An authorization failure still closes it at the next check.
	fixture = newRevocationFixture(t, 50*time.Millisecond)
	fixture.service.failure.Store(&connectors.ErrUnauthorized)
	expectClosed(t, fixture.phone, time.Second)
}

func newTestServer(t *testing.T, handler *Handler) string {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(func() { handler.Close(); server.Close() })
	return server.URL
}

func TestJitterStaysWithinHalfAnIntervalEitherWay(t *testing.T) {
	for range 1000 {
		if delay := jittered(30 * time.Second); delay < 15*time.Second || delay >= 45*time.Second {
			t.Fatalf("jittered delay %s outside [15s, 45s)", delay)
		}
	}
}
