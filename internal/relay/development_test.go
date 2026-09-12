package relay

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestDevelopmentRelayRoutesOpaqueEnvelopes(t *testing.T) {
	handler := NewDevelopmentHandler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	websocketURL := "ws" + strings.TrimPrefix(server.URL, "http")

	connectorKeyID := strings.Repeat("c", 43)
	clientKeyID := strings.Repeat("b", 43)
	connector := connectPeer(t, websocketURL, helloMessage{
		ProtocolVersion: protocolVersion,
		Type:            "connector.hello",
		PluginVersion:   "0.1.0",
		Identity:        testIdentity(connectorKeyID),
		Capabilities:    []string{"session.list"},
	})
	client := connectPeer(t, websocketURL, helloMessage{
		ProtocolVersion: protocolVersion,
		Type:            "client.hello",
		Identity:        testIdentity(clientKeyID),
	})

	_, presenceMessage, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("read connector presence: %v", err)
	}
	var presence helloMessage
	if err := json.Unmarshal(presenceMessage, &presence); err != nil {
		t.Fatalf("decode connector presence: %v", err)
	}
	if presence.Identity.KeyID != connectorKeyID {
		t.Fatalf("expected connector %q, got %q", connectorKeyID, presence.Identity.KeyID)
	}

	request := testEnvelope(clientKeyID, connectorKeyID)
	requestBytes, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	if err := client.WriteMessage(websocket.TextMessage, requestBytes); err != nil {
		t.Fatalf("write client request: %v", err)
	}

	_, routedRequest, err := connector.ReadMessage()
	if err != nil {
		t.Fatalf("read connector request: %v", err)
	}
	if string(routedRequest) != string(requestBytes) {
		t.Fatalf("relay changed opaque request\nwant: %s\ngot:  %s", requestBytes, routedRequest)
	}

	response := testEnvelope(connectorKeyID, clientKeyID)
	responseBytes, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	if err := connector.WriteMessage(websocket.TextMessage, responseBytes); err != nil {
		t.Fatalf("write connector response: %v", err)
	}

	_, routedResponse, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("read client response: %v", err)
	}
	if string(routedResponse) != string(responseBytes) {
		t.Fatalf("relay changed opaque response\nwant: %s\ngot:  %s", responseBytes, routedResponse)
	}
}

func TestDevelopmentRelayNotifiesConnectorOfClientPresence(t *testing.T) {
	handler := NewDevelopmentHandler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	websocketURL := "ws" + strings.TrimPrefix(server.URL, "http")

	connectorKeyID := strings.Repeat("c", 43)
	clientKeyID := strings.Repeat("b", 43)
	connector := connectPeer(t, websocketURL, helloMessage{
		ProtocolVersion: protocolVersion,
		Type:            "connector.hello",
		PluginVersion:   "0.1.0",
		Identity:        testIdentity(connectorKeyID),
		Capabilities:    []string{"session.list"},
	})
	client := connectPeer(t, websocketURL, helloMessage{
		ProtocolVersion: protocolVersion,
		Type:            "client.hello",
		Identity:        testIdentity(clientKeyID),
	})

	if _, _, err := client.ReadMessage(); err != nil {
		t.Fatalf("read connector presence on client: %v", err)
	}

	_, presenceMessage, err := connector.ReadMessage()
	if err != nil {
		t.Fatalf("read client presence on connector: %v", err)
	}
	var presence helloMessage
	if err := json.Unmarshal(presenceMessage, &presence); err != nil {
		t.Fatalf("decode client presence: %v", err)
	}
	if presence.Type != "client.hello" || presence.Identity.KeyID != clientKeyID {
		t.Fatalf("expected client %q hello, got %#v", clientKeyID, presence)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v", err)
	}

	_ = connector.SetReadDeadline(time.Now().Add(time.Second))
	_, offlineMessage, err := connector.ReadMessage()
	if err != nil {
		t.Fatalf("read client offline on connector: %v", err)
	}
	var offline struct {
		ProtocolVersion int    `json:"protocolVersion"`
		Type            string `json:"type"`
		KeyID           string `json:"keyId"`
	}
	if err := json.Unmarshal(offlineMessage, &offline); err != nil {
		t.Fatalf("decode client offline: %v", err)
	}
	if offline.Type != "client.offline" || offline.KeyID != clientKeyID {
		t.Fatalf("expected client.offline for %q, got %#v", clientKeyID, offline)
	}
}

func TestDevelopmentRelayNotifiesLateConnectorOfExistingClient(t *testing.T) {
	handler := NewDevelopmentHandler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	websocketURL := "ws" + strings.TrimPrefix(server.URL, "http")

	connectorKeyID := strings.Repeat("c", 43)
	clientKeyID := strings.Repeat("b", 43)
	// The client connects first (e.g. the connector restarted while the phone stayed connected).
	client := connectPeer(t, websocketURL, helloMessage{
		ProtocolVersion: protocolVersion,
		Type:            "client.hello",
		Identity:        testIdentity(clientKeyID),
	})
	connector := connectPeer(t, websocketURL, helloMessage{
		ProtocolVersion: protocolVersion,
		Type:            "connector.hello",
		PluginVersion:   "0.1.0",
		Identity:        testIdentity(connectorKeyID),
		Capabilities:    []string{"session.list"},
	})

	if _, _, err := client.ReadMessage(); err != nil {
		t.Fatalf("read connector presence on client: %v", err)
	}

	_, presenceMessage, err := connector.ReadMessage()
	if err != nil {
		t.Fatalf("read client presence on late-connecting connector: %v", err)
	}
	var presence helloMessage
	if err := json.Unmarshal(presenceMessage, &presence); err != nil {
		t.Fatalf("decode client presence: %v", err)
	}
	if presence.Type != "client.hello" || presence.Identity.KeyID != clientKeyID {
		t.Fatalf("expected client %q hello, got %#v", clientKeyID, presence)
	}
}

func TestDevelopmentRelayRejectsSenderSpoofing(t *testing.T) {
	handler := NewDevelopmentHandler()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	websocketURL := "ws" + strings.TrimPrefix(server.URL, "http")

	connectorKeyID := strings.Repeat("c", 43)
	clientKeyID := strings.Repeat("b", 43)
	connector := connectPeer(t, websocketURL, helloMessage{
		ProtocolVersion: protocolVersion,
		Type:            "connector.hello",
		PluginVersion:   "0.1.0",
		Identity:        testIdentity(connectorKeyID),
	})
	client := connectPeer(t, websocketURL, helloMessage{
		ProtocolVersion: protocolVersion,
		Type:            "client.hello",
		Identity:        testIdentity(clientKeyID),
	})
	if _, _, err := client.ReadMessage(); err != nil {
		t.Fatalf("read connector presence: %v", err)
	}

	spoofed := testEnvelope(strings.Repeat("s", 43), connectorKeyID)
	if err := client.WriteJSON(spoofed); err != nil {
		t.Fatalf("write spoofed request: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := client.ReadMessage(); err == nil {
		t.Fatal("expected spoofing client connection to close")
	}
	_ = connector.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := connector.ReadMessage(); err == nil {
		t.Fatal("spoofed request reached connector")
	}
}

func TestDevelopmentRelayRejectsNonLoopbackBrowserOrigin(t *testing.T) {
	server := httptest.NewServer(NewDevelopmentHandler())
	t.Cleanup(server.Close)
	websocketURL := "ws" + strings.TrimPrefix(server.URL, "http")
	header := http.Header{}
	header.Set("Origin", "https://attacker.example")

	connection, response, err := websocket.DefaultDialer.Dial(websocketURL, header)
	if connection != nil {
		_ = connection.Close()
	}
	if err == nil {
		t.Fatal("expected non-loopback origin to be rejected")
	}
	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status %d, got %#v", http.StatusForbidden, response)
	}
}

func connectPeer(t *testing.T, websocketURL string, hello helloMessage) *websocket.Conn {
	t.Helper()
	header := http.Header{}
	header.Set("Origin", "http://127.0.0.1:5173")
	connection, response, err := websocket.DefaultDialer.Dial(websocketURL, header)
	if err != nil {
		if response != nil {
			t.Fatalf("connect peer: %v (status %d)", err, response.StatusCode)
		}
		t.Fatalf("connect peer: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	if err := connection.WriteJSON(hello); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	return connection
}

func testIdentity(keyID string) publicIdentity {
	return publicIdentity{
		Version:   protocolVersion,
		Suite:     hpkeSuiteID,
		KeyID:     keyID,
		PublicKey: "AQ",
	}
}

func testEnvelope(senderKeyID, recipientKeyID string) relayEnvelope {
	return relayEnvelope{
		ProtocolVersion: protocolVersion,
		Type:            "relay.envelope",
		MessageID:       "123e4567-e89b-42d3-a456-426614174000",
		SenderKeyID:     senderKeyID,
		RecipientKeyID:  recipientKeyID,
		Sequence:        0,
		ExpiresAt:       time.Now().Add(time.Minute).UnixMilli(),
		Suite:           hpkeSuiteID,
		EncapsulatedKey: "AQ",
		Ciphertext:      "AQ",
	}
}
