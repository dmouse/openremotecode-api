package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"opencode-remote/server/internal/connectors"

	"github.com/gorilla/websocket"
)

// Envelope sizes are ciphertext bytes before base64url, matching cmd/loadtest's -size.
var benchmarkSizes = []int{1 << 10, 4 << 10, 64 << 10}

func benchmarkEnvelope(tb testing.TB, size int, sender, recipient string) []byte {
	tb.Helper()
	ciphertext := make([]byte, size)
	if _, err := rand.Read(ciphertext); err != nil {
		tb.Fatal(err)
	}
	envelope := testEnvelope(sender, recipient)
	envelope.EncapsulatedKey = base64.RawURLEncoding.EncodeToString(ciphertext[:65])
	envelope.Ciphertext = base64.RawURLEncoding.EncodeToString(ciphertext)
	envelope.ExpiresAt = time.Now().Add(4 * time.Minute).UnixMilli()
	message, err := json.Marshal(envelope)
	if err != nil {
		tb.Fatal(err)
	}
	return message
}

// BenchmarkParseEnvelope is the validation every relayed frame pays before routing.
//
// It rotates through distinct messages. Real ciphertext never repeats, and with one message
// repeated millions of times the CPU's branch predictor learns it, which makes any
// per-character branching validator look many times faster than it is on real traffic.
func BenchmarkParseEnvelope(b *testing.B) {
	for _, size := range benchmarkSizes {
		messages := make([][]byte, 64)
		for index := range messages {
			messages[index] = benchmarkEnvelope(b, size, strings.Repeat("s", 43), strings.Repeat("r", 43))
		}
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			now := time.Now()
			b.SetBytes(int64(len(messages[0])))
			b.ReportAllocs()
			index := 0
			for b.Loop() {
				if _, err := parseEnvelope(messages[index%len(messages)], now); err != nil {
					b.Fatal(err)
				}
				index++
			}
		})
	}
}

type benchmarkAdmissions map[string]connectors.Admission

func (admissions benchmarkAdmissions) ConsumeRelayTicket(_ context.Context, ticket string) (connectors.Admission, error) {
	admission, ok := admissions[ticket]
	if !ok {
		return connectors.Admission{}, connectors.ErrUnauthorized
	}
	return admission, nil
}

func (benchmarkAdmissions) ValidateAdmission(context.Context, connectors.Admission) error { return nil }

// BenchmarkRelayRoundTrip sends an envelope from a phone through the production relay to its
// connector and back, one at a time, over real WebSockets. Each iteration is two relayed
// frames; the peers' own reads and writes run in the same process and appear in profiles too.
func BenchmarkRelayRoundTrip(b *testing.B) {
	for _, size := range benchmarkSizes {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			phoneIdentity, connectorIdentity := testIdentity(strings.Repeat("p", 43)), testIdentity(strings.Repeat("c", 43))
			admission := func(role, subject string, self, peer publicIdentity) connectors.Admission {
				return connectors.Admission{UserID: "usr_benchmark", Role: role, SubjectID: subject, SessionID: "asn_benchmark",
					Identity:               connectors.PublicIdentity(self),
					TrustedIdentities:      []connectors.PublicIdentity{connectors.PublicIdentity(peer)},
					AuthorizationExpiresAt: time.Now().Add(time.Hour)}
			}
			handler := NewHandler(benchmarkAdmissions{
				"ort_phone":     admission(connectors.RelayRoleClient, "dev_benchmark", phoneIdentity, connectorIdentity),
				"ort_connector": admission(connectors.RelayRoleConnector, "con_benchmark", connectorIdentity, phoneIdentity),
			}, HandlerConfig{})
			server := httptest.NewServer(handler)
			b.Cleanup(func() { handler.Close(); server.Close() })

			dial := func(ticket string, hello helloMessage) *websocket.Conn {
				dialer := websocket.Dialer{Subprotocols: []string{relayWebSocketProtocol, "ticket." + ticket}}
				connection, _, err := dialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), nil)
				if err != nil {
					b.Fatal(err)
				}
				b.Cleanup(func() { _ = connection.Close() })
				if err := connection.WriteJSON(hello); err != nil {
					b.Fatal(err)
				}
				return connection
			}
			connector := dial("ort_connector", helloMessage{ProtocolVersion: protocolVersion, Type: "connector.hello",
				PluginVersion: "benchmark", Identity: connectorIdentity, Nonce: testNonce()})
			phone := dial("ort_phone", helloMessage{ProtocolVersion: protocolVersion, Type: "client.hello",
				Identity: phoneIdentity, Nonce: testNonce()})
			// Drain relay.ready and the presence hellos before timing.
			awaitType(b, connector, "client.hello")
			awaitType(b, phone, "connector.hello")

			request := benchmarkEnvelope(b, size, phoneIdentity.KeyID, connectorIdentity.KeyID)
			reply := benchmarkEnvelope(b, size, connectorIdentity.KeyID, phoneIdentity.KeyID)
			b.SetBytes(int64(len(request) + len(reply)))
			b.ReportAllocs()
			for b.Loop() {
				if err := phone.WriteMessage(websocket.TextMessage, request); err != nil {
					b.Fatal(err)
				}
				if _, _, err := connector.ReadMessage(); err != nil {
					b.Fatal(err)
				}
				if err := connector.WriteMessage(websocket.TextMessage, reply); err != nil {
					b.Fatal(err)
				}
				if _, _, err := phone.ReadMessage(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func awaitType(b *testing.B, connection *websocket.Conn, want string) {
	b.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer func() { _ = connection.SetReadDeadline(time.Time{}) }()
	for {
		var message struct {
			Type string `json:"type"`
		}
		if err := connection.ReadJSON(&message); err != nil {
			b.Fatalf("waiting for %s: %v", want, err)
		}
		if message.Type == want {
			return
		}
	}
}
