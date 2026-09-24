package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	protocolVersion = 2
	// Identities are versioned independently of the relay protocol; they persist
	// across protocol revisions and must not be invalidated by one.
	identityVersion       = 1
	hpkeSuiteID           = "HPKE-Auth-P256-HKDF-SHA256-AES-256-GCM"
	maxHelloLength        = 16 * 1024
	maxRelayFrameLength   = 2_000_000
	maxCiphertextLength   = 1_500_000
	maxEnvelopeTTL        = 5 * time.Minute
	helloTimeout          = 10 * time.Second
	writeTimeout          = 10 * time.Second
	pongTimeout           = 60 * time.Second
	pingInterval          = 45 * time.Second
	outboundQueueCapacity = 64
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

type DevelopmentHandler struct {
	hub      *hub
	upgrader websocket.Upgrader
	now      func() time.Time
}

func NewDevelopmentHandler() *DevelopmentHandler {
	return &DevelopmentHandler{
		hub: newHub(),
		upgrader: websocket.Upgrader{
			HandshakeTimeout: helloTimeout,
			ReadBufferSize:   4096,
			WriteBufferSize:  4096,
			CheckOrigin:      allowDevelopmentOrigin,
		},
		now: time.Now,
	}
}

func (handler *DevelopmentHandler) ServeHTTP(
	response http.ResponseWriter,
	request *http.Request,
) {
	connection, err := handler.upgrader.Upgrade(response, request, nil)
	if err != nil {
		return
	}
	connection.EnableWriteCompression(false)
	connection.SetReadLimit(maxHelloLength)
	_ = connection.SetReadDeadline(handler.now().Add(helloTimeout))

	messageType, message, err := connection.ReadMessage()
	if err != nil || messageType != websocket.TextMessage {
		_ = connection.Close()
		return
	}
	hello, err := parseHello(message)
	if err != nil {
		closeWithPolicyViolation(connection)
		return
	}

	peer := newPeer(connection, hello)
	if err := handler.hub.register(peer); err != nil {
		closeWithPolicyViolation(connection)
		return
	}
	defer func() {
		handler.hub.unregister(peer)
		peer.stop()
	}()

	go peer.writePump()
	connection.SetReadLimit(maxRelayFrameLength)
	_ = connection.SetReadDeadline(handler.now().Add(pongTimeout))
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(handler.now().Add(pongTimeout))
	})

	for {
		messageType, message, err = connection.ReadMessage()
		if err != nil {
			return
		}
		if messageType != websocket.TextMessage {
			return
		}

		envelope, err := parseEnvelope(message, handler.now())
		if err != nil || envelope.SenderKeyID != peer.keyID {
			return
		}
		if !handler.hub.route(envelope.RecipientKeyID, message) {
			return
		}
	}
}

type publicIdentity struct {
	Version   int    `json:"version"`
	Suite     string `json:"suite"`
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

type helloMessage struct {
	ProtocolVersion int            `json:"protocolVersion"`
	Type            string         `json:"type"`
	PluginVersion   string         `json:"pluginVersion,omitempty"`
	Identity        publicIdentity `json:"identity"`
	Nonce           string         `json:"nonce"`
	Capabilities    []string       `json:"capabilities,omitempty"`
}

type relayEnvelope struct {
	ProtocolVersion int    `json:"protocolVersion"`
	Type            string `json:"type"`
	MessageID       string `json:"messageId"`
	SenderKeyID     string `json:"senderKeyId"`
	RecipientKeyID  string `json:"recipientKeyId"`
	Epoch           string `json:"epoch"`
	Sequence        uint64 `json:"sequence"`
	ExpiresAt       int64  `json:"expiresAt"`
	Suite           string `json:"suite"`
	EncapsulatedKey string `json:"encapsulatedKey"`
	Ciphertext      string `json:"ciphertext"`
}

func parseHello(message []byte) (helloMessage, error) {
	var hello helloMessage
	if err := decodeStrict(message, &hello); err != nil {
		return hello, err
	}
	if hello.ProtocolVersion != protocolVersion || !validIdentity(hello.Identity) ||
		!exactBase64URL(hello.Nonce, 22) {
		return hello, errors.New("invalid hello protocol, identity or nonce")
	}

	switch hello.Type {
	case "client.hello":
		if hello.PluginVersion != "" || len(hello.Capabilities) != 0 {
			return hello, errors.New("invalid client hello")
		}
	case "connector.hello":
		if hello.PluginVersion == "" || len(hello.PluginVersion) > 32 || len(hello.Capabilities) > 64 {
			return hello, errors.New("invalid connector hello")
		}
		for _, capability := range hello.Capabilities {
			if capability == "" || len(capability) > 64 {
				return hello, errors.New("invalid connector capability")
			}
		}
	default:
		return hello, errors.New("unsupported hello type")
	}
	return hello, nil
}

func parseEnvelope(message []byte, now time.Time) (relayEnvelope, error) {
	var envelope relayEnvelope
	if err := decodeStrict(message, &envelope); err != nil {
		return envelope, err
	}
	nowMilliseconds := now.UnixMilli()
	if envelope.ProtocolVersion != protocolVersion ||
		envelope.Type != "relay.envelope" ||
		envelope.Suite != hpkeSuiteID ||
		!uuidPattern.MatchString(envelope.MessageID) ||
		!exactBase64URL(envelope.SenderKeyID, 43) ||
		!exactBase64URL(envelope.RecipientKeyID, 43) ||
		!exactBase64URL(envelope.Epoch, 43) ||
		envelope.ExpiresAt <= nowMilliseconds ||
		envelope.ExpiresAt > now.Add(maxEnvelopeTTL).UnixMilli() ||
		!validBase64URL(envelope.EncapsulatedKey, 256) ||
		!validBase64URL(envelope.Ciphertext, maxCiphertextLength) {
		return envelope, errors.New("invalid relay envelope")
	}
	return envelope, nil
}

func validIdentity(identity publicIdentity) bool {
	return identity.Version == identityVersion &&
		identity.Suite == hpkeSuiteID &&
		exactBase64URL(identity.KeyID, 43) &&
		validBase64URL(identity.PublicKey, 1024)
}

// base64URLAlphabet marks the bytes of unpadded base64url (RFC 4648 §5).
var base64URLAlphabet = func() (table [256]bool) {
	for _, character := range []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") {
		table[character] = true
	}
	return table
}()

// isBase64URL reports whether every byte of value is in the base64url alphabet. Every
// relayed frame runs its ciphertext through this, so it is a table lookup per byte: a
// regular expression cost about 60% of relay CPU, and a per-byte switch mispredicts on
// ciphertext, which never repeats. Bytes of a multi-byte UTF-8 sequence are all >= 0x80
// and so never in the table.
func isBase64URL(value string) bool {
	for index := 0; index < len(value); index++ {
		if !base64URLAlphabet[value[index]] {
			return false
		}
	}
	return true
}

func validBase64URL(value string, maximumLength int) bool {
	return len(value) > 0 && len(value) <= maximumLength && isBase64URL(value)
}

func exactBase64URL(value string, length int) bool {
	return len(value) == length && isBase64URL(value)
}

func decodeStrict(message []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(message))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("message contains trailing data")
	}
	return nil
}

func allowDevelopmentOrigin(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return false
	}
	switch parsed.Hostname() {
	case "127.0.0.1", "::1", "localhost":
		return true
	default:
		return false
	}
}

type peer struct {
	connection *websocket.Conn
	keyID      string
	role       string
	hello      []byte
	send       chan []byte
	done       chan struct{}
	stopOnce   sync.Once
}

func newPeer(connection *websocket.Conn, hello helloMessage) *peer {
	serializedHello, _ := json.Marshal(hello)
	return &peer{
		connection: connection,
		keyID:      hello.Identity.KeyID,
		role:       hello.Type,
		hello:      serializedHello,
		send:       make(chan []byte, outboundQueueCapacity),
		done:       make(chan struct{}),
	}
}

func (peer *peer) enqueue(message []byte) bool {
	message = bytes.Clone(message)
	select {
	case <-peer.done:
		return false
	case peer.send <- message:
		return true
	default:
		peer.stop()
		return false
	}
}

func (peer *peer) stop() {
	peer.stopOnce.Do(func() {
		close(peer.done)
	})
}

func (peer *peer) writePump() {
	ticker := time.NewTicker(pingInterval)
	defer func() {
		ticker.Stop()
		_ = peer.connection.Close()
	}()

	for {
		select {
		case message := <-peer.send:
			_ = peer.connection.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := peer.connection.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			if err := peer.connection.WriteControl(
				websocket.PingMessage,
				nil,
				time.Now().Add(writeTimeout),
			); err != nil {
				return
			}
		case <-peer.done:
			_ = peer.connection.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
				time.Now().Add(writeTimeout),
			)
			return
		}
	}
}

type hub struct {
	mutex      sync.RWMutex
	peers      map[string]*peer
	connectors map[string]*peer
	clients    map[string]*peer
}

func newHub() *hub {
	return &hub{
		peers:      make(map[string]*peer),
		connectors: make(map[string]*peer),
		clients:    make(map[string]*peer),
	}
}

func (hub *hub) register(connectedPeer *peer) error {
	hub.mutex.Lock()
	if _, exists := hub.peers[connectedPeer.keyID]; exists {
		hub.mutex.Unlock()
		return errors.New("identity is already connected")
	}
	hub.peers[connectedPeer.keyID] = connectedPeer
	var recipients []*peer
	var messages [][]byte
	if connectedPeer.role == "connector.hello" {
		hub.connectors[connectedPeer.keyID] = connectedPeer
		for _, client := range hub.clients {
			recipients = append(recipients, client)
			messages = append(messages, connectedPeer.hello)
			recipients = append(recipients, connectedPeer)
			messages = append(messages, client.hello)
		}
	} else {
		hub.clients[connectedPeer.keyID] = connectedPeer
		for _, connector := range hub.connectors {
			recipients = append(recipients, connectedPeer)
			messages = append(messages, connector.hello)
			recipients = append(recipients, connector)
			messages = append(messages, connectedPeer.hello)
		}
	}
	hub.mutex.Unlock()

	for index, recipient := range recipients {
		recipient.enqueue(messages[index])
	}
	return nil
}

func (hub *hub) unregister(connectedPeer *peer) {
	hub.mutex.Lock()
	if hub.peers[connectedPeer.keyID] != connectedPeer {
		hub.mutex.Unlock()
		return
	}
	delete(hub.peers, connectedPeer.keyID)
	delete(hub.connectors, connectedPeer.keyID)
	delete(hub.clients, connectedPeer.keyID)
	isConnector := connectedPeer.role == "connector.hello"
	var recipients []*peer
	if isConnector {
		for _, client := range hub.clients {
			recipients = append(recipients, client)
		}
	} else {
		for _, connector := range hub.connectors {
			recipients = append(recipients, connector)
		}
	}
	hub.mutex.Unlock()

	offlineType := "client.offline"
	if isConnector {
		offlineType = "connector.offline"
	}
	offline, _ := json.Marshal(struct {
		ProtocolVersion int    `json:"protocolVersion"`
		Type            string `json:"type"`
		KeyID           string `json:"keyId"`
	}{
		ProtocolVersion: protocolVersion,
		Type:            offlineType,
		KeyID:           connectedPeer.keyID,
	})
	for _, recipient := range recipients {
		recipient.enqueue(offline)
	}
}

func (hub *hub) route(recipientKeyID string, message []byte) bool {
	hub.mutex.RLock()
	recipient := hub.peers[recipientKeyID]
	hub.mutex.RUnlock()
	return recipient != nil && recipient.enqueue(message)
}

func closeWithPolicyViolation(connection *websocket.Conn) {
	_ = connection.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.ClosePolicyViolation, ""),
		time.Now().Add(writeTimeout),
	)
	_ = connection.Close()
}
