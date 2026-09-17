package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"opencode-remote/server/internal/connectors"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

const relayWebSocketProtocol = "opencode-remote.v1"

type AdmissionService interface {
	ConsumeRelayTicket(context.Context, string) (connectors.Admission, error)
	ValidateConnectorAdmission(context.Context, connectors.Admission) error
}

type HandlerConfig struct {
	AllowedOrigins []string
	Logger         *slog.Logger
	Now            func() time.Time
	// DevelopmentEcho also mounts the insecure /dev/relay echo endpoint. Never enable in production.
	DevelopmentEcho bool
}

type Handler struct {
	admissions      AdmissionService
	hub             *secureHub
	upgrader        websocket.Upgrader
	allowedOrigins  map[string]struct{}
	logger          *slog.Logger
	now             func() time.Time
	developmentEcho bool
}

func NewHandler(admissions AdmissionService, config HandlerConfig) *Handler {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	handler := &Handler{
		admissions:      admissions,
		hub:             newSecureHub(),
		allowedOrigins:  make(map[string]struct{}, len(config.AllowedOrigins)),
		logger:          config.Logger,
		now:             config.Now,
		developmentEcho: config.DevelopmentEcho,
	}
	for _, origin := range config.AllowedOrigins {
		if origin = strings.TrimSpace(origin); origin != "" {
			handler.allowedOrigins[origin] = struct{}{}
		}
	}
	handler.upgrader = websocket.Upgrader{
		HandshakeTimeout: helloTimeout,
		ReadBufferSize:   4096,
		WriteBufferSize:  4096,
		Subprotocols:     []string{relayWebSocketProtocol},
		CheckOrigin:      handler.allowOrigin,
	}
	return handler
}

// RegisterRoutes mounts the relay endpoint, plus the insecure development echo when enabled.
func (handler *Handler) RegisterRoutes(router gin.IRouter) {
	router.GET("/v1/relay", gin.WrapH(handler))
	if handler.developmentEcho {
		router.GET("/dev/relay", gin.WrapH(NewDevelopmentHandler()))
	}
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if !handler.allowOrigin(request) {
		http.Error(response, "origin not allowed", http.StatusForbidden)
		return
	}
	ticket, ok := relayTicket(request)
	if !ok {
		http.Error(response, "relay admission denied", http.StatusUnauthorized)
		return
	}
	admission, err := handler.admissions.ConsumeRelayTicket(request.Context(), ticket)
	if err != nil {
		http.Error(response, "relay admission denied", http.StatusUnauthorized)
		return
	}
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
	if err != nil || !helloMatchesAdmission(hello, admission) || !admission.AuthorizationExpiresAt.After(handler.now()) {
		closeWithPolicyViolation(connection)
		return
	}

	peer := newSecurePeer(connection, admission, hello)
	peer.enqueue(relayReadyMessage(admission))
	if err := handler.hub.register(peer); err != nil {
		closeWithPolicyViolation(connection)
		return
	}
	defer func() {
		handler.hub.unregister(peer)
		peer.stop()
	}()

	go peer.writePump()
	if admission.Role == connectors.RelayRoleConnector {
		validationContext, cancelValidation := context.WithCancel(request.Context())
		defer cancelValidation()
		go handler.monitorConnectorAuthorization(validationContext, peer, admission)
	}
	authorizationTimer := time.AfterFunc(admission.AuthorizationExpiresAt.Sub(handler.now()), peer.stop)
	defer authorizationTimer.Stop()
	connection.SetReadLimit(maxRelayFrameLength)
	_ = connection.SetReadDeadline(handler.now().Add(pongTimeout))
	connection.SetPongHandler(func(string) error {
		return connection.SetReadDeadline(handler.now().Add(pongTimeout))
	})

	for {
		messageType, message, err = connection.ReadMessage()
		if err != nil || messageType != websocket.TextMessage {
			return
		}
		envelope, err := parseEnvelope(message, handler.now())
		if err != nil || envelope.SenderKeyID != peer.keyID || !handler.hub.route(peer, envelope.RecipientKeyID, message) {
			return
		}
	}
}

// Recheck immediately and every second, including idle connections and admission/revocation races.
func (handler *Handler) monitorConnectorAuthorization(ctx context.Context, peer *securePeer, admission connectors.Admission) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		checkContext, cancel := context.WithTimeout(ctx, time.Second)
		err := handler.admissions.ValidateConnectorAdmission(checkContext, admission)
		cancel()
		if err != nil {
			peer.stop()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-peer.done:
			return
		case <-ticker.C:
		}
	}
}

func (handler *Handler) Close() {
	handler.hub.close()
}

func (handler *Handler) allowOrigin(request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == "" {
		return request.Header.Get("Sec-Fetch-Site") != "cross-site"
	}
	_, allowed := handler.allowedOrigins[origin]
	return allowed
}

func relayTicket(request *http.Request) (string, bool) {
	protocols := websocket.Subprotocols(request)
	if len(protocols) != 2 || protocols[0] != relayWebSocketProtocol || !strings.HasPrefix(protocols[1], "ticket.") {
		return "", false
	}
	ticket := strings.TrimPrefix(protocols[1], "ticket.")
	return ticket, ticket != ""
}

func helloMatchesAdmission(hello helloMessage, admission connectors.Admission) bool {
	expectedType := admission.Role + ".hello"
	return hello.Type == expectedType &&
		hello.Identity.Version == admission.Identity.Version &&
		hello.Identity.Suite == admission.Identity.Suite &&
		hello.Identity.KeyID == admission.Identity.KeyID &&
		hello.Identity.PublicKey == admission.Identity.PublicKey
}

func relayReadyMessage(admission connectors.Admission) []byte {
	message, _ := json.Marshal(struct {
		ProtocolVersion        int       `json:"protocolVersion"`
		Type                   string    `json:"type"`
		Role                   string    `json:"role"`
		KeyID                  string    `json:"keyId"`
		AuthorizationExpiresAt time.Time `json:"authorizationExpiresAt"`
	}{
		ProtocolVersion:        protocolVersion,
		Type:                   "relay.ready",
		Role:                   admission.Role,
		KeyID:                  admission.Identity.KeyID,
		AuthorizationExpiresAt: admission.AuthorizationExpiresAt,
	})
	return message
}

type securePeer struct {
	connection *websocket.Conn
	userID     string
	role       string
	keyID      string
	hello      []byte
	trusted    map[string]struct{}
	send       chan []byte
	done       chan struct{}
	stopOnce   sync.Once
}

func newSecurePeer(connection *websocket.Conn, admission connectors.Admission, hello helloMessage) *securePeer {
	serializedHello, _ := json.Marshal(hello)
	trusted := make(map[string]struct{}, len(admission.TrustedIdentities))
	for _, identity := range admission.TrustedIdentities {
		trusted[identity.KeyID] = struct{}{}
	}
	return &securePeer{
		connection: connection,
		userID:     admission.UserID,
		role:       admission.Role,
		keyID:      admission.Identity.KeyID,
		hello:      serializedHello,
		trusted:    trusted,
		send:       make(chan []byte, outboundQueueCapacity),
		done:       make(chan struct{}),
	}
}

func (peer *securePeer) enqueue(message []byte) bool {
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

func (peer *securePeer) stop() {
	peer.stopOnce.Do(func() { close(peer.done) })
}

func (peer *securePeer) writePump() {
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
			if err := peer.connection.WriteControl(websocket.PingMessage, nil, time.Now().Add(writeTimeout)); err != nil {
				return
			}
		case <-peer.done:
			_ = peer.connection.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(writeTimeout))
			return
		}
	}
}

type secureHub struct {
	mutex sync.RWMutex
	peers map[string]*securePeer
}

func newSecureHub() *secureHub { return &secureHub{peers: make(map[string]*securePeer)} }

func securePeerID(userID, keyID string) string { return userID + ":" + keyID }

// register admits connected, replacing any existing connection already
// registered for the same identity. A same-identity replacement happens when
// a peer proactively renews its relay admission ahead of its authorization
// lease expiring (see Handler.ServeHTTP's authorizationTimer): the new
// connection has independently passed the same ticket-consumption and
// identity checks as any other connection, so evicting the old one here
// never crosses accounts or bypasses authentication. The evicted peer's own
// serve loop unwinds through its normal stop()/unregister path; unregister's
// stale-write guard (hub.peers[id] != connected) makes that a no-op once
// this function has already installed the replacement, so no spurious
// offline event reaches other peers and the new registration is untouched.
func (hub *secureHub) register(connected *securePeer) error {
	hub.mutex.Lock()
	id := securePeerID(connected.userID, connected.keyID)
	existing := hub.peers[id]
	hub.peers[id] = connected
	var recipients []*securePeer
	var messages [][]byte
	for _, peer := range hub.peers {
		if peer == connected || peer.userID != connected.userID || peer.role == connected.role {
			continue
		}
		if _, trusted := peer.trusted[connected.keyID]; !trusted {
			continue
		}
		if _, trusted := connected.trusted[peer.keyID]; !trusted {
			continue
		}
		// Whichever side just (re)connected, tell it about the other and vice versa.
		recipients, messages = append(recipients, peer), append(messages, connected.hello)
		recipients, messages = append(recipients, connected), append(messages, peer.hello)
	}
	hub.mutex.Unlock()
	if existing != nil {
		existing.stop()
	}
	for index, recipient := range recipients {
		recipient.enqueue(messages[index])
	}
	return nil
}

func (hub *secureHub) unregister(connected *securePeer) {
	hub.mutex.Lock()
	id := securePeerID(connected.userID, connected.keyID)
	if hub.peers[id] != connected {
		hub.mutex.Unlock()
		return
	}
	delete(hub.peers, id)
	isConnector := connected.role == connectors.RelayRoleConnector
	peerRole := connectors.RelayRoleClient
	if !isConnector {
		peerRole = connectors.RelayRoleConnector
	}
	var recipients []*securePeer
	for _, peer := range hub.peers {
		if peer.userID == connected.userID && peer.role == peerRole {
			if _, trusted := peer.trusted[connected.keyID]; trusted {
				recipients = append(recipients, peer)
			}
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
	}{ProtocolVersion: protocolVersion, Type: offlineType, KeyID: connected.keyID})
	for _, recipient := range recipients {
		recipient.enqueue(offline)
	}
}

func (hub *secureHub) route(sender *securePeer, recipientKeyID string, message []byte) bool {
	if _, trusted := sender.trusted[recipientKeyID]; !trusted {
		return false
	}
	hub.mutex.RLock()
	recipient := hub.peers[securePeerID(sender.userID, recipientKeyID)]
	if recipient != nil {
		_, reciprocalTrust := recipient.trusted[sender.keyID]
		if recipient.role == sender.role || !reciprocalTrust {
			hub.mutex.RUnlock()
			return false
		}
	}
	hub.mutex.RUnlock()
	if recipient != nil {
		recipient.enqueue(message)
	}
	return true
}

func (hub *secureHub) close() {
	hub.mutex.Lock()
	peers := make([]*securePeer, 0, len(hub.peers))
	for _, peer := range hub.peers {
		peers = append(peers, peer)
	}
	hub.peers = make(map[string]*securePeer)
	hub.mutex.Unlock()
	for _, peer := range peers {
		peer.stop()
	}
}
