package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"opencode-remote/server/internal/connectors"
	"opencode-remote/server/internal/identity"
	"opencode-remote/server/internal/platform/httpserver"

	"github.com/gin-gonic/gin"
)

const (
	secureDeviceCookieName      = "__Host-opencode_remote_device"
	developmentDeviceCookieName = "opencode_remote_device"
	maximumBodySize             = 16 * 1024
)

type AuthenticationService interface {
	AuthenticateAccess(context.Context, string) (identity.AccessPrincipal, error)
}

type ConnectorService interface {
	IssueChallenge(context.Context, string, *string) (connectors.ChallengeResult, error)
	BeginPairing(context.Context, connectors.BeginPairingInput) (connectors.BeginPairingResult, error)
	ClaimPairing(context.Context, connectors.ClaimPairingInput) (connectors.ClaimPairingResult, error)
	ConfirmPairing(context.Context, string, string, string) (connectors.ConfirmPairingResult, error)
	PollPairing(context.Context, string) (connectors.PollPairingResult, error)
	CancelPairing(context.Context, string, string) error
	RevokeConnector(context.Context, string) error
	RotateConnectorCredential(context.Context, string) (connectors.RotationResult, error)
	ActivateConnectorCredential(context.Context, string) (time.Time, error)
	RevokeAccountConnector(context.Context, string, string) error
	RenameAccountConnector(context.Context, string, string, string) (connectors.Connector, error)
	OwnConnector(context.Context, string) (connectors.Connector, error)
	RotateDeviceCredential(context.Context, string, string, string, string) (connectors.RotationResult, error)
	ActivateDeviceCredential(context.Context, string, string, string, string) (time.Time, error)
	IssueBrowserTicket(context.Context, string, string, string, string, time.Time) (connectors.TicketResult, error)
	IssueConnectorTicket(context.Context, string) (connectors.TicketResult, error)
	ListConnectors(context.Context, string) ([]connectors.Connector, error)
}

type Config struct {
	AllowedOrigins []string
	CookieSecure   bool
	Logger         *slog.Logger
	Now            func() time.Time
	TrustedProxies []*net.IPNet
}

type Handler struct {
	authentication AuthenticationService
	connectors     ConnectorService
	allowedOrigins map[string]struct{}
	trustedProxies []*net.IPNet
	cookieSecure   bool
	cookieName     string
	cookiePath     string
	logger         *slog.Logger
	now            func() time.Time
	beginLimiter   *fixedWindowLimiter
	claimLimiter   *fixedWindowLimiter
	pollLimiter    *fixedWindowLimiter
	ticketLimiter  *fixedWindowLimiter
}

func NewHandler(authentication AuthenticationService, connectorService ConnectorService, config Config) *Handler {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	handler := &Handler{
		authentication: authentication,
		connectors:     connectorService,
		allowedOrigins: make(map[string]struct{}, len(config.AllowedOrigins)),
		trustedProxies: config.TrustedProxies,
		cookieSecure:   config.CookieSecure,
		logger:         config.Logger,
		now:            config.Now,
		beginLimiter:   newFixedWindowLimiter(10, time.Minute),
		claimLimiter:   newFixedWindowLimiter(10, time.Minute),
		pollLimiter:    newFixedWindowLimiter(60, time.Minute),
		ticketLimiter:  newFixedWindowLimiter(60, time.Minute),
	}
	if config.CookieSecure {
		handler.cookieName, handler.cookiePath = secureDeviceCookieName, "/"
	} else {
		handler.cookieName, handler.cookiePath = developmentDeviceCookieName, "/v1"
	}
	for _, origin := range config.AllowedOrigins {
		if origin = strings.TrimSpace(origin); origin != "" {
			handler.allowedOrigins[origin] = struct{}{}
		}
	}
	return handler
}

func (handler *Handler) RegisterRoutes(router gin.IRouter) {
	pairings := router.Group("/v1/connector-pairings")
	pairings.POST("/challenge", handler.plugin(handler.beginLimiter, handler.connectorChallenge))
	pairings.POST("", handler.plugin(handler.beginLimiter, handler.beginPairing))
	pairings.POST("/:pairingID/poll", handler.plugin(handler.pollLimiter, handler.pollPairing))
	pairings.POST("/:pairingID/cancel", handler.plugin(handler.pollLimiter, handler.cancelPairing))
	pairings.POST("/claim", handler.browser(handler.claimLimiter, handler.claimPairing))
	pairings.POST("/:pairingID/confirm", handler.browser(handler.claimLimiter, handler.confirmPairing))

	router.POST("/v1/devices/challenge", handler.browser(handler.claimLimiter, handler.deviceChallenge))
	router.POST("/v1/devices/self/rotate", handler.browser(handler.ticketLimiter, handler.rotateDeviceCredential))
	router.POST("/v1/devices/self/rotate/activate", handler.browser(handler.ticketLimiter, handler.activateDeviceCredential))
	router.POST("/v1/relay/tickets", handler.limited(handler.ticketLimiter, handler.issueTicket))

	connectors := router.Group("/v1/connectors")
	connectors.GET("", gin.WrapF(handler.listConnectors))
	connectors.HEAD("", gin.WrapF(handler.listConnectors))
	connectors.POST("/self/revoke", handler.plugin(handler.ticketLimiter, handler.revokeConnector))
	connectors.POST("/self/rotate", handler.plugin(handler.ticketLimiter, handler.rotateConnectorCredential))
	connectors.POST("/self/rotate/activate", handler.plugin(handler.ticketLimiter, handler.activateConnectorCredential))
	connectors.POST("/:connectorID/revoke", handler.browser(handler.ticketLimiter, handler.revokeAccountConnector))
	connectors.POST("/:connectorID/rename", handler.browser(handler.ticketLimiter, handler.renameAccountConnector))
	connectors.GET("/self", handler.plugin(handler.ticketLimiter, handler.ownConnector))
	connectors.HEAD("/self", handler.plugin(handler.ticketLimiter, handler.ownConnector))
}

// plugin, browser, and limited attach the audience gate and rate limiter for a route,
// keeping the route table readable as "audience, limiter, handler".
func (handler *Handler) plugin(limiter *fixedWindowLimiter, next http.HandlerFunc) gin.HandlerFunc {
	return httpserver.WrapHandler(handler.pluginOnly(limiter, next))
}

func (handler *Handler) browser(limiter *fixedWindowLimiter, next http.HandlerFunc) gin.HandlerFunc {
	return httpserver.WrapHandler(handler.browserOnly(limiter, next))
}

func (handler *Handler) limited(limiter *fixedWindowLimiter, next http.HandlerFunc) gin.HandlerFunc {
	return httpserver.WrapHandler(handler.rateLimited(limiter, next))
}

func (handler *Handler) connectorChallenge(response http.ResponseWriter, request *http.Request) {
	result, err := handler.connectors.IssueChallenge(request.Context(), connectors.ChallengePurposeConnector, nil)
	if err != nil {
		handler.writeServiceError(response, "connector_challenge", err)
		return
	}
	writeJSON(response, http.StatusCreated, challengeResponse{Challenge: result.Challenge, ExpiresAt: result.ExpiresAt})
}

func (handler *Handler) deviceChallenge(response http.ResponseWriter, request *http.Request) {
	principal, ok := handler.accessPrincipal(response, request)
	if !ok {
		return
	}
	result, err := handler.connectors.IssueChallenge(request.Context(), connectors.ChallengePurposeDevice, &principal.Account.ID)
	if err != nil {
		handler.writeServiceError(response, "device_challenge", err)
		return
	}
	writeJSON(response, http.StatusCreated, challengeResponse{Challenge: result.Challenge, ExpiresAt: result.ExpiresAt})
}

func (handler *Handler) beginPairing(response http.ResponseWriter, request *http.Request) {
	var input struct {
		Name     string                    `json:"name"`
		Identity connectors.PublicIdentity `json:"identity"`
		Proof    connectors.IdentityProof  `json:"proof"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeDecodeError(response, err)
		return
	}
	result, err := handler.connectors.BeginPairing(request.Context(), connectors.BeginPairingInput(input))
	if err != nil {
		handler.writeServiceError(response, "begin_pairing", err)
		return
	}
	writeJSON(response, http.StatusCreated, beginPairingResponse{
		PairingID: result.PairingID, PairingSecret: result.PairingSecret, UserCode: result.UserCode,
		ServiceID: result.ServiceID, VerificationURI: result.VerificationURI, ExpiresAt: result.ExpiresAt,
		PollIntervalSeconds: max(1, int(result.PollInterval/time.Second)),
	})
}

func (handler *Handler) claimPairing(response http.ResponseWriter, request *http.Request) {
	principal, ok := handler.accessPrincipal(response, request)
	if !ok {
		return
	}
	var input struct {
		UserCode   string                    `json:"userCode"`
		DeviceName string                    `json:"deviceName"`
		Identity   connectors.PublicIdentity `json:"identity"`
		Proof      connectors.IdentityProof  `json:"proof"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeDecodeError(response, err)
		return
	}
	result, err := handler.connectors.ClaimPairing(request.Context(), connectors.ClaimPairingInput{
		UserID: principal.Account.ID, UserCode: input.UserCode, DeviceName: input.DeviceName,
		Identity: input.Identity, Proof: input.Proof,
	})
	if err != nil {
		handler.writeServiceError(response, "claim_pairing", err)
		return
	}
	writeJSON(response, http.StatusOK, claimPairingResponse(result))
}

func (handler *Handler) confirmPairing(response http.ResponseWriter, request *http.Request) {
	principal, ok := handler.accessPrincipal(response, request)
	if !ok {
		return
	}
	var input struct {
		DeviceID string `json:"deviceId"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeDecodeError(response, err)
		return
	}
	result, err := handler.connectors.ConfirmPairing(request.Context(), principal.Account.ID, request.PathValue("pairingID"), input.DeviceID)
	if err != nil {
		handler.writeServiceError(response, "confirm_pairing", err)
		return
	}
	handler.setDeviceCookie(response, result)
	writeJSON(response, http.StatusOK, struct {
		DeviceID    string `json:"deviceId"`
		ConnectorID string `json:"connectorId"`
	}{DeviceID: result.DeviceID, ConnectorID: result.ConnectorID})
}

func (handler *Handler) pollPairing(response http.ResponseWriter, request *http.Request) {
	secret, err := authorizationToken(request, "Pairing")
	if err != nil {
		handler.writeServiceError(response, "poll_pairing", connectors.ErrUnauthorized)
		return
	}
	result, err := handler.connectors.PollPairing(request.Context(), secret)
	if err != nil {
		handler.writeServiceError(response, "poll_pairing", err)
		return
	}
	if request.PathValue("pairingID") != result.PairingID {
		handler.writeServiceError(response, "poll_pairing", connectors.ErrUnauthorized)
		return
	}
	writeJSON(response, http.StatusOK, pollPairingResponse(result))
}

func (handler *Handler) cancelPairing(response http.ResponseWriter, request *http.Request) {
	secret, err := authorizationToken(request, "Pairing")
	if err != nil {
		handler.writeServiceError(response, "cancel_pairing", connectors.ErrUnauthorized)
		return
	}
	if err := handler.connectors.CancelPairing(request.Context(), request.PathValue("pairingID"), secret); err != nil {
		handler.writeServiceError(response, "cancel_pairing", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) ownConnector(response http.ResponseWriter, request *http.Request) {
	credential, err := authorizationToken(request, "Bearer")
	if err != nil {
		handler.writeServiceError(response, "own_connector", connectors.ErrUnauthorized)
		return
	}
	connector, err := handler.connectors.OwnConnector(request.Context(), credential)
	if err != nil {
		handler.writeServiceError(response, "own_connector", err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		ConnectorID string    `json:"connectorId"`
		LinkedAt    time.Time `json:"linkedAt"`
	}{ConnectorID: connector.ID, LinkedAt: connector.CreatedAt})
}

func (handler *Handler) revokeConnector(response http.ResponseWriter, request *http.Request) {
	credential, err := authorizationToken(request, "Bearer")
	if err != nil {
		handler.writeServiceError(response, "revoke_connector", connectors.ErrUnauthorized)
		return
	}
	if err := handler.connectors.RevokeConnector(request.Context(), credential); err != nil {
		handler.writeServiceError(response, "revoke_connector", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

// rotateConnectorCredential issues a replacement the caller must activate. The current
// credential keeps working until then, so a plugin that never persists this one is not
// locked out.
func (handler *Handler) rotateConnectorCredential(response http.ResponseWriter, request *http.Request) {
	credential, err := authorizationToken(request, "Bearer")
	if err != nil {
		handler.writeServiceError(response, "rotate_connector_credential", connectors.ErrUnauthorized)
		return
	}
	result, err := handler.connectors.RotateConnectorCredential(request.Context(), credential)
	if err != nil {
		handler.writeServiceError(response, "rotate_connector_credential", err)
		return
	}
	writeJSON(response, http.StatusCreated, rotateConnectorResponse{
		Credential: result.Credential, ActivateBy: result.ActivateBy,
	})
}

// activateConnectorCredential is authenticated by the pending credential, which is not the
// live one yet, so it commits the rotation the caller has already made durable.
func (handler *Handler) activateConnectorCredential(response http.ResponseWriter, request *http.Request) {
	credential, err := authorizationToken(request, "Bearer")
	if err != nil {
		handler.writeServiceError(response, "activate_connector_credential", connectors.ErrUnauthorized)
		return
	}
	expiresAt, err := handler.connectors.ActivateConnectorCredential(request.Context(), credential)
	if err != nil {
		handler.writeServiceError(response, "activate_connector_credential", err)
		return
	}
	writeJSON(response, http.StatusOK, activateConnectorResponse{CredentialExpiresAt: expiresAt})
}

func (handler *Handler) issueTicket(response http.ResponseWriter, request *http.Request) {
	credential, err := authorizationToken(request, "Bearer")
	if err != nil {
		handler.writeServiceError(response, "issue_ticket", connectors.ErrUnauthorized)
		return
	}
	var input struct {
		DeviceID string `json:"deviceId,omitempty"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeDecodeError(response, err)
		return
	}
	var result connectors.TicketResult
	if strings.HasPrefix(credential, "orc_") {
		if request.Header.Get("Origin") != "" || input.DeviceID != "" {
			handler.writeServiceError(response, "issue_ticket", connectors.ErrUnauthorized)
			return
		}
		result, err = handler.connectors.IssueConnectorTicket(request.Context(), credential)
	} else {
		if !handler.allowedBrowserOrigin(response, request) {
			return
		}
		principal, authErr := handler.authentication.AuthenticateAccess(request.Context(), credential)
		if authErr != nil {
			handler.writeServiceError(response, "issue_ticket", connectors.ErrUnauthorized)
			return
		}
		cookie, cookieErr := request.Cookie(handler.cookieName)
		if cookieErr != nil {
			handler.writeServiceError(response, "issue_ticket", connectors.ErrUnauthorized)
			return
		}
		result, err = handler.connectors.IssueBrowserTicket(request.Context(), principal.Account.ID, principal.SessionID, input.DeviceID, cookie.Value, principal.AccessTokenExpiresAt)
	}
	if err != nil {
		handler.writeServiceError(response, "issue_ticket", err)
		return
	}
	writeJSON(response, http.StatusCreated, ticketResponse{Ticket: result.Ticket, ExpiresAt: result.ExpiresAt, WebSocketURL: "/v1/relay"})
}

func (handler *Handler) listConnectors(response http.ResponseWriter, request *http.Request) {
	principal, ok := handler.accessPrincipal(response, request)
	if !ok {
		return
	}
	items, err := handler.connectors.ListConnectors(request.Context(), principal.Account.ID)
	if err != nil {
		handler.writeServiceError(response, "list_connectors", err)
		return
	}
	documents := make([]connectorDocument, 0, len(items))
	for _, item := range items {
		documents = append(documents, connectorDocument{ID: item.ID, Name: item.Name, Identity: item.Identity, CreatedAt: item.CreatedAt})
	}
	writeJSON(response, http.StatusOK, struct {
		Connectors []connectorDocument `json:"connectors"`
	}{Connectors: documents})
}

func (handler *Handler) revokeAccountConnector(response http.ResponseWriter, request *http.Request) {
	principal, ok := handler.accessPrincipal(response, request)
	if !ok {
		return
	}
	err := handler.connectors.RevokeAccountConnector(request.Context(), principal.Account.ID, request.PathValue("connectorID"))
	if errors.Is(err, connectors.ErrNotFound) {
		writeError(response, http.StatusNotFound, "not_found", "Connection is unavailable")
		return
	}
	if err != nil {
		handler.writeServiceError(response, "revoke_account_connector", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) renameAccountConnector(response http.ResponseWriter, request *http.Request) {
	principal, ok := handler.accessPrincipal(response, request)
	if !ok {
		return
	}
	var input struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeDecodeError(response, err)
		return
	}
	connector, err := handler.connectors.RenameAccountConnector(request.Context(), principal.Account.ID, request.PathValue("connectorID"), input.Name)
	if errors.Is(err, connectors.ErrNotFound) {
		writeError(response, http.StatusNotFound, "not_found", "Connection is unavailable")
		return
	}
	if err != nil {
		handler.writeServiceError(response, "rename_account_connector", err)
		return
	}
	writeJSON(response, http.StatusOK, struct {
		ConnectorID string `json:"connectorId"`
		Name        string `json:"name"`
	}{connector.ID, connector.Name})
}

func (handler *Handler) accessPrincipal(response http.ResponseWriter, request *http.Request) (identity.AccessPrincipal, bool) {
	token, err := authorizationToken(request, "Bearer")
	if err != nil {
		response.Header().Set("WWW-Authenticate", "Bearer")
		handler.writeServiceError(response, "access", connectors.ErrUnauthorized)
		return identity.AccessPrincipal{}, false
	}
	principal, err := handler.authentication.AuthenticateAccess(request.Context(), token)
	if err != nil {
		response.Header().Set("WWW-Authenticate", "Bearer")
		handler.writeServiceError(response, "access", connectors.ErrUnauthorized)
		return identity.AccessPrincipal{}, false
	}
	return principal, true
}

func (handler *Handler) pluginOnly(limiter *fixedWindowLimiter, next http.Handler) http.Handler {
	return handler.rateLimited(limiter, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Origin") != "" || request.Header.Get("Sec-Fetch-Site") == "cross-site" {
			writeError(response, http.StatusForbidden, "origin_not_allowed", "Request origin is not allowed")
			return
		}
		next.ServeHTTP(response, request)
	}))
}

func (handler *Handler) browserOnly(limiter *fixedWindowLimiter, next http.Handler) http.Handler {
	return handler.rateLimited(limiter, http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if !handler.allowedBrowserOrigin(response, request) {
			return
		}
		next.ServeHTTP(response, request)
	}))
}

func (handler *Handler) allowedBrowserOrigin(response http.ResponseWriter, request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin != "" {
		response.Header().Add("Vary", "Origin")
		if _, allowed := handler.allowedOrigins[origin]; allowed {
			return true
		}
	} else if request.Header.Get("Sec-Fetch-Site") != "cross-site" {
		return true
	}
	writeError(response, http.StatusForbidden, "origin_not_allowed", "Request origin is not allowed")
	return false
}

func (handler *Handler) rateLimited(limiter *fixedWindowLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		allowed, retryAfter := limiter.allow(clientAddress(request, handler.trustedProxies), handler.now())
		if !allowed {
			response.Header().Set("Retry-After", strconv.Itoa(max(1, int((retryAfter+time.Second-1)/time.Second))))
			writeError(response, http.StatusTooManyRequests, "rate_limited", "Too many requests")
			return
		}
		next.ServeHTTP(response, request)
	})
}

func (handler *Handler) writeServiceError(response http.ResponseWriter, operation string, err error) {
	switch {
	case errors.Is(err, connectors.ErrInvalidInput):
		writeError(response, http.StatusBadRequest, "invalid_request", "Request is invalid")
	case errors.Is(err, connectors.ErrUnauthorized), errors.Is(err, identity.ErrUnauthorized):
		writeError(response, http.StatusUnauthorized, "unauthorized", "Credential is invalid or expired")
	case errors.Is(err, connectors.ErrExpired):
		writeError(response, http.StatusGone, "expired", "Pairing has expired")
	case errors.Is(err, connectors.ErrConflict):
		writeError(response, http.StatusConflict, "invalid_state", "Operation is not valid in the current state")
	default:
		handler.logger.Error("connector request failed", "operation", operation)
		writeError(response, http.StatusInternalServerError, "internal_error", "Request could not be completed")
	}
}

func (handler *Handler) setDeviceCookie(response http.ResponseWriter, result connectors.ConfirmPairingResult) {
	handler.writeDeviceCookie(response, result.DeviceCredential, result.DeviceCredentialExpiresAt)
}

func (handler *Handler) writeDeviceCookie(response http.ResponseWriter, credential string, expiresAt time.Time) {
	http.SetCookie(response, &http.Cookie{
		Name: handler.cookieName, Value: credential, Path: handler.cookiePath,
		Expires: expiresAt, MaxAge: max(1, int(expiresAt.Sub(handler.now()).Seconds())),
		HttpOnly: true, Secure: handler.cookieSecure, SameSite: http.SameSiteStrictMode,
	})
}

// deviceRequest authenticates a device the way ticket issuance does: an account principal,
// the device ID from the body, and the current device cookie, all three together.
func (handler *Handler) deviceRequest(response http.ResponseWriter, request *http.Request, operation string) (principal identity.AccessPrincipal, deviceID, credential string, ok bool) {
	principal, ok = handler.accessPrincipal(response, request)
	if !ok {
		return principal, "", "", false
	}
	var input struct {
		DeviceID string `json:"deviceId"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeDecodeError(response, err)
		return principal, "", "", false
	}
	cookie, err := request.Cookie(handler.cookieName)
	if err != nil || input.DeviceID == "" {
		handler.writeServiceError(response, operation, connectors.ErrUnauthorized)
		return principal, "", "", false
	}
	return principal, input.DeviceID, cookie.Value, true
}

// rotateDeviceCredential issues a replacement the caller must activate. The current cookie
// keeps working until then, so a client that never persists this one is not locked out.
func (handler *Handler) rotateDeviceCredential(response http.ResponseWriter, request *http.Request) {
	principal, deviceID, credential, ok := handler.deviceRequest(response, request, "rotate_device_credential")
	if !ok {
		return
	}
	result, err := handler.connectors.RotateDeviceCredential(request.Context(), principal.Account.ID, principal.SessionID, deviceID, credential)
	if err != nil {
		handler.writeServiceError(response, "rotate_device_credential", err)
		return
	}
	// The pending credential is returned in the body, not as a cookie: writing it as one
	// would replace the live cookie the client still needs until it activates.
	writeJSON(response, http.StatusCreated, rotateDeviceResponse{
		Credential: result.Credential, ActivateBy: result.ActivateBy,
	})
}

// activateDeviceCredential commits a pending rotation and only then writes the new cookie.
func (handler *Handler) activateDeviceCredential(response http.ResponseWriter, request *http.Request) {
	principal, deviceID, credential, ok := handler.deviceRequest(response, request, "activate_device_credential")
	if !ok {
		return
	}
	expiresAt, err := handler.connectors.ActivateDeviceCredential(request.Context(), principal.Account.ID, principal.SessionID, deviceID, credential)
	if err != nil {
		handler.writeServiceError(response, "activate_device_credential", err)
		return
	}
	handler.writeDeviceCookie(response, credential, expiresAt)
	writeJSON(response, http.StatusOK, activateDeviceResponse{CredentialExpiresAt: expiresAt})
}

type challengeResponse struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expiresAt"`
}
type beginPairingResponse struct {
	PairingID           string    `json:"pairingId"`
	PairingSecret       string    `json:"pairingSecret"`
	UserCode            string    `json:"userCode"`
	ServiceID           string    `json:"serviceId"`
	VerificationURI     string    `json:"verificationUri"`
	ExpiresAt           time.Time `json:"expiresAt"`
	PollIntervalSeconds int       `json:"pollIntervalSeconds"`
}
type claimPairingResponse connectors.ClaimPairingResult

func (value claimPairingResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PairingID  string                       `json:"pairingId"`
		DeviceID   string                       `json:"deviceId"`
		ExpiresAt  time.Time                    `json:"expiresAt"`
		Transcript connectors.PairingTranscript `json:"transcript"`
	}{value.PairingID, value.DeviceID, value.ExpiresAt, value.Transcript})
}

type pollPairingResponse connectors.PollPairingResult

func (value pollPairingResponse) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Status                       string                        `json:"status"`
		PairingID                    string                        `json:"pairingId"`
		ServiceID                    string                        `json:"serviceId"`
		ExpiresAt                    time.Time                     `json:"expiresAt"`
		Transcript                   *connectors.PairingTranscript `json:"transcript,omitempty"`
		ConnectorID                  string                        `json:"connectorId,omitempty"`
		ConnectorCredential          string                        `json:"connectorCredential,omitempty"`
		ConnectorCredentialExpiresAt *time.Time                    `json:"connectorCredentialExpiresAt,omitempty"`
		LinkedAt                     *time.Time                    `json:"linkedAt,omitempty"`
	}{value.Status, value.PairingID, value.ServiceID, value.ExpiresAt, value.Transcript, value.ConnectorID, value.ConnectorCredential, value.ConnectorCredentialExpiresAt, value.LinkedAt})
}

type ticketResponse struct {
	Ticket       string    `json:"ticket"`
	ExpiresAt    time.Time `json:"expiresAt"`
	WebSocketURL string    `json:"webSocketUrl"`
}
type rotateDeviceResponse struct {
	Credential string    `json:"credential"`
	ActivateBy time.Time `json:"activateBy"`
}
type activateDeviceResponse struct {
	CredentialExpiresAt time.Time `json:"credentialExpiresAt"`
}
type rotateConnectorResponse struct {
	Credential string    `json:"credential"`
	ActivateBy time.Time `json:"activateBy"`
}
type activateConnectorResponse struct {
	CredentialExpiresAt time.Time `json:"credentialExpiresAt"`
}
type connectorDocument struct {
	ID        string                    `json:"id"`
	Name      string                    `json:"name"`
	Identity  connectors.PublicIdentity `json:"identity"`
	CreatedAt time.Time                 `json:"createdAt"`
}

var (
	errUnsupportedMediaType = errors.New("unsupported media type")
	errTrailingJSON         = errors.New("trailing JSON data")
)

func decodeJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errUnsupportedMediaType
	}
	request.Body = http.MaxBytesReader(response, request.Body, maximumBodySize)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errTrailingJSON
	}
	return nil
}

func writeDecodeError(response http.ResponseWriter, err error) {
	if errors.Is(err, errUnsupportedMediaType) {
		writeError(response, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return
	}
	var maximumBytesError *http.MaxBytesError
	if errors.As(err, &maximumBytesError) {
		writeError(response, http.StatusRequestEntityTooLarge, "request_too_large", "Request body is too large")
		return
	}
	writeError(response, http.StatusBadRequest, "invalid_json", "Request body must be one valid JSON object")
}

func authorizationToken(request *http.Request, scheme string) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return "", connectors.ErrUnauthorized
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], scheme) {
		return "", connectors.ErrUnauthorized
	}
	return parts[1], nil
}

func writeError(response http.ResponseWriter, status int, code, message string) {
	writeJSON(response, status, struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{code, message})
}
func writeJSON(response http.ResponseWriter, status int, document any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(document)
}

type window struct {
	startedAt time.Time
	count     int
}
type fixedWindowLimiter struct {
	mutex    sync.Mutex
	maximum  int
	duration time.Duration
	clients  map[string]window
}

func newFixedWindowLimiter(maximum int, duration time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{maximum: maximum, duration: duration, clients: make(map[string]window)}
}
func (limiter *fixedWindowLimiter) allow(client string, now time.Time) (bool, time.Duration) {
	limiter.mutex.Lock()
	defer limiter.mutex.Unlock()
	entry := limiter.clients[client]
	if entry.startedAt.IsZero() || !now.Before(entry.startedAt.Add(limiter.duration)) {
		limiter.clients[client] = window{startedAt: now, count: 1}
		return true, 0
	}
	if entry.count >= limiter.maximum {
		return false, entry.startedAt.Add(limiter.duration).Sub(now)
	}
	entry.count++
	limiter.clients[client] = entry
	return true, 0
}

func clientAddress(request *http.Request, trustedProxies []*net.IPNet) string {
	peer := remoteHost(request.RemoteAddr)
	peerIP := net.ParseIP(peer)
	if peerIP == nil || !ipInNetworks(peerIP, trustedProxies) {
		return peer
	}
	forwardedFor := request.Header.Values("X-Forwarded-For")
	if len(forwardedFor) != 1 {
		return peer
	}
	addresses := strings.Split(forwardedFor[0], ",")
	for index := len(addresses) - 1; index >= 0; index-- {
		address := strings.TrimSpace(addresses[index])
		ip := net.ParseIP(address)
		if ip == nil {
			return peer
		}
		if !ipInNetworks(ip, trustedProxies) {
			return address
		}
	}
	return peer
}
func remoteHost(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	return address
}
func ipInNetworks(ip net.IP, networks []*net.IPNet) bool {
	for _, network := range networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}
