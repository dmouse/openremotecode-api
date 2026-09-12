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
	"time"

	"opencode-remote/server/internal/identity"
	"opencode-remote/server/internal/platform/httpserver"

	"github.com/gin-gonic/gin"
)

const (
	secureRefreshCookieName      = "__Host-opencode_remote_refresh"
	developmentRefreshCookieName = "opencode_remote_refresh"
	maximumBodySize              = 16 * 1024
)

type AuthenticationService interface {
	Register(context.Context, identity.RegisterInput) (identity.AuthOutcome, error)
	Login(context.Context, identity.LoginInput) (identity.AuthOutcome, error)
	AuthenticateWithGoogle(context.Context, identity.GoogleAuthInput) (identity.Credentials, error)
	VerifyEmail(context.Context, identity.VerifyEmailInput) (identity.AuthOutcome, error)
	ResendVerification(context.Context, string) (identity.VerificationChallenge, error)
	Refresh(context.Context, string) (identity.Credentials, error)
	Logout(context.Context, string) error
	CurrentAccount(context.Context, string) (identity.Account, error)
}

type Config struct {
	AllowedOrigins      []string
	CookieSecure        bool
	Logger              *slog.Logger
	Now                 func() time.Time
	RegistrationEnabled bool
	TrustedProxies      []*net.IPNet
}

type Handler struct {
	service             AuthenticationService
	allowedOrigins      map[string]struct{}
	trustedProxies      []*net.IPNet
	cookieSecure        bool
	cookieName          string
	cookiePath          string
	registrationEnabled bool
	logger              *slog.Logger
	now                 func() time.Time
	registerLimiter     *fixedWindowLimiter
	loginLimiter        *fixedWindowLimiter
	googleLimiter       *fixedWindowLimiter
	refreshLimiter      *fixedWindowLimiter
	verifyEmailLimiter  *fixedWindowLimiter
	resendLimiter       *fixedWindowLimiter
}

func NewHandler(service AuthenticationService, config Config) *Handler {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	handler := &Handler{
		service:             service,
		allowedOrigins:      make(map[string]struct{}, len(config.AllowedOrigins)),
		trustedProxies:      config.TrustedProxies,
		cookieSecure:        config.CookieSecure,
		registrationEnabled: config.RegistrationEnabled,
		logger:              config.Logger,
		now:                 config.Now,
		registerLimiter: newFixedWindowLimiter(rateLimit{
			maximum: 5,
			window:  10 * time.Minute,
		}),
		loginLimiter: newFixedWindowLimiter(rateLimit{
			maximum: 10,
			window:  time.Minute,
		}),
		// Sized like login rather than register. The route both signs in and creates
		// accounts, but every request carries an assertion Google already charged the
		// caller to obtain, so the account-creation half needs no tighter bound than
		// the sign-in half. It still needs its own limiter: sharing login's would let
		// either route exhaust the other's budget.
		googleLimiter: newFixedWindowLimiter(rateLimit{
			maximum: 10,
			window:  time.Minute,
		}),
		refreshLimiter: newFixedWindowLimiter(rateLimit{
			maximum: 30,
			window:  time.Minute,
		}),
		// Layered on top of the service-side attempt cap, which is per challenge;
		// this one bounds guessing across challenges from one address.
		verifyEmailLimiter: newFixedWindowLimiter(rateLimit{
			maximum: 10,
			window:  10 * time.Minute,
		}),
		// Layered on top of the service-side resend cooldown, which is per challenge.
		resendLimiter: newFixedWindowLimiter(rateLimit{
			maximum: 3,
			window:  10 * time.Minute,
		}),
	}
	if config.CookieSecure {
		handler.cookieName = secureRefreshCookieName
		handler.cookiePath = "/"
	} else {
		handler.cookieName = developmentRefreshCookieName
		handler.cookiePath = "/v1/auth"
	}
	for _, origin := range config.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			handler.allowedOrigins[origin] = struct{}{}
		}
	}

	return handler
}

func (handler *Handler) RegisterRoutes(router gin.IRouter) {
	auth := router.Group("/v1/auth")
	auth.POST("/register", handler.protected(handler.registerLimiter, handler.register))
	auth.POST("/login", handler.protected(handler.loginLimiter, handler.login))
	auth.POST("/google", handler.protected(handler.googleLimiter, handler.google))
	auth.POST("/verify-email", handler.protected(handler.verifyEmailLimiter, handler.verifyEmail))
	auth.POST("/resend-verification", handler.protected(handler.resendLimiter, handler.resendVerification))
	auth.POST("/refresh", handler.protected(handler.refreshLimiter, handler.refresh))
	auth.POST("/logout", handler.protected(nil, handler.logout))
	router.GET("/v1/account", gin.WrapF(handler.currentAccount))
	router.HEAD("/v1/account", gin.WrapF(handler.currentAccount))
}

// protected attaches the origin gate and (optional) rate limiter for an auth route,
// keeping the route table readable as "limiter, handler".
func (handler *Handler) protected(limiter *fixedWindowLimiter, next http.HandlerFunc) gin.HandlerFunc {
	return httpserver.WrapHandler(handler.protect(limiter, next))
}

func (handler *Handler) protect(limiter *fixedWindowLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		origin := request.Header.Get("Origin")
		if origin != "" {
			response.Header().Add("Vary", "Origin")
			if _, allowed := handler.allowedOrigins[origin]; !allowed {
				writeError(response, http.StatusForbidden, "origin_not_allowed", "Request origin is not allowed")
				return
			}
		} else if request.Header.Get("Sec-Fetch-Site") == "cross-site" {
			writeError(response, http.StatusForbidden, "origin_not_allowed", "Request origin is not allowed")
			return
		}
		if limiter != nil {
			allowed, retryAfter := limiter.allow(
				clientAddress(request, handler.trustedProxies),
				handler.now(),
			)
			if !allowed {
				seconds := max(1, int((retryAfter+time.Second-1)/time.Second))
				response.Header().Set("Retry-After", strconv.Itoa(seconds))
				writeError(response, http.StatusTooManyRequests, "rate_limited", "Too many requests")
				return
			}
		}
		next.ServeHTTP(response, request)
	})
}

func (handler *Handler) register(response http.ResponseWriter, request *http.Request) {
	if !handler.registrationEnabled {
		writeError(response, http.StatusServiceUnavailable, "registration_unavailable", "Registration is unavailable")
		return
	}
	var input struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		ClientName string `json:"clientName"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeDecodeError(response, err)
		return
	}
	outcome, err := handler.service.Register(request.Context(), identity.RegisterInput(input))
	if err != nil {
		handler.writeServiceError(response, "register", err)
		return
	}
	// Registration always answers with a verification challenge and never a cookie —
	// identically for a new address and one that is already registered. Anything that
	// distinguished the two here would undo the decoy the service returns.
	if outcome.Verification == nil {
		handler.writeServiceError(response, "register", errUnexpectedOutcome)
		return
	}
	writeJSON(response, http.StatusCreated, verificationChallengeResponseFrom(*outcome.Verification))
}

func (handler *Handler) login(response http.ResponseWriter, request *http.Request) {
	var input struct {
		Email      string `json:"email"`
		Password   string `json:"password"`
		ClientName string `json:"clientName"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeDecodeError(response, err)
		return
	}
	outcome, err := handler.service.Login(request.Context(), identity.LoginInput(input))
	if err != nil {
		handler.writeServiceError(response, "login", err)
		return
	}
	handler.writeOutcome(response, "login", http.StatusOK, outcome)
}

// google exchanges a Google ID token for a session. It always answers with
// credentials or an error, never a verification challenge: Google has already
// proved the address, so no account this route touches is left pending.
//
// It is deliberately not gated on RegistrationEnabled. That switch exists to stop
// unsolicited account creation through the mailed-code flow, and it is the same
// switch an operator would reach for here — but the two are separable, and
// conflating them would silently disable sign-in for accounts that already exist.
// An operator who wants Google sign-in off unsets the audiences.
func (handler *Handler) google(response http.ResponseWriter, request *http.Request) {
	var input struct {
		IDToken    string `json:"idToken"`
		ClientName string `json:"clientName"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeDecodeError(response, err)
		return
	}
	credentials, err := handler.service.AuthenticateWithGoogle(request.Context(), identity.GoogleAuthInput{
		IDToken:    input.IDToken,
		ClientName: input.ClientName,
	})
	if err != nil {
		handler.writeServiceError(response, "google", err)
		return
	}
	handler.setRefreshCookie(response, credentials)
	writeJSON(response, http.StatusOK, credentialsResponseFrom(credentials))
}

func (handler *Handler) verifyEmail(response http.ResponseWriter, request *http.Request) {
	var input struct {
		VerificationTicket string `json:"verificationTicket"`
		Code               string `json:"code"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeDecodeError(response, err)
		return
	}
	outcome, err := handler.service.VerifyEmail(request.Context(), identity.VerifyEmailInput{
		Ticket: input.VerificationTicket,
		Code:   input.Code,
	})
	if err != nil {
		handler.writeServiceError(response, "verify_email", err)
		return
	}
	handler.writeOutcome(response, "verify_email", http.StatusOK, outcome)
}

func (handler *Handler) resendVerification(response http.ResponseWriter, request *http.Request) {
	var input struct {
		VerificationTicket string `json:"verificationTicket"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeDecodeError(response, err)
		return
	}
	challenge, err := handler.service.ResendVerification(request.Context(), input.VerificationTicket)
	if err != nil {
		handler.writeServiceError(response, "resend_verification", err)
		return
	}
	writeJSON(response, http.StatusOK, verificationChallengeResponseFrom(challenge))
}

// writeOutcome sets a refresh cookie only for a real session. A pending account
// gets a verification challenge and no cookie, because it has nothing to refresh.
func (handler *Handler) writeOutcome(
	response http.ResponseWriter,
	operation string,
	status int,
	outcome identity.AuthOutcome,
) {
	switch {
	case outcome.Credentials != nil:
		handler.setRefreshCookie(response, *outcome.Credentials)
		writeJSON(response, status, credentialsResponseFrom(*outcome.Credentials))
	case outcome.Verification != nil:
		writeJSON(response, status, verificationChallengeResponseFrom(*outcome.Verification))
	default:
		handler.writeServiceError(response, operation, errUnexpectedOutcome)
	}
}

func (handler *Handler) refresh(response http.ResponseWriter, request *http.Request) {
	cookie, err := request.Cookie(handler.cookieName)
	if err != nil {
		handler.writeServiceError(response, "refresh", identity.ErrInvalidRefresh)
		return
	}
	credentials, err := handler.service.Refresh(request.Context(), cookie.Value)
	if err != nil {
		if errors.Is(err, identity.ErrInvalidRefresh) {
			handler.clearRefreshCookie(response)
		}
		handler.writeServiceError(response, "refresh", err)
		return
	}
	handler.setRefreshCookie(response, credentials)
	writeJSON(response, http.StatusOK, credentialsResponseFrom(credentials))
}

func (handler *Handler) logout(response http.ResponseWriter, request *http.Request) {
	if cookie, err := request.Cookie(handler.cookieName); err == nil {
		if err := handler.service.Logout(request.Context(), cookie.Value); err != nil {
			handler.writeServiceError(response, "logout", err)
			return
		}
	}
	handler.clearRefreshCookie(response)
	response.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) currentAccount(response http.ResponseWriter, request *http.Request) {
	accessToken, err := bearerToken(request)
	if err != nil {
		response.Header().Set("WWW-Authenticate", "Bearer")
		handler.writeServiceError(response, "current_account", identity.ErrUnauthorized)
		return
	}
	account, err := handler.service.CurrentAccount(request.Context(), accessToken)
	if err != nil {
		if errors.Is(err, identity.ErrUnauthorized) {
			response.Header().Set("WWW-Authenticate", "Bearer")
		}
		handler.writeServiceError(response, "current_account", err)
		return
	}
	writeJSON(response, http.StatusOK, accountResponse{User: accountFrom(account)})
}

func (handler *Handler) writeServiceError(
	response http.ResponseWriter,
	operation string,
	err error,
) {
	switch {
	case errors.Is(err, identity.ErrInvalidInput):
		writeError(response, http.StatusBadRequest, "invalid_request", "Request is invalid")
	case errors.Is(err, identity.ErrInvalidVerificationCode):
		writeError(response, http.StatusBadRequest, "invalid_verification_code", "Verification code is invalid or expired")
	case errors.Is(err, identity.ErrVerificationThrottled):
		writeError(response, http.StatusTooManyRequests, "rate_limited", "Too many requests")
	case errors.Is(err, identity.ErrInvalidCredentials):
		writeError(response, http.StatusUnauthorized, "invalid_credentials", "Email or password is invalid")
	case errors.Is(err, identity.ErrInvalidGoogleToken):
		writeError(response, http.StatusUnauthorized, "invalid_google_token", "Google sign-in could not be verified")
	// The one federated error a client can act on: it names the recovery path rather
	// than failing blank. It reveals that an account holds this address, which the
	// caller has just proved to Google that they control, so it is not an oracle.
	case errors.Is(err, identity.ErrAccountLinkRequired):
		writeError(response, http.StatusConflict, "account_link_required", "An account already uses this address. Sign in with your password to link Google.")
	case errors.Is(err, identity.ErrIdentityAlreadyLinked):
		writeError(response, http.StatusConflict, "account_identity_conflict", "This account is already linked to a different Google account")
	case errors.Is(err, identity.ErrGoogleUnavailable):
		writeError(response, http.StatusServiceUnavailable, "google_signin_unavailable", "Google sign-in is unavailable")
	case errors.Is(err, identity.ErrInvalidRefresh):
		writeError(response, http.StatusUnauthorized, "invalid_refresh", "Refresh credential is invalid or expired")
	case errors.Is(err, identity.ErrUnauthorized):
		writeError(response, http.StatusUnauthorized, "unauthorized", "Access credential is invalid or expired")
	default:
		handler.logger.Error("authentication request failed", "operation", operation)
		writeError(response, http.StatusInternalServerError, "internal_error", "Request could not be completed")
	}
}

func (handler *Handler) setRefreshCookie(
	response http.ResponseWriter,
	credentials identity.Credentials,
) {
	maxAge := max(1, int(credentials.RefreshTokenExpiresAt.Sub(handler.now()).Seconds()))
	http.SetCookie(response, &http.Cookie{
		Name:     handler.cookieName,
		Value:    credentials.RefreshToken,
		Path:     handler.cookiePath,
		Expires:  credentials.RefreshTokenExpiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   handler.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (handler *Handler) clearRefreshCookie(response http.ResponseWriter) {
	http.SetCookie(response, &http.Cookie{
		Name:     handler.cookieName,
		Value:    "",
		Path:     handler.cookiePath,
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   handler.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

type credentialsResponse struct {
	AccessToken          string          `json:"accessToken"`
	AccessTokenExpiresAt time.Time       `json:"accessTokenExpiresAt"`
	User                 accountDocument `json:"user"`
}

type accountResponse struct {
	User accountDocument `json:"user"`
}

// verificationChallengeResponse carries no access token by design: the ticket is
// scoped to verify-email and resend-verification and authenticates nothing else.
type verificationChallengeResponse struct {
	User                        accountDocument `json:"user"`
	VerificationTicket          string          `json:"verificationTicket"`
	VerificationTicketExpiresAt time.Time       `json:"verificationTicketExpiresAt"`
}

type accountDocument struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Status        string    `json:"status"`
	EmailVerified bool      `json:"emailVerified"`
	EmailBounced  bool      `json:"emailBounced"`
	CreatedAt     time.Time `json:"createdAt"`
}

func credentialsResponseFrom(credentials identity.Credentials) credentialsResponse {
	return credentialsResponse{
		AccessToken:          credentials.AccessToken,
		AccessTokenExpiresAt: credentials.AccessTokenExpiresAt,
		User:                 accountFrom(credentials.Account),
	}
}

func verificationChallengeResponseFrom(
	challenge identity.VerificationChallenge,
) verificationChallengeResponse {
	return verificationChallengeResponse{
		User:                        accountFrom(challenge.Account),
		VerificationTicket:          challenge.Ticket,
		VerificationTicketExpiresAt: challenge.TicketExpiresAt,
	}
}

func accountFrom(account identity.Account) accountDocument {
	return accountDocument{
		ID:            account.ID,
		Email:         account.Email,
		Status:        account.Status,
		EmailVerified: account.EmailVerifiedAt != nil,
		EmailBounced:  account.EmailBouncedAt != nil,
		CreatedAt:     account.CreatedAt,
	}
}

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

var (
	errUnsupportedMediaType = errors.New("unsupported media type")
	errTrailingJSON         = errors.New("trailing JSON data")
	// errUnexpectedOutcome guards the AuthOutcome contract at the transport edge: a
	// result carrying neither credentials nor a challenge is a service bug, and must
	// become a 500 rather than an empty 200 the client would misread.
	errUnexpectedOutcome = errors.New("authentication outcome is empty")
)

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

func bearerToken(request *http.Request) (string, error) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return "", identity.ErrUnauthorized
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", identity.ErrUnauthorized
	}
	return parts[1], nil
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

func writeError(response http.ResponseWriter, status int, code, message string) {
	writeJSON(response, status, struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message})
}

func writeJSON(response http.ResponseWriter, status int, document any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(document)
}
