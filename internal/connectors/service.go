package connectors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	hpkeSuiteID                        = "HPKE-Auth-P256-HKDF-SHA256-AES-256-GCM"
	defaultChallengeLifetime           = 2 * time.Minute
	defaultPairingLifetime             = 10 * time.Minute
	defaultDeviceCredentialLifetime    = 365 * 24 * time.Hour
	defaultConnectorCredentialLifetime = 90 * 24 * time.Hour
	defaultTicketLifetime              = 30 * time.Second
	// A rotation the plugin never activates lapses this soon after it is issued.
	defaultCredentialActivationWindow = 15 * time.Minute
	defaultPollInterval               = 2 * time.Second
	defaultAuthorizationLease         = 5 * time.Minute
	deviceCredentialSeedLength        = 32
	// Incorrect pairing codes are capped per account and across the service. The user code
	// is 40 bits and lives ten minutes, so guessing is only a threat at volume: per-account
	// caps make volume cost verified accounts rather than IP addresses, and the global cap
	// bounds the total guessing rate however many accounts an attacker holds.
	defaultAccountClaimFailureLimit  = 10
	defaultAccountClaimFailureWindow = time.Hour
	defaultGlobalClaimFailureLimit   = 120
	defaultGlobalClaimFailureWindow  = time.Minute
)

type ServiceOptions struct {
	Now            func() time.Time
	Random         io.Reader
	PairingCodeKey []byte
	// Derives device credentials. Kept separate from PairingCodeKey so that rotating the
	// user-code key does not invalidate every paired device. Seeded from PairingCodeKey
	// when unset, which keeps an existing deployment's devices valid.
	DeviceCredentialKey         []byte
	ServiceID                   string
	VerificationURI             string
	ChallengeLifetime           time.Duration
	PairingLifetime             time.Duration
	DeviceCredentialLifetime    time.Duration
	ConnectorCredentialLifetime time.Duration
	CredentialActivationWindow  time.Duration
	TicketLifetime              time.Duration
	PollInterval                time.Duration
	AuthorizeAccount            func(context.Context, string) error
	AuthorizeSession            func(context.Context, string, string) error
	// OnRevoked is told about each committed connector or device revocation, so live relay
	// sockets can be closed at once rather than at their next periodic check.
	OnRevoked func(Revocation)
}

type Service struct {
	repository                  Repository
	now                         func() time.Time
	random                      io.Reader
	pairingCodeKey              []byte
	deviceCredentialKey         []byte
	serviceID                   string
	verificationURI             string
	challengeLifetime           time.Duration
	pairingLifetime             time.Duration
	deviceCredentialLifetime    time.Duration
	connectorCredentialLifetime time.Duration
	credentialActivationWindow  time.Duration
	ticketLifetime              time.Duration
	pollInterval                time.Duration
	authorizeAccount            func(context.Context, string) error
	authorizeSession            func(context.Context, string, string) error
	accountClaimFailureLimit    int
	accountClaimFailureWindow   time.Duration
	globalClaimFailureLimit     int
	globalClaimFailureWindow    time.Duration
	onRevoked                   func(Revocation)
}

func NewService(repository Repository, options ServiceOptions) (*Service, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = defaultRandom()
	}
	if len(options.PairingCodeKey) < 32 {
		return nil, errors.New("pairing code key must contain at least 32 bytes")
	}
	if len(options.DeviceCredentialKey) == 0 {
		options.DeviceCredentialKey = options.PairingCodeKey
	}
	if len(options.DeviceCredentialKey) < 32 {
		return nil, errors.New("device credential key must contain at least 32 bytes")
	}
	if strings.TrimSpace(options.ServiceID) == "" || len(options.ServiceID) > 128 {
		return nil, errors.New("service ID is invalid")
	}
	if strings.TrimSpace(options.VerificationURI) == "" {
		return nil, errors.New("verification URI is required")
	}
	if options.AuthorizeAccount == nil {
		return nil, errors.New("account authorizer is required")
	}
	if options.AuthorizeSession == nil {
		return nil, errors.New("session authorizer is required")
	}
	if options.ChallengeLifetime <= 0 {
		options.ChallengeLifetime = defaultChallengeLifetime
	}
	if options.PairingLifetime <= 0 {
		options.PairingLifetime = defaultPairingLifetime
	}
	if options.DeviceCredentialLifetime <= 0 {
		options.DeviceCredentialLifetime = defaultDeviceCredentialLifetime
	}
	if options.ConnectorCredentialLifetime <= 0 {
		options.ConnectorCredentialLifetime = defaultConnectorCredentialLifetime
	}
	if options.CredentialActivationWindow <= 0 {
		options.CredentialActivationWindow = defaultCredentialActivationWindow
	}
	if options.TicketLifetime <= 0 {
		options.TicketLifetime = defaultTicketLifetime
	}
	if options.PollInterval <= 0 {
		options.PollInterval = defaultPollInterval
	}
	if options.OnRevoked == nil {
		options.OnRevoked = func(Revocation) {}
	}
	return &Service{
		repository:                  repository,
		now:                         options.Now,
		random:                      options.Random,
		pairingCodeKey:              append([]byte(nil), options.PairingCodeKey...),
		deviceCredentialKey:         append([]byte(nil), options.DeviceCredentialKey...),
		serviceID:                   options.ServiceID,
		verificationURI:             options.VerificationURI,
		challengeLifetime:           options.ChallengeLifetime,
		pairingLifetime:             options.PairingLifetime,
		deviceCredentialLifetime:    options.DeviceCredentialLifetime,
		connectorCredentialLifetime: options.ConnectorCredentialLifetime,
		credentialActivationWindow:  options.CredentialActivationWindow,
		ticketLifetime:              options.TicketLifetime,
		pollInterval:                options.PollInterval,
		authorizeAccount:            options.AuthorizeAccount,
		authorizeSession:            options.AuthorizeSession,
		accountClaimFailureLimit:    defaultAccountClaimFailureLimit,
		accountClaimFailureWindow:   defaultAccountClaimFailureWindow,
		globalClaimFailureLimit:     defaultGlobalClaimFailureLimit,
		globalClaimFailureWindow:    defaultGlobalClaimFailureWindow,
		onRevoked:                   options.OnRevoked,
	}, nil
}

func (service *Service) IssueChallenge(ctx context.Context, purpose string, userID *string) (ChallengeResult, error) {
	if purpose != ChallengePurposeConnector && purpose != ChallengePurposeDevice {
		return ChallengeResult{}, ErrInvalidInput
	}
	if purpose == ChallengePurposeDevice && (userID == nil || *userID == "") {
		return ChallengeResult{}, ErrUnauthorized
	}
	challenge, err := randomBase64(service.random, 32)
	if err != nil {
		return ChallengeResult{}, err
	}
	now := service.now().UTC()
	err = service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		return store.CreateChallenge(ctx, Challenge{
			Hash: hashSecret(challenge), Purpose: purpose, UserID: userID,
			CreatedAt: now, ExpiresAt: now.Add(service.challengeLifetime),
		})
	})
	if err != nil {
		return ChallengeResult{}, err
	}
	return ChallengeResult{Challenge: challenge, ExpiresAt: now.Add(service.challengeLifetime)}, nil
}

func (service *Service) BeginPairing(ctx context.Context, input BeginPairingInput) (BeginPairingResult, error) {
	name, err := normalizeName(input.Name)
	if err != nil || !validIdentity(input.Identity) || !verifyIdentityProof(input.Identity, input.Proof) {
		return BeginPairingResult{}, ErrInvalidInput
	}
	pairingID, err := issueIdentifier(service.random, "par_")
	if err != nil {
		return BeginPairingResult{}, err
	}
	pairingSecret, err := issueToken(service.random, "orp_")
	if err != nil {
		return BeginPairingResult{}, err
	}
	userCode, err := issueUserCode(service.random)
	if err != nil {
		return BeginPairingResult{}, err
	}
	now := service.now().UTC()
	expiresAt := now.Add(service.pairingLifetime)
	connectorCredential := deriveConnectorCredential(pairingSecret)
	pairing := Pairing{
		ID: pairingID, SecretHash: hashSecret(pairingSecret), UserCodeHash: service.hashUserCode(userCode),
		ConnectorName: name, ConnectorIdentity: input.Identity, ConnectorCredentialHash: hashSecret(connectorCredential), State: PairingStatePending,
		CreatedAt: now, ExpiresAt: expiresAt,
	}
	err = service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		challenge, err := store.ChallengeForUpdate(ctx, hashSecret(input.Proof.Challenge))
		if err != nil {
			return err
		}
		if challenge.Purpose != ChallengePurposeConnector || challenge.UserID != nil || challenge.UsedAt != nil || !challenge.ExpiresAt.After(now) {
			return ErrUnauthorized
		}
		challenge.UsedAt = &now
		if err := store.SaveChallenge(ctx, challenge); err != nil {
			return err
		}
		if err := store.ExpirePairingsForKey(ctx, input.Identity.KeyID, now); err != nil {
			return err
		}
		return store.CreatePairing(ctx, pairing)
	})
	if err != nil {
		return BeginPairingResult{}, normalizeAuthorizationError(err)
	}
	return BeginPairingResult{
		PairingID: pairingID, PairingSecret: pairingSecret, UserCode: userCode,
		ServiceID: service.serviceID, VerificationURI: service.verificationURI,
		ExpiresAt: expiresAt, PollInterval: service.pollInterval,
	}, nil
}

func (service *Service) ClaimPairing(ctx context.Context, input ClaimPairingInput) (ClaimPairingResult, error) {
	name, err := normalizeName(input.DeviceName)
	if err != nil || input.UserID == "" || !validIdentity(input.Identity) || !verifyIdentityProof(input.Identity, input.Proof) {
		return ClaimPairingResult{}, ErrInvalidInput
	}
	code := normalizeUserCode(input.UserCode)
	if len(code) != 8 {
		return ClaimPairingResult{}, ErrInvalidInput
	}
	now := service.now().UTC()
	var result ClaimPairingResult
	expired, wrongCode := false, false
	err = service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		if err := service.authorizeAccount(ctx, input.UserID); err != nil {
			return ErrUnauthorized
		}
		challenge, err := store.ChallengeForUpdate(ctx, hashSecret(input.Proof.Challenge))
		if err != nil {
			return err
		}
		if challenge.Purpose != ChallengePurposeDevice || challenge.UserID == nil || *challenge.UserID != input.UserID || challenge.UsedAt != nil || !challenge.ExpiresAt.After(now) {
			return ErrUnauthorized
		}
		if err := service.checkClaimFailures(ctx, store, input.UserID, now); err != nil {
			return err
		}
		// Every guess spends its challenge, so each costs a fresh signed challenge. This and
		// the failure record below must commit even when the code is wrong, which is why a
		// wrong code returns nil here and is reported after the transaction.
		challenge.UsedAt = &now
		if err := store.SaveChallenge(ctx, challenge); err != nil {
			return err
		}
		pairing, err := store.PairingByCodeForUpdate(ctx, service.hashUserCode(code))
		if errors.Is(err, ErrNotFound) {
			wrongCode = true
			return store.RecordClaimFailure(ctx, input.UserID, now, now.Add(-service.accountClaimFailureWindow))
		}
		if err != nil {
			return err
		}
		if !pairing.ExpiresAt.After(now) {
			pairing.State = PairingStateExpired
			if err := store.SavePairing(ctx, pairing); err != nil {
				return err
			}
			expired = true
			return nil
		}
		if pairing.State != PairingStatePending {
			return ErrConflict
		}

		device, err := store.DeviceByKeyIDForUpdate(ctx, input.Identity.KeyID)
		if errors.Is(err, ErrNotFound) {
			deviceID, issueErr := issueIdentifier(service.random, "dev_")
			if issueErr != nil {
				return issueErr
			}
			device = Device{ID: deviceID, UserID: input.UserID, Name: name, Identity: input.Identity, CreatedAt: now}
			if err := store.CreateDevice(ctx, device); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if device.UserID != input.UserID || device.RevokedAt != nil || device.Identity.PublicKey != input.Identity.PublicKey {
			return ErrConflict
		}

		pairing.State = PairingStateVerification
		pairing.UserID = stringPointer(input.UserID)
		pairing.DeviceID = stringPointer(device.ID)
		if err := store.SavePairing(ctx, pairing); err != nil {
			return err
		}
		if err := store.AppendAuditEvent(ctx, AuditEvent{
			UserID: &input.UserID, DeviceID: &device.ID, PairingID: &pairing.ID,
			EventType: "pairing.reviewed", OccurredAt: now,
		}); err != nil {
			return err
		}
		result = ClaimPairingResult{
			PairingID: pairing.ID, DeviceID: device.ID, ExpiresAt: pairing.ExpiresAt,
			Transcript: service.transcript(pairing, input.Identity),
		}
		return nil
	})
	if err != nil {
		return ClaimPairingResult{}, normalizeAuthorizationError(err)
	}
	if wrongCode {
		return ClaimPairingResult{}, ErrInvalidCode
	}
	if expired {
		return ClaimPairingResult{}, ErrExpired
	}
	return result, nil
}

// checkClaimFailures refuses a claim while the account, or the service as a whole, is over
// its budget of incorrect codes. It runs before the code is looked up, so a refused claim
// learns nothing about whether its code was right.
func (service *Service) checkClaimFailures(ctx context.Context, store TransactionStore, userID string, now time.Time) error {
	counts, err := store.ClaimFailuresForUpdate(ctx, userID,
		now.Add(-service.accountClaimFailureWindow), now.Add(-service.globalClaimFailureWindow))
	if err != nil {
		return err
	}
	if counts.Account >= service.accountClaimFailureLimit {
		return AttemptsExceededError{RetryAfter: max(time.Second, counts.AccountOldest.Add(service.accountClaimFailureWindow).Sub(now))}
	}
	if counts.Global >= service.globalClaimFailureLimit {
		return AttemptsExceededError{RetryAfter: service.globalClaimFailureWindow}
	}
	return nil
}

func (service *Service) ConfirmPairing(ctx context.Context, userID, pairingID, deviceID string) (ConfirmPairingResult, error) {
	if userID == "" || pairingID == "" || deviceID == "" {
		return ConfirmPairingResult{}, ErrInvalidInput
	}
	now := service.now().UTC()
	var result ConfirmPairingResult
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		if err := service.authorizeAccount(ctx, userID); err != nil {
			return err
		}
		pairing, err := store.PairingByIDForUpdate(ctx, pairingID)
		if err != nil {
			return err
		}
		if !pairing.ExpiresAt.After(now) {
			return ErrExpired
		}
		if pairing.UserID == nil || *pairing.UserID != userID || pairing.DeviceID == nil || *pairing.DeviceID != deviceID {
			return ErrConflict
		}
		device, err := store.DeviceByIDForUpdate(ctx, deviceID)
		if err != nil {
			return err
		}
		if device.UserID != userID || device.RevokedAt != nil {
			return ErrUnauthorized
		}
		if pairing.State == PairingStateCompleted && pairing.ConnectorID != nil && device.CredentialExpiresAt != nil {
			// A retry of a completed confirmation re-derives the credential this pairing
			// issued, so a lost response is recoverable and concurrent confirmations agree.
			// If the device has since rotated or re-paired, the stored hash no longer matches
			// and the old value is never handed out again.
			if len(pairing.ConnectorCredentialHash) != sha256.Size || len(pairing.DeviceCredentialSeed) != deviceCredentialSeedLength {
				return ErrConflict
			}
			deviceCredential := service.deriveDeviceCredential(pairing.DeviceCredentialSeed)
			if !hmac.Equal(hashSecret(deviceCredential), device.CredentialHash) {
				return ErrConflict
			}
			connector, err := store.ConnectorByIDForUpdate(ctx, *pairing.ConnectorID)
			if err != nil {
				return err
			}
			if connector.UserID != userID || connector.RevokedAt != nil ||
				!hmac.Equal(connector.CredentialHash, pairing.ConnectorCredentialHash) {
				return ErrConflict
			}
			result = ConfirmPairingResult{
				DeviceID: device.ID, ConnectorID: *pairing.ConnectorID, DeviceCredential: deviceCredential,
				DeviceCredentialExpiresAt: *device.CredentialExpiresAt,
			}
			return nil
		}
		if pairing.State == PairingStateExpired {
			// Rejected in OpenCode or cancelled: report it as over, not as still waiting.
			return ErrExpired
		}
		// ConnectorReviewedAt is set only by an explicit approval in OpenCode (ApprovePairing),
		// so an account that learned the user code cannot complete the pairing on its own.
		if pairing.State != PairingStateVerification || pairing.ConnectorReviewedAt == nil || len(pairing.ConnectorCredentialHash) != sha256.Size {
			return ErrConflict
		}

		connector, err := store.ConnectorByKeyIDForUpdate(ctx, pairing.ConnectorIdentity.KeyID)
		if errors.Is(err, ErrNotFound) {
			connectorID, issueErr := issueIdentifier(service.random, "con_")
			if issueErr != nil {
				return issueErr
			}
			connector = Connector{
				ID: connectorID, UserID: userID, Name: pairing.ConnectorName,
				Identity: pairing.ConnectorIdentity, CreatedAt: now,
			}
			if err := store.CreateConnector(ctx, connector); err != nil {
				return err
			}
		} else if err != nil {
			return err
		} else if connector.UserID != userID || connector.RevokedAt != nil || connector.Identity.PublicKey != pairing.ConnectorIdentity.PublicKey {
			return ErrConflict
		}

		// Every confirmation issues a fresh credential from its own random seed. Deriving it
		// from anything stable (the device key ID, formerly) would hand a re-paired device its
		// old credential back, undoing any rotation, and would let the server key alone
		// recompute every device's credential.
		seed := make([]byte, deviceCredentialSeedLength)
		if _, err := io.ReadFull(service.random, seed); err != nil {
			return err
		}
		pairing.DeviceCredentialSeed = seed
		deviceCredential := service.deriveDeviceCredential(seed)
		deviceCredentialExpiresAt := now.Add(service.deviceCredentialLifetime)
		device.CredentialHash = hashSecret(deviceCredential)
		device.CredentialExpiresAt = &deviceCredentialExpiresAt
		if device.ActivatedAt == nil {
			device.ActivatedAt = &now
		}
		if err := store.SaveDevice(ctx, device); err != nil {
			return err
		}
		if err := store.UpsertTrust(ctx, Trust{UserID: userID, DeviceID: device.ID, ConnectorID: connector.ID, CreatedAt: now}); err != nil {
			return err
		}
		connectorCredentialExpiresAt := now.Add(service.connectorCredentialLifetime)
		connector.CredentialHash = pairing.ConnectorCredentialHash
		connector.CredentialExpiresAt = &connectorCredentialExpiresAt
		if err := store.SaveConnector(ctx, connector); err != nil {
			return err
		}
		pairing.State = PairingStateCompleted
		pairing.ConnectorID = &connector.ID
		pairing.ConfirmedAt = &now
		pairing.CompletedAt = &now
		if err := store.SavePairing(ctx, pairing); err != nil {
			return err
		}
		if err := store.AppendAuditEvent(ctx, AuditEvent{
			UserID: &userID, DeviceID: &device.ID, ConnectorID: &connector.ID, PairingID: &pairing.ID,
			EventType: "pairing.completed", OccurredAt: now,
		}); err != nil {
			return err
		}
		result = ConfirmPairingResult{
			DeviceID: device.ID, ConnectorID: connector.ID, DeviceCredential: deviceCredential,
			DeviceCredentialExpiresAt: deviceCredentialExpiresAt,
		}
		return nil
	})
	if err != nil {
		return ConfirmPairingResult{}, normalizeAuthorizationError(err)
	}
	return result, nil
}

func (service *Service) PollPairing(ctx context.Context, pairingSecret string) (PollPairingResult, error) {
	if !validToken(pairingSecret, "orp_") {
		return PollPairingResult{}, ErrUnauthorized
	}
	now := service.now().UTC()
	var result PollPairingResult
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		pairing, err := store.PairingBySecretForUpdate(ctx, hashSecret(pairingSecret))
		if err != nil {
			return err
		}
		result = PollPairingResult{Status: pairing.State, PairingID: pairing.ID, ServiceID: service.serviceID, ExpiresAt: pairing.ExpiresAt}
		if !pairing.ExpiresAt.After(now) {
			if pairing.State != PairingStateCompleted {
				pairing.State = PairingStateExpired
				if err := store.SavePairing(ctx, pairing); err != nil {
					return err
				}
				result.Status = PairingStateExpired
				return nil
			}
			return ErrExpired
		}
		if pairing.DeviceID != nil {
			device, err := store.DeviceByIDForUpdate(ctx, *pairing.DeviceID)
			if err != nil {
				return err
			}
			transcript := service.transcript(pairing, device.Identity)
			result.Transcript = &transcript
		}
		if pairing.State == PairingStateVerification {
			// Observing the transcript approves nothing; see ApprovePairing.
			return nil
		}
		if pairing.State == PairingStateCompleted && pairing.ConnectorID != nil {
			connector, err := store.ConnectorByIDForUpdate(ctx, *pairing.ConnectorID)
			if err != nil {
				return err
			}
			if connector.CredentialExpiresAt == nil || connector.RevokedAt != nil {
				return ErrUnauthorized
			}
			credential := deriveConnectorCredential(pairingSecret)
			if !hmac.Equal(hashSecret(credential), connector.CredentialHash) {
				return ErrUnauthorized
			}
			result.ConnectorID = connector.ID
			result.ConnectorCredential = credential
			result.ConnectorCredentialExpiresAt = connector.CredentialExpiresAt
			result.LinkedAt = &connector.CreatedAt
			return nil
		}
		if pairing.State != PairingStateConfirmed {
			return nil
		}
		if pairing.ConnectorID == nil {
			return ErrConflict
		}
		connector, err := store.ConnectorByIDForUpdate(ctx, *pairing.ConnectorID)
		if err != nil {
			return err
		}
		if connector.RevokedAt != nil {
			return ErrUnauthorized
		}
		credential := deriveConnectorCredential(pairingSecret)
		expiresAt := now.Add(service.connectorCredentialLifetime)
		connector.CredentialHash = hashSecret(credential)
		connector.CredentialExpiresAt = &expiresAt
		if err := store.SaveConnector(ctx, connector); err != nil {
			return err
		}
		pairing.State = PairingStateCompleted
		pairing.CompletedAt = &now
		if err := store.SavePairing(ctx, pairing); err != nil {
			return err
		}
		if err := store.AppendAuditEvent(ctx, AuditEvent{
			UserID: pairing.UserID, DeviceID: pairing.DeviceID, ConnectorID: pairing.ConnectorID, PairingID: &pairing.ID,
			EventType: "pairing.completed", OccurredAt: now,
		}); err != nil {
			return err
		}
		result.Status = PairingStateCompleted
		result.ConnectorID = connector.ID
		result.ConnectorCredential = credential
		result.ConnectorCredentialExpiresAt = &expiresAt
		result.LinkedAt = &connector.CreatedAt
		return nil
	})
	if err != nil {
		return PollPairingResult{}, normalizeAuthorizationError(err)
	}
	return result, nil
}

// ApprovePairing records that the person at the OpenCode machine compared the safety code
// and approved the device that claimed this pairing. Confirmation requires it, so a pairing
// completes only with consent on both sides: without it, anyone who saw or guessed the user
// code could bind this OpenCode instance to their own account and drive it.
//
// It is authenticated by the pairing secret, which only the connector holds, and bound to
// the device key the connector was shown, so an approval can never apply to another device.
// Repeating it is a no-op, so a retry after a lost response succeeds.
func (service *Service) ApprovePairing(ctx context.Context, pairingID, pairingSecret, deviceKeyID string) error {
	if pairingID == "" || !validToken(pairingSecret, "orp_") {
		return ErrUnauthorized
	}
	if deviceKeyID == "" || len(deviceKeyID) > 64 {
		return ErrInvalidInput
	}
	now := service.now().UTC()
	expired := false
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		pairing, err := store.PairingBySecretForUpdate(ctx, hashSecret(pairingSecret))
		if err != nil {
			return err
		}
		if pairing.ID != pairingID {
			return ErrUnauthorized
		}
		if pairing.State == PairingStateExpired {
			expired = true
			return nil
		}
		if !pairing.ExpiresAt.After(now) {
			if pairing.State == PairingStateCompleted {
				return ErrExpired
			}
			pairing.State = PairingStateExpired
			expired = true
			return store.SavePairing(ctx, pairing)
		}
		if pairing.State != PairingStateVerification || pairing.DeviceID == nil {
			return ErrConflict
		}
		device, err := store.DeviceByIDForUpdate(ctx, *pairing.DeviceID)
		if err != nil {
			return err
		}
		if device.Identity.KeyID != deviceKeyID {
			return ErrConflict
		}
		if pairing.ConnectorReviewedAt != nil {
			return nil
		}
		pairing.ConnectorReviewedAt = &now
		if err := store.SavePairing(ctx, pairing); err != nil {
			return err
		}
		return store.AppendAuditEvent(ctx, AuditEvent{
			UserID: pairing.UserID, DeviceID: pairing.DeviceID, PairingID: &pairing.ID,
			EventType: "pairing.connector_approved", OccurredAt: now,
		})
	})
	if err != nil {
		return normalizeAuthorizationError(err)
	}
	if expired {
		return ErrExpired
	}
	return nil
}

func (service *Service) CancelPairing(ctx context.Context, pairingID, pairingSecret string) error {
	if pairingID == "" || !validToken(pairingSecret, "orp_") {
		return ErrUnauthorized
	}
	now := service.now().UTC()
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		pairing, err := store.PairingBySecretForUpdate(ctx, hashSecret(pairingSecret))
		if err != nil {
			return err
		}
		if pairing.ID != pairingID {
			return ErrUnauthorized
		}
		if pairing.State == PairingStateExpired {
			return nil
		}
		if pairing.State == PairingStateCompleted {
			return ErrConflict
		}
		pairing.State = PairingStateExpired
		if err := store.SavePairing(ctx, pairing); err != nil {
			return err
		}
		return store.AppendAuditEvent(ctx, AuditEvent{
			UserID: pairing.UserID, DeviceID: pairing.DeviceID, PairingID: &pairing.ID,
			EventType: "pairing.cancelled", OccurredAt: now,
		})
	})
	return normalizeAuthorizationError(err)
}

func (service *Service) IssueBrowserTicket(ctx context.Context, userID, sessionID, deviceID, credential string, authorizationExpiresAt time.Time) (TicketResult, error) {
	if userID == "" || sessionID == "" || deviceID == "" || !validToken(credential, "ord_") {
		return TicketResult{}, ErrUnauthorized
	}
	return service.issueTicket(ctx, RelayRoleClient, userID, sessionID, deviceID, hashSecret(credential), authorizationExpiresAt)
}

// RotateDeviceCredential issues a replacement for the device credential without disturbing
// the live one. Authenticated exactly as ticket issuance is: an account session, the device
// ID, and the current credential together, so the device ID is never the sole authority.
func (service *Service) RotateDeviceCredential(ctx context.Context, userID, sessionID, deviceID, credential string) (RotationResult, error) {
	if userID == "" || sessionID == "" || deviceID == "" || !validToken(credential, "ord_") {
		return RotationResult{}, ErrUnauthorized
	}
	now := service.now().UTC()
	var result RotationResult
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		device, err := store.DeviceByCredentialForUpdate(ctx, hashSecret(credential))
		if err != nil {
			return err
		}
		if device.ID != deviceID || device.UserID != userID || device.ActivatedAt == nil || device.RevokedAt != nil ||
			device.CredentialExpiresAt == nil || !device.CredentialExpiresAt.After(now) {
			return ErrUnauthorized
		}
		if err := service.authorizeAccount(ctx, device.UserID); err != nil {
			return err
		}
		if err := service.authorizeSession(ctx, device.UserID, sessionID); err != nil {
			return err
		}
		issued, err := issueToken(service.random, "ord_")
		if err != nil {
			return err
		}
		// A retried rotation replaces any pending one; only the newest can be activated.
		activationDeadline := now.Add(service.credentialActivationWindow)
		device.PendingCredentialHash = hashSecret(issued)
		device.PendingCredentialExpiresAt = &activationDeadline
		if err := store.SaveDevice(ctx, device); err != nil {
			return err
		}
		if err := store.AppendAuditEvent(ctx, AuditEvent{
			UserID: &device.UserID, DeviceID: &device.ID,
			EventType: "device.credential.rotated", OccurredAt: now,
		}); err != nil {
			return err
		}
		result = RotationResult{Credential: issued, ActivateBy: activationDeadline}
		return nil
	})
	if err != nil {
		return RotationResult{}, normalizeAuthorizationError(err)
	}
	return result, nil
}

// ActivateDeviceCredential commits a pending rotation. It is the only call that retires the
// previous credential, so the client controls when that happens and can make the new value
// durable first.
func (service *Service) ActivateDeviceCredential(ctx context.Context, userID, sessionID, deviceID, credential string) (time.Time, error) {
	if userID == "" || sessionID == "" || deviceID == "" || !validToken(credential, "ord_") {
		return time.Time{}, ErrUnauthorized
	}
	now := service.now().UTC()
	var expiresAt time.Time
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		hash := hashSecret(credential)
		device, err := store.DeviceByAnyCredentialForUpdate(ctx, hash)
		if err != nil {
			return err
		}
		if device.ID != deviceID || device.UserID != userID || device.ActivatedAt == nil || device.RevokedAt != nil {
			return ErrUnauthorized
		}
		if err := service.authorizeAccount(ctx, device.UserID); err != nil {
			return err
		}
		if err := service.authorizeSession(ctx, device.UserID, sessionID); err != nil {
			return err
		}
		// Activating the credential that is already current is a retry of a committed
		// rotation, which must stay idempotent after a lost response.
		if hmac.Equal(hash, device.CredentialHash) {
			if device.CredentialExpiresAt == nil || !device.CredentialExpiresAt.After(now) {
				return ErrUnauthorized
			}
			expiresAt = *device.CredentialExpiresAt
			return nil
		}
		if device.PendingCredentialHash == nil || !hmac.Equal(hash, device.PendingCredentialHash) ||
			device.PendingCredentialExpiresAt == nil || !device.PendingCredentialExpiresAt.After(now) {
			return ErrUnauthorized
		}
		// The lifetime starts here, so a provisional credential never burns time unused.
		expiresAt = now.Add(service.deviceCredentialLifetime)
		device.CredentialHash = hash
		device.CredentialExpiresAt = &expiresAt
		device.PendingCredentialHash = nil
		device.PendingCredentialExpiresAt = nil
		if err := store.SaveDevice(ctx, device); err != nil {
			return err
		}
		return store.AppendAuditEvent(ctx, AuditEvent{
			UserID: &device.UserID, DeviceID: &device.ID,
			EventType: "device.credential.activated", OccurredAt: now,
		})
	})
	if err != nil {
		return time.Time{}, normalizeAuthorizationError(err)
	}
	return expiresAt, nil
}

// cancelPendingDeviceRotation discards an unactivated rotation when the device proves it is
// still using its current credential.
func (service *Service) cancelPendingDeviceRotation(ctx context.Context, store TransactionStore, device *Device, now time.Time) error {
	if device.PendingCredentialHash == nil {
		return nil
	}
	device.PendingCredentialHash = nil
	device.PendingCredentialExpiresAt = nil
	if err := store.SaveDevice(ctx, *device); err != nil {
		return err
	}
	return store.AppendAuditEvent(ctx, AuditEvent{
		UserID: &device.UserID, DeviceID: &device.ID,
		EventType: "device.credential.rotation_cancelled", OccurredAt: now,
	})
}

// OwnConnector returns metadata only for the connector authenticated by this credential.
func (service *Service) OwnConnector(ctx context.Context, credential string) (Connector, error) {
	if !validToken(credential, "orc_") {
		return Connector{}, ErrUnauthorized
	}
	now := service.now().UTC()
	var result Connector
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		connector, err := store.ConnectorByCredentialForUpdate(ctx, hashSecret(credential))
		if err != nil {
			return err
		}
		if connector.RevokedAt != nil || connector.CredentialExpiresAt == nil || !connector.CredentialExpiresAt.After(now) {
			return ErrUnauthorized
		}
		if err := service.authorizeAccount(ctx, connector.UserID); err != nil {
			return err
		}
		result = connector
		return nil
	})
	return result, normalizeAuthorizationError(err)
}

// RotateConnectorCredential issues a replacement credential without disturbing the live one.
// The rotation stays provisional until ActivateConnectorCredential commits it, so a plugin
// that never persists or never activates the new value keeps working on its current
// credential instead of being locked out into re-pairing.
func (service *Service) RotateConnectorCredential(ctx context.Context, credential string) (RotationResult, error) {
	if !validToken(credential, "orc_") {
		return RotationResult{}, ErrUnauthorized
	}
	now := service.now().UTC()
	var result RotationResult
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		connector, err := store.ConnectorByCredentialForUpdate(ctx, hashSecret(credential))
		if err != nil {
			return err
		}
		if connector.RevokedAt != nil || connector.CredentialExpiresAt == nil || !connector.CredentialExpiresAt.After(now) {
			return ErrUnauthorized
		}
		if err := service.authorizeAccount(ctx, connector.UserID); err != nil {
			return err
		}
		issued, err := issueToken(service.random, "orc_")
		if err != nil {
			return err
		}
		// A retried rotation replaces any pending one; only the newest can be activated.
		activationDeadline := now.Add(service.credentialActivationWindow)
		connector.PendingCredentialHash = hashSecret(issued)
		connector.PendingCredentialExpiresAt = &activationDeadline
		if err := store.SaveConnector(ctx, connector); err != nil {
			return err
		}
		if err := store.AppendAuditEvent(ctx, AuditEvent{
			UserID: &connector.UserID, ConnectorID: &connector.ID,
			EventType: "connector.credential.rotated", OccurredAt: now,
		}); err != nil {
			return err
		}
		result = RotationResult{Credential: issued, ActivateBy: activationDeadline}
		return nil
	})
	if err != nil {
		return RotationResult{}, normalizeAuthorizationError(err)
	}
	return result, nil
}

// ActivateConnectorCredential commits a pending rotation. It is the only call that retires
// the previous credential, so the plugin controls when that happens and can make the new
// value durable first.
func (service *Service) ActivateConnectorCredential(ctx context.Context, credential string) (time.Time, error) {
	if !validToken(credential, "orc_") {
		return time.Time{}, ErrUnauthorized
	}
	now := service.now().UTC()
	var expiresAt time.Time
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		hash := hashSecret(credential)
		connector, err := store.ConnectorByAnyCredentialForUpdate(ctx, hash)
		if err != nil {
			return err
		}
		if connector.RevokedAt != nil {
			return ErrUnauthorized
		}
		if err := service.authorizeAccount(ctx, connector.UserID); err != nil {
			return err
		}
		// Activating the credential that is already current is a retry of a committed
		// rotation, which must stay idempotent after a lost response.
		if hmac.Equal(hash, connector.CredentialHash) {
			if connector.CredentialExpiresAt == nil || !connector.CredentialExpiresAt.After(now) {
				return ErrUnauthorized
			}
			expiresAt = *connector.CredentialExpiresAt
			return nil
		}
		if connector.PendingCredentialHash == nil || !hmac.Equal(hash, connector.PendingCredentialHash) ||
			connector.PendingCredentialExpiresAt == nil || !connector.PendingCredentialExpiresAt.After(now) {
			return ErrUnauthorized
		}
		// The lifetime starts here, so a provisional credential never burns time unused.
		expiresAt = now.Add(service.connectorCredentialLifetime)
		connector.CredentialHash = hash
		connector.CredentialExpiresAt = &expiresAt
		connector.PendingCredentialHash = nil
		connector.PendingCredentialExpiresAt = nil
		if err := store.SaveConnector(ctx, connector); err != nil {
			return err
		}
		return store.AppendAuditEvent(ctx, AuditEvent{
			UserID: &connector.UserID, ConnectorID: &connector.ID,
			EventType: "connector.credential.activated", OccurredAt: now,
		})
	})
	if err != nil {
		return time.Time{}, normalizeAuthorizationError(err)
	}
	return expiresAt, nil
}

// cancelPendingRotation discards an unactivated rotation when the connector proves it is
// still using its current credential. Returns whether the connector needs saving.
func (service *Service) cancelPendingRotation(ctx context.Context, store TransactionStore, connector *Connector, now time.Time) error {
	if connector.PendingCredentialHash == nil {
		return nil
	}
	connector.PendingCredentialHash = nil
	connector.PendingCredentialExpiresAt = nil
	if err := store.SaveConnector(ctx, *connector); err != nil {
		return err
	}
	return store.AppendAuditEvent(ctx, AuditEvent{
		UserID: &connector.UserID, ConnectorID: &connector.ID,
		EventType: "connector.credential.rotation_cancelled", OccurredAt: now,
	})
}

// RevokeConnector authenticates the connector itself, never a caller-selected account or ID.
// Keep the credential hash so a retry after a lost response remains idempotent.
func (service *Service) RevokeConnector(ctx context.Context, credential string) error {
	if !validToken(credential, "orc_") {
		return ErrUnauthorized
	}
	now := service.now().UTC()
	var revoked Revocation
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		connector, err := store.ConnectorByCredentialForUpdate(ctx, hashSecret(credential))
		if err != nil {
			return err
		}
		revoked = Revocation{UserID: connector.UserID, ConnectorID: connector.ID}
		if connector.RevokedAt != nil {
			return nil
		}
		if connector.CredentialExpiresAt == nil || !connector.CredentialExpiresAt.After(now) {
			return ErrUnauthorized
		}
		connector.RevokedAt = &now
		if err := store.SaveConnector(ctx, connector); err != nil {
			return err
		}
		return store.AppendAuditEvent(ctx, AuditEvent{
			UserID: &connector.UserID, ConnectorID: &connector.ID,
			EventType: "connector.revoked", OccurredAt: now,
		})
	})
	if err != nil {
		return normalizeAuthorizationError(err)
	}
	service.onRevoked(revoked)
	return nil
}

// RevokeAccountConnector lets an authenticated account revoke its own connector,
// including an expired connector or one not paired with the current client device.
// Missing and foreign IDs are indistinguishable. Keep the row/hash for idempotent
// retries and for rejecting outstanding tickets and existing relay admissions.
func (service *Service) RevokeAccountConnector(ctx context.Context, userID, connectorID string) error {
	if userID == "" || connectorID == "" || len(connectorID) > 64 {
		return ErrInvalidInput
	}
	if err := service.authorizeAccount(ctx, userID); err != nil {
		return ErrUnauthorized
	}
	now := service.now().UTC()
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		connector, err := store.ConnectorByIDForUpdate(ctx, connectorID)
		if err != nil {
			return err
		}
		if connector.UserID != userID {
			return ErrNotFound
		}
		if connector.RevokedAt != nil {
			return nil
		}
		connector.RevokedAt = &now
		if err := store.SaveConnector(ctx, connector); err != nil {
			return err
		}
		return store.AppendAuditEvent(ctx, AuditEvent{
			UserID: &connector.UserID, ConnectorID: &connector.ID,
			EventType: "connector.revoked", OccurredAt: now,
		})
	})
	if err != nil {
		return err
	}
	// Repeats notify too: closing a socket that is already gone does nothing.
	service.onRevoked(Revocation{UserID: userID, ConnectorID: connectorID})
	return nil
}

// RevokeAccountDevice lets an authenticated account revoke one of its client devices,
// typically a lost or replaced phone, from any of its sessions. Its credential, every
// trust relationship it holds, and any live relay socket end together; connectors stop
// receiving its identity at their next admission. Missing and foreign IDs are
// indistinguishable, and a repeat is a no-op so a retry after a lost response succeeds.
// A revoked device cannot be re-paired: its key must be replaced by a new installation.
func (service *Service) RevokeAccountDevice(ctx context.Context, userID, deviceID string) error {
	if userID == "" || deviceID == "" || len(deviceID) > 64 {
		return ErrInvalidInput
	}
	if err := service.authorizeAccount(ctx, userID); err != nil {
		return ErrUnauthorized
	}
	now := service.now().UTC()
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		device, err := store.DeviceByIDForUpdate(ctx, deviceID)
		if err != nil {
			return err
		}
		if device.UserID != userID {
			return ErrNotFound
		}
		if device.RevokedAt != nil {
			return nil
		}
		device.RevokedAt = &now
		device.PendingCredentialHash = nil
		device.PendingCredentialExpiresAt = nil
		if err := store.SaveDevice(ctx, device); err != nil {
			return err
		}
		if err := store.RevokeDeviceTrust(ctx, userID, device.ID, now); err != nil {
			return err
		}
		return store.AppendAuditEvent(ctx, AuditEvent{
			UserID: &device.UserID, DeviceID: &device.ID,
			EventType: "device.revoked", OccurredAt: now,
		})
	})
	if err != nil {
		return err
	}
	service.onRevoked(Revocation{UserID: userID, DeviceID: deviceID})
	return nil
}

func (service *Service) ListDevices(ctx context.Context, userID string) ([]Device, error) {
	if userID == "" {
		return nil, ErrUnauthorized
	}
	return service.repository.ListDevices(ctx, userID)
}

func (service *Service) RenameAccountConnector(ctx context.Context, userID, connectorID, name string) (Connector, error) {
	name, err := normalizeName(name)
	if err != nil || userID == "" || connectorID == "" || len(connectorID) > 64 {
		return Connector{}, ErrInvalidInput
	}
	if err := service.authorizeAccount(ctx, userID); err != nil {
		return Connector{}, ErrUnauthorized
	}
	var result Connector
	err = service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		connector, err := store.ConnectorByIDForUpdate(ctx, connectorID)
		if err != nil {
			return err
		}
		if connector.UserID != userID || connector.RevokedAt != nil {
			return ErrNotFound
		}
		if connector.Name != name {
			connector.Name = name
			if err := store.SaveConnector(ctx, connector); err != nil {
				return err
			}
			if err := store.AppendAuditEvent(ctx, AuditEvent{UserID: &connector.UserID, ConnectorID: &connector.ID, EventType: "connector.renamed", OccurredAt: service.now().UTC()}); err != nil {
				return err
			}
		}
		result = connector
		return nil
	})
	return result, err
}

// ValidateAdmission rechecks a live relay admission against current state, so revoking
// a connector, a device, or a client's account session ends its socket promptly
// instead of at the end of its lease.
func (service *Service) ValidateAdmission(ctx context.Context, admission Admission) error {
	if admission.UserID == "" || admission.SubjectID == "" {
		return ErrUnauthorized
	}
	switch admission.Role {
	case RelayRoleConnector:
	case RelayRoleClient:
		if admission.SessionID == "" {
			return ErrUnauthorized
		}
	default:
		return ErrUnauthorized
	}
	now := service.now().UTC()
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		if admission.Role == RelayRoleConnector {
			connector, err := store.ConnectorByIDForUpdate(ctx, admission.SubjectID)
			if err != nil {
				return err
			}
			if connector.UserID != admission.UserID || connector.Identity != admission.Identity || connector.RevokedAt != nil ||
				connector.CredentialExpiresAt == nil || !connector.CredentialExpiresAt.After(now) {
				return ErrUnauthorized
			}
			return service.authorizeAccount(ctx, connector.UserID)
		}
		device, err := store.DeviceByIDForUpdate(ctx, admission.SubjectID)
		if err != nil {
			return err
		}
		if device.UserID != admission.UserID || device.Identity != admission.Identity || device.ActivatedAt == nil ||
			device.RevokedAt != nil || device.CredentialExpiresAt == nil || !device.CredentialExpiresAt.After(now) {
			return ErrUnauthorized
		}
		if err := service.authorizeAccount(ctx, device.UserID); err != nil {
			return err
		}
		return service.authorizeSession(ctx, device.UserID, admission.SessionID)
	})
	return normalizeAuthorizationError(err)
}

func (service *Service) IssueConnectorTicket(ctx context.Context, credential string) (TicketResult, error) {
	if !validToken(credential, "orc_") {
		return TicketResult{}, ErrUnauthorized
	}
	return service.issueTicket(ctx, RelayRoleConnector, "", "", "", hashSecret(credential), time.Time{})
}

func (service *Service) issueTicket(ctx context.Context, role, userID, credentialID, subjectID string, credentialHash []byte, authorizationExpiresAt time.Time) (TicketResult, error) {
	ticket, err := issueToken(service.random, "ort_")
	if err != nil {
		return TicketResult{}, err
	}
	now := service.now().UTC()
	expiresAt := now.Add(service.ticketLifetime)
	err = service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		var identity PublicIdentity
		if role == RelayRoleClient {
			device, err := store.DeviceByCredentialForUpdate(ctx, credentialHash)
			if err != nil {
				return err
			}
			if device.ID != subjectID || device.UserID != userID || device.ActivatedAt == nil || device.RevokedAt != nil || device.CredentialExpiresAt == nil || !device.CredentialExpiresAt.After(now) {
				return ErrUnauthorized
			}
			// Connecting on the current credential proves the device never took up a
			// pending rotation, so that rotation is discarded rather than left to expire.
			if err := service.cancelPendingDeviceRotation(ctx, store, &device, now); err != nil {
				return err
			}
			identity = device.Identity
			if authorizationExpiresAt.IsZero() || device.CredentialExpiresAt.Before(authorizationExpiresAt) {
				authorizationExpiresAt = *device.CredentialExpiresAt
			}
		} else {
			connector, err := store.ConnectorByCredentialForUpdate(ctx, credentialHash)
			if err != nil {
				return err
			}
			if connector.RevokedAt != nil || connector.CredentialExpiresAt == nil || !connector.CredentialExpiresAt.After(now) {
				return ErrUnauthorized
			}
			// Connecting on the current credential proves the connector never took up a
			// pending rotation, so that rotation is discarded rather than left to expire.
			if err := service.cancelPendingRotation(ctx, store, &connector, now); err != nil {
				return err
			}
			userID, subjectID, credentialID, identity = connector.UserID, connector.ID, connector.ID, connector.Identity
			authorizationExpiresAt = *connector.CredentialExpiresAt
		}
		if err := service.authorizeAccount(ctx, userID); err != nil {
			return err
		}
		if role == RelayRoleClient {
			if err := service.authorizeSession(ctx, userID, credentialID); err != nil {
				return err
			}
		}
		return store.CreateRelayTicket(ctx, RelayTicket{
			TokenHash: hashSecret(ticket), UserID: userID, Role: role, SubjectID: subjectID,
			SubjectKeyID: identity.KeyID, CredentialID: credentialID, AuthorizationExpiresAt: &authorizationExpiresAt, CreatedAt: now, ExpiresAt: expiresAt,
		})
	})
	if err != nil {
		return TicketResult{}, normalizeAuthorizationError(err)
	}
	return TicketResult{Ticket: ticket, ExpiresAt: expiresAt}, nil
}

func (service *Service) ConsumeRelayTicket(ctx context.Context, ticket string) (Admission, error) {
	if !validToken(ticket, "ort_") {
		return Admission{}, ErrUnauthorized
	}
	now := service.now().UTC()
	var admission Admission
	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		record, err := store.RelayTicketForUpdate(ctx, hashSecret(ticket))
		if err != nil {
			return err
		}
		if record.ConsumedAt != nil || !record.ExpiresAt.After(now) || record.AuthorizationExpiresAt == nil || !record.AuthorizationExpiresAt.After(now) {
			return ErrUnauthorized
		}
		if err := service.authorizeAccount(ctx, record.UserID); err != nil {
			return err
		}
		if record.Role == RelayRoleClient {
			if err := service.authorizeSession(ctx, record.UserID, record.CredentialID); err != nil {
				return err
			}
		}
		var identity PublicIdentity
		if record.Role == RelayRoleClient {
			device, err := store.DeviceByIDForUpdate(ctx, record.SubjectID)
			if err != nil {
				return err
			}
			if device.UserID != record.UserID || device.ActivatedAt == nil || device.RevokedAt != nil || device.Identity.KeyID != record.SubjectKeyID {
				return ErrUnauthorized
			}
			identity = device.Identity
		} else if record.Role == RelayRoleConnector {
			connector, err := store.ConnectorByIDForUpdate(ctx, record.SubjectID)
			if err != nil {
				return err
			}
			if connector.UserID != record.UserID || connector.RevokedAt != nil || connector.Identity.KeyID != record.SubjectKeyID {
				return ErrUnauthorized
			}
			identity = connector.Identity
		} else {
			return ErrUnauthorized
		}
		trusted, err := store.TrustedIdentities(ctx, record.UserID, record.Role, record.SubjectID)
		if err != nil {
			return err
		}
		record.ConsumedAt = &now
		if err := store.SaveRelayTicket(ctx, record); err != nil {
			return err
		}
		leaseExpiresAt := now.Add(defaultAuthorizationLease)
		if record.AuthorizationExpiresAt.Before(leaseExpiresAt) {
			leaseExpiresAt = *record.AuthorizationExpiresAt
		}
		admission = Admission{UserID: record.UserID, Role: record.Role, SubjectID: record.SubjectID, Identity: identity, TrustedIdentities: trusted, AuthorizationExpiresAt: leaseExpiresAt}
		if record.Role == RelayRoleClient {
			admission.SessionID = record.CredentialID
		}
		return nil
	})
	if err != nil {
		return Admission{}, normalizeAuthorizationError(err)
	}
	return admission, nil
}

func (service *Service) ListConnectors(ctx context.Context, userID string) ([]Connector, error) {
	if userID == "" {
		return nil, ErrUnauthorized
	}
	return service.repository.ListConnectors(ctx, userID)
}

func (service *Service) transcript(pairing Pairing, deviceIdentity PublicIdentity) PairingTranscript {
	return PairingTranscript{
		Version: 1, ServiceID: service.serviceID, PairingID: pairing.ID,
		ConnectorIdentity: pairing.ConnectorIdentity, DeviceIdentity: deviceIdentity,
	}
}

func validIdentity(identity PublicIdentity) bool {
	if identity.Version != 1 || identity.Suite != hpkeSuiteID {
		return false
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(identity.PublicKey)
	if err != nil || len(publicKey) != 65 || publicKey[0] != 4 {
		return false
	}
	digest := sha256.Sum256(publicKey)
	if identity.KeyID != base64.RawURLEncoding.EncodeToString(digest[:]) {
		return false
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	return x != nil && y != nil
}

func verifyIdentityProof(identity PublicIdentity, proof IdentityProof) bool {
	challenge, err := base64.RawURLEncoding.DecodeString(proof.Challenge)
	if err != nil || len(challenge) != 32 {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(proof.Signature)
	if err != nil || len(signature) != 64 {
		return false
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(identity.PublicKey)
	if err != nil {
		return false
	}
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKey)
	if x == nil {
		return false
	}
	message, err := json.Marshal([]any{"opencode-remote/identity-proof/v1", proof.Challenge, identity.Version, identity.Suite, identity.KeyID, identity.PublicKey})
	if err != nil {
		return false
	}
	digest := sha256.Sum256(message)
	return ecdsa.Verify(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, digest[:], newBigInt(signature[:32]), newBigInt(signature[32:]))
}

func (service *Service) hashUserCode(code string) []byte {
	mac := hmac.New(sha256.New, service.pairingCodeKey)
	_, _ = mac.Write([]byte(normalizeUserCode(code)))
	return mac.Sum(nil)
}

func issueUserCode(random io.Reader) (string, error) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	bytes := make([]byte, 5)
	if _, err := io.ReadFull(random, bytes); err != nil {
		return "", err
	}
	value := uint64(bytes[0])<<32 | uint64(bytes[1])<<24 | uint64(bytes[2])<<16 | uint64(bytes[3])<<8 | uint64(bytes[4])
	encoded := make([]byte, 8)
	for index := 7; index >= 0; index-- {
		encoded[index] = alphabet[value&31]
		value >>= 5
	}
	return string(encoded[:4]) + "-" + string(encoded[4:]), nil
}

func normalizeUserCode(value string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
}

func normalizeName(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 64 || !utf8.ValidString(value) {
		return "", ErrInvalidInput
	}
	return value, nil
}

func issueIdentifier(random io.Reader, prefix string) (string, error) {
	value, err := randomBase64(random, 18)
	if err != nil {
		return "", err
	}
	return prefix + value, nil
}

func issueToken(random io.Reader, prefix string) (string, error) {
	value, err := randomBase64(random, 32)
	if err != nil {
		return "", err
	}
	return prefix + value, nil
}

func randomBase64(random io.Reader, size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func validToken(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil && len(decoded) == 32
}

func hashSecret(value string) []byte     { digest := sha256.Sum256([]byte(value)); return digest[:] }
func stringPointer(value string) *string { return &value }
func newBigInt(value []byte) *big.Int    { return new(big.Int).SetBytes(value) }
func defaultRandom() io.Reader           { return rand.Reader }

func deriveConnectorCredential(pairingSecret string) string {
	mac := hmac.New(sha256.New, []byte(pairingSecret))
	_, _ = mac.Write([]byte("opencode-remote/connector-credential/v1"))
	return "orc_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// deriveDeviceCredential turns a pairing's random seed into the device credential it issues.
// The seed lives only on the pairing row, so recomputing a credential takes both the database
// and the server key; the key exists so the database alone does not yield one either.
func (service *Service) deriveDeviceCredential(seed []byte) string {
	mac := hmac.New(sha256.New, service.deviceCredentialKey)
	_, _ = mac.Write([]byte("opencode-remote/device-credential/v2\x00"))
	_, _ = mac.Write(seed)
	return "ord_" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func normalizeAuthorizationError(err error) error {
	if errors.Is(err, ErrNotFound) {
		return ErrUnauthorized
	}
	return err
}
