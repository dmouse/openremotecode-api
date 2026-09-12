package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"sync"
	"time"
)

// memoryRepository is an in-memory Repository and TransactionStore with real
// rollback: a transaction that returns an error leaves no trace. That fidelity is
// the point, because the verification flow deliberately relies on the difference
// between returning an error and returning nil from a transaction closure.
type memoryRepository struct {
	mutex         sync.Mutex
	users         map[string]User
	usersByEmail  map[string]string
	federated     map[string]FederatedIdentity
	sessions      map[string]Session
	refresh       map[string]RefreshCredential
	verifications map[string]EmailVerification
	events        []AuditEvent
}

func newMemoryRepository() *memoryRepository {
	return &memoryRepository{
		users:         map[string]User{},
		usersByEmail:  map[string]string{},
		federated:     map[string]FederatedIdentity{},
		sessions:      map[string]Session{},
		refresh:       map[string]RefreshCredential{},
		verifications: map[string]EmailVerification{},
	}
}

// federatedKey mirrors the composite primary key so the fake enforces the same
// uniqueness the schema does.
func federatedKey(provider, subject string) string { return provider + "\x00" + subject }

func (repository *memoryRepository) WithinTransaction(
	ctx context.Context,
	operation func(TransactionStore) error,
) error {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	snapshot := repository.snapshot()
	if err := operation(repository); err != nil {
		repository.restore(snapshot)
		return err
	}
	return nil
}

func (repository *memoryRepository) snapshot() *memoryRepository {
	return &memoryRepository{
		users:         maps.Clone(repository.users),
		usersByEmail:  maps.Clone(repository.usersByEmail),
		federated:     maps.Clone(repository.federated),
		sessions:      maps.Clone(repository.sessions),
		refresh:       maps.Clone(repository.refresh),
		verifications: maps.Clone(repository.verifications),
		events:        append([]AuditEvent(nil), repository.events...),
	}
}

func (repository *memoryRepository) restore(snapshot *memoryRepository) {
	repository.users = snapshot.users
	repository.usersByEmail = snapshot.usersByEmail
	repository.federated = snapshot.federated
	repository.sessions = snapshot.sessions
	repository.refresh = snapshot.refresh
	repository.verifications = snapshot.verifications
	repository.events = snapshot.events
}

func (repository *memoryRepository) UserByNormalizedEmail(
	_ context.Context,
	normalizedEmail string,
) (User, error) {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	userID, ok := repository.usersByEmail[normalizedEmail]
	if !ok {
		return User{}, ErrNotFound
	}
	return repository.users[userID], nil
}

func (repository *memoryRepository) AccessPrincipalByAccessTokenHash(
	_ context.Context,
	accessTokenHash []byte,
	now time.Time,
) (AccessPrincipal, error) {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	for _, session := range repository.sessions {
		if hex.EncodeToString(session.AccessTokenHash) != hex.EncodeToString(accessTokenHash) {
			continue
		}
		user := repository.users[session.UserID]
		if session.RevokedAt != nil ||
			!session.AccessTokenExpiresAt.After(now) ||
			user.Status != AccountStatusActive {
			return AccessPrincipal{}, ErrNotFound
		}
		return AccessPrincipal{
			Account:              user.Account,
			SessionID:            session.ID,
			AccessTokenExpiresAt: session.AccessTokenExpiresAt,
		}, nil
	}
	return AccessPrincipal{}, ErrNotFound
}

func (repository *memoryRepository) ActiveAccountByID(
	_ context.Context,
	userID string,
) (Account, error) {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	user, ok := repository.users[userID]
	if !ok || user.Status != AccountStatusActive {
		return Account{}, ErrNotFound
	}
	return user.Account, nil
}

func (repository *memoryRepository) ActiveSessionByID(
	_ context.Context,
	userID, sessionID string,
	now time.Time,
) error {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	session, ok := repository.sessions[sessionID]
	user := repository.users[userID]
	if !ok || session.UserID != userID || session.RevokedAt != nil ||
		!session.AccessTokenExpiresAt.After(now) || user.Status != AccountStatusActive {
		return ErrNotFound
	}
	return nil
}

func (repository *memoryRepository) SetEmailBounced(
	_ context.Context,
	userID string,
	at *time.Time,
) error {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	user, ok := repository.users[userID]
	if !ok {
		return ErrNotFound
	}
	user.EmailBouncedAt = at
	repository.users[userID] = user
	return nil
}

func (repository *memoryRepository) CreateUser(_ context.Context, user User) error {
	if _, taken := repository.usersByEmail[user.NormalizedEmail]; taken {
		return ErrConflict
	}
	repository.users[user.ID] = user
	repository.usersByEmail[user.NormalizedEmail] = user.ID
	return nil
}

func (repository *memoryRepository) FederatedIdentityForUpdate(
	_ context.Context,
	provider string,
	subject string,
) (FederatedIdentity, error) {
	link, ok := repository.federated[federatedKey(provider, subject)]
	if !ok {
		return FederatedIdentity{}, ErrNotFound
	}
	return link, nil
}

func (repository *memoryRepository) FederatedIdentityByUserForUpdate(
	_ context.Context,
	provider string,
	userID string,
) (FederatedIdentity, error) {
	for _, link := range repository.federated {
		if link.Provider == provider && link.UserID == userID {
			return link, nil
		}
	}
	return FederatedIdentity{}, ErrNotFound
}

func (repository *memoryRepository) CreateFederatedIdentity(
	_ context.Context,
	link FederatedIdentity,
) error {
	if _, taken := repository.federated[federatedKey(link.Provider, link.Subject)]; taken {
		return ErrConflict
	}
	// Mirrors the per-provider unique index on user_id: one account holds at most
	// one identity per provider.
	for _, existing := range repository.federated {
		if existing.Provider == link.Provider && existing.UserID == link.UserID {
			return ErrConflict
		}
	}
	repository.federated[federatedKey(link.Provider, link.Subject)] = link
	return nil
}

func (repository *memoryRepository) TouchFederatedIdentity(
	_ context.Context,
	provider string,
	subject string,
	email string,
	at time.Time,
) error {
	key := federatedKey(provider, subject)
	link, ok := repository.federated[key]
	if !ok {
		return ErrNotFound
	}
	link.Email = email
	link.LastAuthenticatedAt = at
	repository.federated[key] = link
	return nil
}

func (repository *memoryRepository) UserByNormalizedEmailForUpdate(
	_ context.Context,
	normalizedEmail string,
) (User, error) {
	userID, ok := repository.usersByEmail[normalizedEmail]
	if !ok {
		return User{}, ErrNotFound
	}
	return repository.users[userID], nil
}

func (repository *memoryRepository) CreateSession(_ context.Context, session Session) error {
	repository.sessions[session.ID] = session
	return nil
}

func (repository *memoryRepository) CreateRefreshCredential(
	_ context.Context,
	credential RefreshCredential,
) error {
	repository.refresh[hex.EncodeToString(credential.TokenHash)] = credential
	return nil
}

func (repository *memoryRepository) CreateEmailVerification(
	_ context.Context,
	verification EmailVerification,
) error {
	if _, exists := repository.verifications[verification.UserID]; exists {
		return ErrConflict
	}
	repository.verifications[verification.UserID] = verification
	return nil
}

func (repository *memoryRepository) ReplaceEmailVerification(
	_ context.Context,
	verification EmailVerification,
) error {
	repository.verifications[verification.UserID] = verification
	return nil
}

func (repository *memoryRepository) EmailVerificationForUpdate(
	_ context.Context,
	ticketHash []byte,
) (EmailVerification, error) {
	for _, verification := range repository.verifications {
		if hex.EncodeToString(verification.TicketHash) == hex.EncodeToString(ticketHash) {
			return verification, nil
		}
	}
	return EmailVerification{}, ErrNotFound
}

func (repository *memoryRepository) EmailVerificationByUserIDForUpdate(
	_ context.Context,
	userID string,
) (EmailVerification, error) {
	verification, ok := repository.verifications[userID]
	if !ok {
		return EmailVerification{}, ErrNotFound
	}
	return verification, nil
}

func (repository *memoryRepository) IncrementEmailVerificationAttempts(
	_ context.Context,
	userID string,
) error {
	verification, ok := repository.verifications[userID]
	if !ok {
		return ErrNotFound
	}
	verification.Attempts++
	repository.verifications[userID] = verification
	return nil
}

func (repository *memoryRepository) DeleteEmailVerification(
	_ context.Context,
	userID string,
) error {
	delete(repository.verifications, userID)
	return nil
}

func (repository *memoryRepository) ActivateUser(
	_ context.Context,
	userID string,
	verifiedAt time.Time,
) error {
	user, ok := repository.users[userID]
	if !ok || user.Status != AccountStatusPending {
		return ErrNotFound
	}
	user.Status = AccountStatusActive
	user.EmailVerifiedAt = &verifiedAt
	repository.users[userID] = user
	return nil
}

func (repository *memoryRepository) RefreshCredentialForUpdate(
	_ context.Context,
	tokenHash []byte,
) (RefreshCredential, error) {
	credential, ok := repository.refresh[hex.EncodeToString(tokenHash)]
	if !ok {
		return RefreshCredential{}, ErrNotFound
	}
	return credential, nil
}

func (repository *memoryRepository) SessionForUpdate(
	_ context.Context,
	sessionID string,
) (Session, error) {
	session, ok := repository.sessions[sessionID]
	if !ok {
		return Session{}, ErrNotFound
	}
	return session, nil
}

func (repository *memoryRepository) UserByID(_ context.Context, userID string) (User, error) {
	user, ok := repository.users[userID]
	if !ok {
		return User{}, ErrNotFound
	}
	return user, nil
}

func (repository *memoryRepository) MarkRefreshCredentialUsed(
	_ context.Context,
	tokenHash []byte,
	usedAt time.Time,
) error {
	key := hex.EncodeToString(tokenHash)
	credential, ok := repository.refresh[key]
	if !ok || credential.UsedAt != nil {
		return ErrNotFound
	}
	credential.UsedAt = &usedAt
	repository.refresh[key] = credential
	return nil
}

func (repository *memoryRepository) RotateSessionAccess(
	_ context.Context,
	sessionID string,
	accessTokenHash []byte,
	accessExpiresAt time.Time,
	refreshedAt time.Time,
) error {
	session, ok := repository.sessions[sessionID]
	if !ok || session.RevokedAt != nil {
		return ErrNotFound
	}
	session.AccessTokenHash = accessTokenHash
	session.AccessTokenExpiresAt = accessExpiresAt
	session.LastRefreshedAt = refreshedAt
	repository.sessions[sessionID] = session
	return nil
}

func (repository *memoryRepository) RevokeSession(
	_ context.Context,
	sessionID string,
	revokedAt time.Time,
) error {
	session, ok := repository.sessions[sessionID]
	if !ok || session.RevokedAt != nil {
		return nil
	}
	session.RevokedAt = &revokedAt
	repository.sessions[sessionID] = session
	return nil
}

func (repository *memoryRepository) AppendAuditEvent(_ context.Context, event AuditEvent) error {
	repository.events = append(repository.events, event)
	return nil
}

func (repository *memoryRepository) auditEventCount(eventType string) int {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	count := 0
	for _, event := range repository.events {
		if event.EventType == eventType {
			count++
		}
	}
	return count
}

func (repository *memoryRepository) verificationFor(userID string) (EmailVerification, bool) {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	verification, ok := repository.verifications[userID]
	return verification, ok
}

func (repository *memoryRepository) userCount() int {
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	return len(repository.users)
}

// sentMail records one delivery attempt. Code is empty for a registration notice,
// which is what distinguishes the decoy path's mail from a real challenge.
type sentMail struct {
	to   string
	code string
}

type fakeMailer struct {
	mutex sync.Mutex
	sent  []sentMail
	err   error
}

func (mailer *fakeMailer) fail(err error) {
	mailer.mutex.Lock()
	defer mailer.mutex.Unlock()
	mailer.err = err
}

func (mailer *fakeMailer) SendVerificationCode(_ context.Context, to, code string) error {
	mailer.mutex.Lock()
	defer mailer.mutex.Unlock()
	mailer.sent = append(mailer.sent, sentMail{to: to, code: code})
	return mailer.err
}

func (mailer *fakeMailer) SendRegistrationNotice(_ context.Context, to string) error {
	mailer.mutex.Lock()
	defer mailer.mutex.Unlock()
	mailer.sent = append(mailer.sent, sentMail{to: to})
	return mailer.err
}

func (mailer *fakeMailer) messages() []sentMail {
	mailer.mutex.Lock()
	defer mailer.mutex.Unlock()
	return append([]sentMail(nil), mailer.sent...)
}

func (mailer *fakeMailer) lastCode() string {
	messages := mailer.messages()
	for index := len(messages) - 1; index >= 0; index-- {
		if messages[index].code != "" {
			return messages[index].code
		}
	}
	return ""
}

func (mailer *fakeMailer) reset() {
	mailer.mutex.Lock()
	defer mailer.mutex.Unlock()
	mailer.sent = nil
}

// fakeGoogleVerifier stands in for googleid.Verifier. Tests set the identity a
// token maps to, so the service's linking rules can be exercised without a signed
// assertion. The real verifier's own checks are covered in its package.
type fakeGoogleVerifier struct {
	mutex      sync.Mutex
	identities map[string]GoogleIdentity
	err        error
}

func newFakeGoogleVerifier() *fakeGoogleVerifier {
	return &fakeGoogleVerifier{identities: map[string]GoogleIdentity{}}
}

func (verifier *fakeGoogleVerifier) accept(token string, asserted GoogleIdentity) {
	verifier.mutex.Lock()
	defer verifier.mutex.Unlock()
	verifier.identities[token] = asserted
}

func (verifier *fakeGoogleVerifier) fail(err error) {
	verifier.mutex.Lock()
	defer verifier.mutex.Unlock()
	verifier.err = err
}

func (verifier *fakeGoogleVerifier) Verify(
	_ context.Context,
	rawIDToken string,
) (GoogleIdentity, error) {
	verifier.mutex.Lock()
	defer verifier.mutex.Unlock()
	if verifier.err != nil {
		return GoogleIdentity{}, verifier.err
	}
	asserted, ok := verifier.identities[rawIDToken]
	if !ok {
		return GoogleIdentity{}, ErrInvalidGoogleToken
	}
	return asserted, nil
}

// testPasswords hashes cheaply so the suite does not pay for Argon2id.
type testPasswords struct{}

func (testPasswords) Hash(_ context.Context, password string) (string, error) {
	hash := sha256.Sum256([]byte(password))
	return "test$" + hex.EncodeToString(hash[:]), nil
}

func (testPasswords) Verify(ctx context.Context, password, encodedHash string) (bool, error) {
	actual, _ := testPasswords{}.Hash(ctx, password)
	return actual == encodedHash, nil
}

// countingRandom is deterministic but never repeats, so distinct tokens stay
// distinct while the tests remain reproducible.
type countingRandom struct {
	mutex sync.Mutex
	value byte
}

func (random *countingRandom) Read(destination []byte) (int, error) {
	random.mutex.Lock()
	defer random.mutex.Unlock()
	for index := range destination {
		destination[index] = random.value
		random.value++
	}
	return len(destination), nil
}

type verificationFixture struct {
	service    *Service
	repository *memoryRepository
	mailer     *fakeMailer
	google     *fakeGoogleVerifier
	now        time.Time
}

func newVerificationFixture(t interface{ Fatalf(string, ...any) }) *verificationFixture {
	return newFixture(t, newFakeGoogleVerifier())
}

// newFixtureWithoutGoogle builds a service for a deployment that has not configured
// Google sign-in, which is the default and must stay a supported arrangement.
func newFixtureWithoutGoogle(t interface{ Fatalf(string, ...any) }) *verificationFixture {
	return newFixture(t, nil)
}

func newFixture(
	t interface{ Fatalf(string, ...any) },
	google *fakeGoogleVerifier,
) *verificationFixture {
	fixture := &verificationFixture{
		repository: newMemoryRepository(),
		mailer:     &fakeMailer{},
		google:     google,
		now:        time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC),
	}
	options := ServiceOptions{
		Now:    func() time.Time { return fixture.now },
		Random: &countingRandom{},
	}
	// Assigning a nil *fakeGoogleVerifier to the interface field would produce a
	// non-nil interface holding a nil pointer, which is exactly the state the
	// service reads as "configured". The field is left alone instead.
	if google != nil {
		options.GoogleVerifier = google
	}
	service, err := NewService(
		fixture.repository,
		testPasswords{},
		fixture.mailer,
		options,
	)
	if err != nil {
		t.Fatalf("create identity service: %v", err)
	}
	fixture.service = service
	return fixture
}

// seedUser inserts an account directly, for the states registration cannot produce:
// a legacy account with no verified address, or a federated account with no password.
func (fixture *verificationFixture) seedUser(
	t interface{ Fatalf(string, ...any) },
	user User,
) {
	if err := fixture.repository.WithinTransaction(
		context.Background(),
		func(store TransactionStore) error { return store.CreateUser(context.Background(), user) },
	); err != nil {
		t.Fatalf("seed account %q: %v", user.ID, err)
	}
}

func (fixture *verificationFixture) linkFor(
	provider string,
	subject string,
) (FederatedIdentity, bool) {
	fixture.repository.mutex.Lock()
	defer fixture.repository.mutex.Unlock()
	link, ok := fixture.repository.federated[federatedKey(provider, subject)]
	return link, ok
}

func (fixture *verificationFixture) advance(duration time.Duration) {
	fixture.now = fixture.now.Add(duration)
}

func (fixture *verificationFixture) register(
	t interface{ Fatalf(string, ...any) },
	email string,
) VerificationChallenge {
	outcome, err := fixture.service.Register(context.Background(), RegisterInput{
		Email:      email,
		Password:   "correct horse battery staple",
		ClientName: "Test client",
	})
	if err != nil {
		t.Fatalf("register %s: %v", email, err)
	}
	if outcome.Verification == nil {
		t.Fatalf("register %s returned no verification challenge", email)
	}
	return *outcome.Verification
}
func (fixture *verificationFixture) accountFor(
	t interface{ Fatalf(string, ...any) },
	userID string,
) Account {
	fixture.repository.mutex.Lock()
	defer fixture.repository.mutex.Unlock()
	user, ok := fixture.repository.users[userID]
	if !ok {
		t.Fatalf("account %q does not exist", userID)
	}
	return user.Account
}
