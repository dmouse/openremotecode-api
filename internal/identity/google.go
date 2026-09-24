package identity

import (
	"context"
	"errors"
	"time"
)

// googleConflictRetries bounds the retry described in AuthenticateWithGoogle. One
// retry is enough: the loser of a race finds the winner's row on its second pass,
// and a conflict that survives that is a real constraint problem, not contention.
const googleConflictRetries = 1

// AuthenticateWithGoogle exchanges a verified Google ID token for a session.
//
// It resolves an account in this order, and the order is the security argument:
//
//  1. An existing link for the token's subject. The subject, not the address, is the
//     durable identity — a Google account can change address, and an address can be
//     reassigned to a different Google account.
//  2. Failing that, a local account with the same address. It is linked only when
//     the address has been proved: either the account already verified it through
//     the code flow, or it is still pending and Google's assertion completes that
//     verification. An active account whose own address was never verified is
//     refused with ErrAccountLinkRequired, because linking it would hand the account
//     to whoever controls an address its owner may never have proved they own.
//  3. Failing that, a new active account, verified as of now.
//
// Unlike Register, this never mints a pending account: Google has already proved
// what the verification code exists to prove.
func (service *Service) AuthenticateWithGoogle(
	ctx context.Context,
	input GoogleAuthInput,
) (Credentials, error) {
	if service.googleVerifier == nil {
		return Credentials{}, ErrGoogleUnavailable
	}
	clientName, err := normalizeClientName(input.ClientName)
	if err != nil {
		return Credentials{}, ErrInvalidInput
	}
	asserted, err := service.googleVerifier.Verify(ctx, input.IDToken)
	if err != nil {
		// Every verification failure collapses into one error. A verifier that
		// returned something more specific must not widen what the caller learns.
		return Credentials{}, ErrInvalidGoogleToken
	}
	// Belt and braces: the verifier is contracted to reject an unverified address,
	// and this is the one claim the whole linking rule rests on.
	if !asserted.EmailVerified {
		return Credentials{}, ErrInvalidGoogleToken
	}
	email, normalizedEmail, err := normalizeEmail(asserted.Email)
	if err != nil {
		return Credentials{}, ErrInvalidGoogleToken
	}

	// Two devices signing in for the first time at the same moment both find no row
	// to lock — SELECT ... FOR UPDATE takes no lock on a row that does not exist —
	// so one of them loses on a unique index. Retrying resolves it against the row
	// the winner committed rather than surfacing a spurious internal error.
	for attempt := 0; ; attempt++ {
		outcome, err := service.googleSignIn(ctx, asserted.Subject, email, normalizedEmail, clientName)
		switch {
		case errors.Is(err, ErrConflict) && attempt < googleConflictRetries:
			continue
		case err != nil:
			return Credentials{}, err
		case outcome.refusal != nil:
			return Credentials{}, outcome.refusal
		}
		return outcome.credentials, nil
	}
}

// googleOutcome carries a refusal alongside a result because the two commit
// differently. Returning the refusal from the transaction closure would roll back
// the audit event that records it, exactly as returning an error would roll back a
// verification attempt counter. The closure therefore commits and reports the
// refusal here, where it becomes the caller's error.
type googleOutcome struct {
	credentials Credentials
	refusal     error
}

func (service *Service) googleSignIn(
	ctx context.Context,
	subject string,
	email string,
	normalizedEmail string,
	clientName string,
) (googleOutcome, error) {
	now := service.now().UTC()
	var outcome googleOutcome

	err := service.repository.WithinTransaction(ctx, func(store TransactionStore) error {
		link, err := store.FederatedIdentityForUpdate(ctx, ProviderGoogle, subject)
		switch {
		case err == nil:
			outcome.credentials, err = service.googleReturningUser(ctx, store, link, email, clientName, now)
			return err
		case errors.Is(err, ErrNotFound):
		default:
			return err
		}

		user, err := store.UserByNormalizedEmailForUpdate(ctx, normalizedEmail)
		switch {
		case errors.Is(err, ErrNotFound):
			outcome.credentials, err = service.googleNewAccount(ctx, store, subject, email, normalizedEmail, clientName, now)
			return err
		case err != nil:
			return err
		}
		outcome, err = service.googleLinkExisting(ctx, store, user, subject, email, clientName, now)
		return err
	})
	if err != nil {
		return googleOutcome{}, err
	}
	return outcome, nil
}

// googleReturningUser signs in an account that is already linked to this subject.
// The account's own address is left alone: the user may have changed it here
// deliberately, and the link is keyed by subject, so the two need not agree.
func (service *Service) googleReturningUser(
	ctx context.Context,
	store TransactionStore,
	link FederatedIdentity,
	email string,
	clientName string,
	now time.Time,
) (Credentials, error) {
	user, err := store.UserByID(ctx, link.UserID)
	if err != nil {
		// A link whose user has vanished is a broken invariant, not a bad credential.
		return Credentials{}, err
	}
	// A disabled account is refused exactly as it is on the password path, so the
	// two routes cannot be played against each other to learn an account's state.
	if user.Status != AccountStatusActive {
		return Credentials{}, ErrInvalidCredentials
	}
	if err := store.TouchFederatedIdentity(ctx, ProviderGoogle, link.Subject, email, now); err != nil {
		return Credentials{}, err
	}
	return service.startGoogleSession(ctx, store, user.Account, clientName, now, "auth.google_signin_succeeded")
}

// googleNewAccount creates an active, verified account for an address no local
// account holds. It has no password hash: nothing has been chosen, and a placeholder
// would be a credential nobody controls.
func (service *Service) googleNewAccount(
	ctx context.Context,
	store TransactionStore,
	subject string,
	email string,
	normalizedEmail string,
	clientName string,
	now time.Time,
) (Credentials, error) {
	userID, err := issueIdentifier(service.random, "usr_")
	if err != nil {
		return Credentials{}, err
	}
	account := Account{
		ID:              userID,
		Email:           email,
		Status:          AccountStatusActive,
		EmailVerifiedAt: &now,
		CreatedAt:       now,
	}
	if err := store.CreateUser(ctx, User{
		Account:         account,
		NormalizedEmail: normalizedEmail,
		PasswordHash:    nil,
	}); err != nil {
		return Credentials{}, err
	}
	if err := store.CreateFederatedIdentity(ctx, FederatedIdentity{
		Provider:            ProviderGoogle,
		Subject:             subject,
		UserID:              userID,
		Email:               email,
		CreatedAt:           now,
		LastAuthenticatedAt: now,
	}); err != nil {
		return Credentials{}, err
	}
	return service.startGoogleSession(ctx, store, account, clientName, now, "auth.google_account_created")
}

// googleLinkExisting attaches the subject to a local account that already holds the
// address. This is the only branch where the linking rule bites.
func (service *Service) googleLinkExisting(
	ctx context.Context,
	store TransactionStore,
	user User,
	subject string,
	email string,
	clientName string,
	now time.Time,
) (googleOutcome, error) {
	account := user.Account
	switch {
	case user.Status == AccountStatusPending:
		// Google proved control of the address, which is what the mailed code exists
		// to prove. Completing the pending verification here is strictly stronger
		// than leaving the account stranded behind a code it may never receive.
		//
		// The password does not survive, though. Anyone can register a pending
		// account for an address they do not control, so the password on it proves
		// nothing about the person Google just vouched for. Keeping it would let
		// whoever pre-registered the address sign in to the account its real owner
		// is about to use. A pending account never holds a session, so there is
		// nothing else to revoke; the owner can set a password later.
		//
		// The pending-only WHERE clause is what keeps this branch from ever touching
		// an account in another state.
		if err := store.ActivateFederatedUser(ctx, user.ID, now); err != nil {
			return googleOutcome{}, err
		}
		if err := store.DeleteEmailVerification(ctx, user.ID); err != nil {
			return googleOutcome{}, err
		}
		account.Status = AccountStatusActive
		account.EmailVerifiedAt = &now
	case user.Status != AccountStatusActive:
		return googleOutcome{}, ErrInvalidCredentials
	case user.EmailVerifiedAt == nil:
		// An account predating email verification. Nobody ever proved this address
		// belongs to whoever registered it, so a matching Google address is not
		// evidence that the two are the same person. The user signs in with their
		// password, which does prove it, and links from there.
		//
		// This returns no error so the audit event commits. Nothing else was written
		// on this path, so committing records the refusal and changes nothing else.
		return googleRefusal(ctx, store, "auth.google_link_required", user.ID, now, ErrAccountLinkRequired)
	}

	// One account holds at most one identity per provider. This is checked rather
	// than left to the unique index because a constraint violation aborts the whole
	// PostgreSQL transaction, which would take the audit event with it — and because
	// a rule this load-bearing should be visible here, not only in the schema.
	//
	// It is reachable without any concurrency: a second Google account that has since
	// taken over an address already linked to this account arrives here.
	switch _, err := store.FederatedIdentityByUserForUpdate(ctx, ProviderGoogle, user.ID); {
	case err == nil:
		return googleRefusal(ctx, store, "auth.google_identity_conflict", user.ID, now, ErrIdentityAlreadyLinked)
	case errors.Is(err, ErrNotFound):
	default:
		return googleOutcome{}, err
	}

	if err := store.CreateFederatedIdentity(ctx, FederatedIdentity{
		Provider:            ProviderGoogle,
		Subject:             subject,
		UserID:              user.ID,
		Email:               email,
		CreatedAt:           now,
		LastAuthenticatedAt: now,
	}); err != nil {
		return googleOutcome{}, err
	}
	credentials, err := service.startGoogleSession(ctx, store, account, clientName, now, "auth.google_identity_linked")
	return googleOutcome{credentials: credentials}, err
}

// googleRefusal records why a sign-in was refused and reports it as an outcome
// rather than an error, so the audit event survives the commit. Every refusal that
// names an account goes through here, so none can accidentally be rolled back.
func googleRefusal(
	ctx context.Context,
	store TransactionStore,
	eventType string,
	userID string,
	now time.Time,
	refusal error,
) (googleOutcome, error) {
	if err := store.AppendAuditEvent(ctx, accountAuditEvent(eventType, userID, now)); err != nil {
		return googleOutcome{}, err
	}
	return googleOutcome{refusal: refusal}, nil
}

func (service *Service) startGoogleSession(
	ctx context.Context,
	store TransactionStore,
	account Account,
	clientName string,
	now time.Time,
	eventType string,
) (Credentials, error) {
	material, err := service.newSessionMaterial(account, clientName, now)
	if err != nil {
		return Credentials{}, err
	}
	if err := persistSessionMaterial(ctx, store, material); err != nil {
		return Credentials{}, err
	}
	if err := store.AppendAuditEvent(ctx, auditEvent(
		eventType,
		account.ID,
		material.session.ID,
		now,
	)); err != nil {
		return Credentials{}, err
	}
	return material.credentials, nil
}
