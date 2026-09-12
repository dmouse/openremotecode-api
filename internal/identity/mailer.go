package identity

import "context"

// Mailer delivers account mail. Implementations return ErrMailUndeliverable for a
// permanent per-recipient rejection and ErrMailDeliveryFailed for anything
// transient, because only the former may record a bounce against the address.
type Mailer interface {
	SendVerificationCode(ctx context.Context, to, code string) error
	// SendRegistrationNotice tells the owner of an already-registered address that
	// someone attempted to register it. It exists so that Register can answer a
	// duplicate address with a decoy challenge instead of an enumeration oracle.
	SendRegistrationNotice(ctx context.Context, to string) error
}
