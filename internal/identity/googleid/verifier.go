// Package googleid verifies Google-issued OpenID Connect ID tokens on behalf of the
// identity module. It is the only place in the server that speaks to Google, and it
// exists so that identity.GoogleVerifier stays free of a transport dependency.
//
// Verification is delegated to google.golang.org/api/idtoken, which pins the
// signing algorithm, fetches and caches Google's JWKS, and checks the signature,
// audience, and expiry. This package adds the checks that library deliberately
// leaves to its caller: the issuer, the presence of a subject and address, and
// Google's own assertion that the address is verified.
package googleid

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"opencode-remote/server/internal/identity"

	"google.golang.org/api/idtoken"
	"google.golang.org/api/option"
)

const (
	// maximumIDTokenLength bounds the work an unauthenticated caller can cause before
	// any parsing happens. Real Google ID tokens are well under a kilobyte.
	maximumIDTokenLength = 4096
	// maximumEmailLength matches the identity module's own address limit, so an
	// assertion carrying something longer is rejected here rather than at the store.
	maximumEmailLength = 254
	// maximumSubjectLength bounds the join key. Google subjects are 21-digit strings;
	// the allowance is generous but finite so the column cannot be overrun.
	maximumSubjectLength = 255
)

// Google mints tokens under both spellings and has never committed to retiring
// either, so both are accepted and nothing else is.
var permittedIssuers = []string{"accounts.google.com", "https://accounts.google.com"}

// Verifier validates ID tokens against a fixed set of audiences.
type Verifier struct {
	validator *idtoken.Validator
	audiences []string
}

// NewVerifier builds a verifier for the given OAuth client IDs. A deployment
// normally configures several — one per mobile platform, plus the web client ID the
// mobile SDKs request tokens for — and a token is accepted if its aud claim matches
// any one of them.
//
// An empty audience list is rejected rather than defaulted. idtoken.Validate skips
// the audience check entirely when handed an empty string, so a verifier built
// without audiences would accept any token Google ever signed, for any application.
func NewVerifier(ctx context.Context, audiences []string) (*Verifier, error) {
	cleaned, err := normalizeAudiences(audiences)
	if err != nil {
		return nil, err
	}
	validator, err := idtoken.NewValidator(ctx, option.WithoutAuthentication())
	if err != nil {
		return nil, fmt.Errorf("build google id token validator: %w", err)
	}
	return &Verifier{validator: validator, audiences: cleaned}, nil
}

// NewVerifierWithHTTPClient is NewVerifier with a caller-supplied client, so tests
// can point key retrieval at a local server instead of Google.
func NewVerifierWithHTTPClient(
	ctx context.Context,
	audiences []string,
	client *http.Client,
) (*Verifier, error) {
	cleaned, err := normalizeAudiences(audiences)
	if err != nil {
		return nil, err
	}
	validator, err := idtoken.NewValidator(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("build google id token validator: %w", err)
	}
	return &Verifier{validator: validator, audiences: cleaned}, nil
}

func normalizeAudiences(audiences []string) ([]string, error) {
	cleaned := make([]string, 0, len(audiences))
	for _, audience := range audiences {
		if audience = strings.TrimSpace(audience); audience != "" {
			cleaned = append(cleaned, audience)
		}
	}
	if len(cleaned) == 0 {
		return nil, errors.New("google id token verification requires at least one audience")
	}
	return cleaned, nil
}

// Verify returns the identity asserted by a valid token. Every failure is reported
// as identity.ErrInvalidGoogleToken so that a caller probing the endpoint cannot
// learn which check rejected the token; the specific reason is wrapped for logs but
// never distinguished in the response.
func (verifier *Verifier) Verify(
	ctx context.Context,
	rawIDToken string,
) (identity.GoogleIdentity, error) {
	if rawIDToken == "" || len(rawIDToken) > maximumIDTokenLength {
		return identity.GoogleIdentity{}, identity.ErrInvalidGoogleToken
	}

	// Each audience is validated in turn rather than validating once with an empty
	// audience and comparing the claim here. Delegating the comparison keeps the
	// check inside the library that also verified the signature, so no future edit
	// to this file can leave the signature verified but the audience unchecked. The
	// cost is at most one signature verification per configured client ID.
	var payload *idtoken.Payload
	for _, audience := range verifier.audiences {
		validated, err := verifier.validator.Validate(ctx, rawIDToken, audience)
		if err == nil {
			payload = validated
			break
		}
	}
	if payload == nil {
		return identity.GoogleIdentity{}, identity.ErrInvalidGoogleToken
	}

	// idtoken checks the signature, audience, and expiry but not the issuer, so a
	// token signed by a different Google-hosted issuer would otherwise pass.
	if !permittedIssuer(payload.Issuer) {
		return identity.GoogleIdentity{}, identity.ErrInvalidGoogleToken
	}
	if payload.Subject == "" || len(payload.Subject) > maximumSubjectLength {
		return identity.GoogleIdentity{}, identity.ErrInvalidGoogleToken
	}

	email, _ := payload.Claims["email"].(string)
	email = strings.TrimSpace(email)
	if email == "" || len(email) > maximumEmailLength {
		return identity.GoogleIdentity{}, identity.ErrInvalidGoogleToken
	}
	// A missing or false email_verified means Google has not confirmed the holder
	// controls the address. Accepting it would let anyone claim any address, which
	// is precisely what the local verification flow exists to prevent. The claim is
	// only ever a bool in practice; a non-bool value is treated as absent.
	verified, _ := payload.Claims["email_verified"].(bool)
	if !verified {
		return identity.GoogleIdentity{}, identity.ErrInvalidGoogleToken
	}

	return identity.GoogleIdentity{
		Subject:       payload.Subject,
		Email:         email,
		EmailVerified: true,
	}, nil
}

func permittedIssuer(issuer string) bool {
	for _, permitted := range permittedIssuers {
		if issuer == permitted {
			return true
		}
	}
	return false
}
