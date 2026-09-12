package googleid

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"opencode-remote/server/internal/identity"
)

const (
	testKeyID     = "test-signing-key"
	testAudience  = "111111111111-web.apps.googleusercontent.com"
	otherAudience = "222222222222-android.apps.googleusercontent.com"
	testSubject   = "108734295610293847561"
)

// certRewriter sends every request to the local key server, whatever host the
// library asks for, so the verifier can be exercised without reaching Google.
type certRewriter struct {
	base      string
	transport http.RoundTripper
}

func (rewriter certRewriter) RoundTrip(request *http.Request) (*http.Response, error) {
	rewritten := request.Clone(request.Context())
	target := rewriter.base + request.URL.Path
	parsed, err := request.URL.Parse(target)
	if err != nil {
		return nil, err
	}
	rewritten.URL = parsed
	rewritten.Host = parsed.Host
	return rewriter.transport.RoundTrip(rewritten)
}

type signingFixture struct {
	key *rsa.PrivateKey
}

func newSigningFixture(t *testing.T) (*signingFixture, *http.Client) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	keys := map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"alg": "RS256",
		"use": "sig",
		"kid": testKeyID,
		"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}}}
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(keys)
	}))
	t.Cleanup(server.Close)
	return &signingFixture{key: key}, &http.Client{
		Transport: certRewriter{base: server.URL, transport: http.DefaultTransport},
	}
}

// sign builds a token from the given claims. Callers override only what their case
// is about, so each test reads as the one thing it changes.
func (fixture *signingFixture) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	return fixture.signWithHeader(t, map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"kid": testKeyID,
	}, claims)
}

func (fixture *signingFixture) signWithHeader(
	t *testing.T,
	header map[string]any,
	claims map[string]any,
) string {
	t.Helper()
	encode := func(document any) string {
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatalf("encode token segment: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	content := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(content))
	signature, err := rsa.SignPKCS1v15(rand.Reader, fixture.key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return content + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func validClaims() map[string]any {
	return map[string]any{
		"iss":            "https://accounts.google.com",
		"aud":            testAudience,
		"sub":            testSubject,
		"email":          "person@example.com",
		"email_verified": true,
		"iat":            time.Now().Add(-time.Minute).Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
}

func newTestVerifier(t *testing.T, audiences []string, client *http.Client) *Verifier {
	t.Helper()
	verifier, err := NewVerifierWithHTTPClient(context.Background(), audiences, client)
	if err != nil {
		t.Fatalf("build verifier: %v", err)
	}
	return verifier
}

func TestVerifierAcceptsValidToken(t *testing.T) {
	fixture, client := newSigningFixture(t)
	verifier := newTestVerifier(t, []string{testAudience}, client)

	asserted, err := verifier.Verify(context.Background(), fixture.sign(t, validClaims()))
	if err != nil {
		t.Fatalf("verify valid token: %v", err)
	}
	if asserted.Subject != testSubject {
		t.Fatalf("subject = %q, want %q", asserted.Subject, testSubject)
	}
	if asserted.Email != "person@example.com" {
		t.Fatalf("email = %q, want person@example.com", asserted.Email)
	}
	if !asserted.EmailVerified {
		t.Fatal("a token asserting a verified address must report it verified")
	}
}

// A deployment configures one client ID per platform. A token addressed to any of
// them is this application's token; one addressed to none of them is not.
func TestVerifierAcceptsAnyConfiguredAudience(t *testing.T) {
	fixture, client := newSigningFixture(t)
	verifier := newTestVerifier(t, []string{otherAudience, testAudience}, client)

	if _, err := verifier.Verify(context.Background(), fixture.sign(t, validClaims())); err != nil {
		t.Fatalf("verify token for a secondary audience: %v", err)
	}
}

func TestVerifierRejectsInvalidTokens(t *testing.T) {
	fixture, client := newSigningFixture(t)
	verifier := newTestVerifier(t, []string{testAudience}, client)

	claimsWith := func(overrides map[string]any) map[string]any {
		claims := validClaims()
		for key, value := range overrides {
			if value == nil {
				delete(claims, key)
				continue
			}
			claims[key] = value
		}
		return claims
	}

	tests := map[string]string{
		// The check idtoken leaves to its caller. Without it a token from any other
		// Google-hosted issuer would pass every remaining test.
		"foreign issuer": fixture.sign(t, claimsWith(map[string]any{"iss": "https://evil.example.com"})),
		"missing issuer": fixture.sign(t, claimsWith(map[string]any{"iss": nil})),
		// A token minted for a different application entirely.
		"wrong audience": fixture.sign(t, claimsWith(map[string]any{"aud": "999-other.apps.googleusercontent.com"})),
		"expired":        fixture.sign(t, claimsWith(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})),
		// The claim the entire account-linking rule rests on.
		"unverified email":         fixture.sign(t, claimsWith(map[string]any{"email_verified": false})),
		"missing email_verified":   fixture.sign(t, claimsWith(map[string]any{"email_verified": nil})),
		"email_verified as string": fixture.sign(t, claimsWith(map[string]any{"email_verified": "true"})),
		"missing email":            fixture.sign(t, claimsWith(map[string]any{"email": nil})),
		"blank email":              fixture.sign(t, claimsWith(map[string]any{"email": "   "})),
		"missing subject":          fixture.sign(t, claimsWith(map[string]any{"sub": nil})),
		"unknown signing key": fixture.signWithHeader(t, map[string]any{
			"alg": "RS256", "typ": "JWT", "kid": "not-a-published-key",
		}, validClaims()),
		// Algorithm confusion: an attacker-chosen "signature" over chosen claims.
		"unsigned": strings.Join([]string{
			base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)),
			base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"https://accounts.google.com","aud":"` +
				testAudience + `","sub":"` + testSubject + `","email":"person@example.com","email_verified":true,"exp":99999999999}`)),
			"",
		}, "."),
		"empty":         "",
		"not a jwt":     "not-a-token",
		"oversized":     strings.Repeat("a", maximumIDTokenLength+1),
		"tampered body": tamper(fixture.sign(t, validClaims())),
	}

	for name, token := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := verifier.Verify(context.Background(), token)
			if !errors.Is(err, identity.ErrInvalidGoogleToken) {
				t.Fatalf("verify %s = %v, want ErrInvalidGoogleToken", name, err)
			}
		})
	}
}

// tamper swaps the payload for one claiming a different subject while keeping the
// original signature, which must no longer verify.
func tamper(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return token
	}
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(
		`{"iss":"https://accounts.google.com","aud":"` + testAudience +
			`","sub":"999999999999999999999","email":"victim@example.com","email_verified":true,"exp":99999999999}`))
	return strings.Join(parts, ".")
}

// An empty audience list would make idtoken skip the audience check entirely, so the
// verifier would accept any token Google ever signed for any application. Refusing
// to build is the only safe answer.
func TestVerifierRequiresAnAudience(t *testing.T) {
	_, client := newSigningFixture(t)
	for name, audiences := range map[string][]string{
		"nil":         nil,
		"empty slice": {},
		"blank entry": {"", "   "},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewVerifierWithHTTPClient(context.Background(), audiences, client); err == nil {
				t.Fatal("building a verifier without an audience must fail")
			}
		})
	}
}

// Both spellings are in circulation and Google has never committed to retiring
// either, so both must keep working.
func TestVerifierAcceptsBothIssuerSpellings(t *testing.T) {
	fixture, client := newSigningFixture(t)
	verifier := newTestVerifier(t, []string{testAudience}, client)

	for _, issuer := range []string{"accounts.google.com", "https://accounts.google.com"} {
		claims := validClaims()
		claims["iss"] = issuer
		if _, err := verifier.Verify(context.Background(), fixture.sign(t, claims)); err != nil {
			t.Fatalf("verify token issued by %q: %v", issuer, err)
		}
	}
}
