package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	identifierRandomLength = 18
	tokenRandomLength      = 32
	verificationCodeSpace  = 1_000_000
)

func issueIdentifier(random io.Reader, prefix string) (string, error) {
	return issueRandomValue(random, prefix, identifierRandomLength)
}

func issueToken(random io.Reader, prefix string) (string, error) {
	return issueRandomValue(random, prefix, tokenRandomLength)
}

func issueRandomValue(random io.Reader, prefix string, length int) (string, error) {
	value := make([]byte, length)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", fmt.Errorf("generate random value: %w", err)
	}
	return prefix + base64.RawURLEncoding.EncodeToString(value), nil
}

// issueVerificationCode returns a uniformly distributed six-digit code. Values at
// or above the largest multiple of the code space are rejected rather than folded,
// so no code is more likely than any other.
func issueVerificationCode(random io.Reader) (string, error) {
	const limit = uint32(math.MaxUint32 - (math.MaxUint32 % verificationCodeSpace))
	value := make([]byte, 4)
	for range 64 {
		if _, err := io.ReadFull(random, value); err != nil {
			return "", fmt.Errorf("generate verification code: %w", err)
		}
		drawn := binary.BigEndian.Uint32(value)
		if drawn < limit {
			return fmt.Sprintf("%06d", drawn%verificationCodeSpace), nil
		}
	}
	return "", errors.New("generate verification code: exhausted rejection sampling attempts")
}

func hashToken(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}

func defaultRandom() io.Reader {
	return rand.Reader
}
