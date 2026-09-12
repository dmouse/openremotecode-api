package identity

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	defaultArgonTime        = 3
	defaultArgonMemory      = 64 * 1024
	defaultArgonParallelism = 4
	defaultSaltLength       = 16
	defaultKeyLength        = 32
	defaultConcurrentHashes = 4
	maximumStoredMemory     = 256 * 1024
)

type PasswordHasher struct {
	time        uint32
	memory      uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
	random      io.Reader
	workers     chan struct{}
}

func NewPasswordHasher() PasswordHasher {
	return newPasswordHasher(
		defaultArgonTime,
		defaultArgonMemory,
		defaultArgonParallelism,
		defaultSaltLength,
		defaultKeyLength,
		rand.Reader,
		defaultConcurrentHashes,
	)
}

func newPasswordHasher(
	timeCost uint32,
	memory uint32,
	parallelism uint8,
	saltLength uint32,
	keyLength uint32,
	random io.Reader,
	maximumConcurrent int,
) PasswordHasher {
	return PasswordHasher{
		time:        timeCost,
		memory:      memory,
		parallelism: parallelism,
		saltLength:  saltLength,
		keyLength:   keyLength,
		random:      random,
		workers:     make(chan struct{}, maximumConcurrent),
	}
}

func (hasher PasswordHasher) Hash(ctx context.Context, password string) (string, error) {
	if err := hasher.acquire(ctx); err != nil {
		return "", err
	}
	defer hasher.release()
	salt := make([]byte, hasher.saltLength)
	if _, err := io.ReadFull(hasher.random, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey(
		[]byte(password),
		salt,
		hasher.time,
		hasher.memory,
		hasher.parallelism,
		hasher.keyLength,
	)
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		hasher.memory,
		hasher.time,
		hasher.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func (hasher PasswordHasher) Verify(
	ctx context.Context,
	password,
	encodedHash string,
) (bool, error) {
	parameters, salt, expectedKey, err := parsePasswordHash(encodedHash)
	if err != nil {
		return false, err
	}
	if err := hasher.acquire(ctx); err != nil {
		return false, err
	}
	defer hasher.release()
	actualKey := argon2.IDKey(
		[]byte(password),
		salt,
		parameters.time,
		parameters.memory,
		parameters.parallelism,
		uint32(len(expectedKey)),
	)
	return subtle.ConstantTimeCompare(actualKey, expectedKey) == 1, nil
}

func (hasher PasswordHasher) acquire(ctx context.Context) error {
	select {
	case hasher.workers <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (hasher PasswordHasher) release() {
	<-hasher.workers
}

type argonParameters struct {
	time        uint32
	memory      uint32
	parallelism uint8
}

func parsePasswordHash(encodedHash string) (argonParameters, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return argonParameters{}, nil, nil, errors.New("invalid password hash format")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return argonParameters{}, nil, nil, errors.New("invalid password hash version")
	}
	var parameters argonParameters
	if _, err := fmt.Sscanf(
		parts[3],
		"m=%d,t=%d,p=%d",
		&parameters.memory,
		&parameters.time,
		&parameters.parallelism,
	); err != nil ||
		parameters.memory < 8*1024 || parameters.memory > maximumStoredMemory ||
		parameters.time == 0 || parameters.time > 10 ||
		parameters.parallelism == 0 || parameters.parallelism > 32 {
		return argonParameters{}, nil, nil, errors.New("invalid password hash parameters")
	}

	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return argonParameters{}, nil, nil, errors.New("invalid password hash salt")
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(key) < 16 || len(key) > 64 {
		return argonParameters{}, nil, nil, errors.New("invalid password hash key")
	}
	return parameters, salt, key, nil
}
