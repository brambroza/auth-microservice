// Package secret holds small cryptographic helpers: encryption at rest for
// secrets kept in the database, random tokens, and token hashing.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// Box encrypts values with AES-256-GCM under the service master key.
type Box struct{ aead cipher.AEAD }

func NewBox(key []byte) (*Box, error) {
	if len(key) != 32 {
		return nil, errors.New("secret: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Seal returns nonce || ciphertext. context binds the ciphertext to its use
// (for example "totp:<user id>") so it cannot be swapped between rows.
func (b *Box) Seal(plaintext []byte, context string) []byte {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return b.aead.Seal(nonce, nonce, plaintext, []byte(context))
}

func (b *Box) Open(sealed []byte, context string) ([]byte, error) {
	n := b.aead.NonceSize()
	if len(sealed) < n {
		return nil, errors.New("secret: ciphertext too short")
	}
	return b.aead.Open(nil, sealed[:n], sealed[n:], []byte(context))
}

// NewToken returns a 256-bit random token, URL-safe.
func NewToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Hash is used for high-entropy random tokens only (refresh tokens, challenge
// tokens, recovery codes). Passwords go through the password package instead.
func Hash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}
