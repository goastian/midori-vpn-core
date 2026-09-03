// Package dataencryption protects recoverable application data before it is
// persisted in PostgreSQL.
package dataencryption

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/chacha20poly1305"
)

const CurrentVersion int16 = 1

type Scope string

const (
	PeerPresharedKey          Scope = "peers:preshared_key"
	PeerOperationPresharedKey Scope = "peer_operations:preshared_key"
	MeshMemberPresharedKey    Scope = "mesh_members:preshared_key"
)

var (
	ErrInvalidKey         = errors.New("data encryption key must be canonical base64 encoding of exactly 32 bytes")
	ErrUnavailable        = errors.New("data encryption is unavailable")
	ErrInvalidCiphertext  = errors.New("encrypted data failed authentication")
	ErrUnsupportedVersion = errors.New("encrypted data version is unsupported")
)

type Cipher struct {
	aead interface {
		NonceSize() int
		Overhead() int
		Seal([]byte, []byte, []byte, []byte) []byte
		Open([]byte, []byte, []byte, []byte) ([]byte, error)
	}
}

func ParseKey(encoded string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != chacha20poly1305.KeySize || base64.StdEncoding.EncodeToString(decoded) != encoded {
		return nil, ErrInvalidKey
	}
	return decoded, nil
}

func New(key []byte) (*Cipher, error) {
	if len(key) != chacha20poly1305.KeySize {
		return nil, ErrInvalidKey
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("initialize data encryption: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

func (c *Cipher) SealPresharedKey(scope Scope, recordID uuid.UUID, plaintext string) ([]byte, int16, error) {
	if plaintext == "" {
		return nil, 0, nil
	}
	if c == nil || c.aead == nil {
		return nil, 0, ErrUnavailable
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, 0, fmt.Errorf("generate data encryption nonce: %w", err)
	}
	sealed := c.aead.Seal(nil, nonce, []byte(plaintext), additionalData(scope, recordID))
	value := make([]byte, 0, len(nonce)+len(sealed))
	value = append(value, nonce...)
	value = append(value, sealed...)
	return value, CurrentVersion, nil
}

func (c *Cipher) OpenPresharedKey(scope Scope, recordID uuid.UUID, version int16, ciphertext []byte) (string, error) {
	if c == nil || c.aead == nil {
		return "", ErrUnavailable
	}
	if version != CurrentVersion {
		return "", ErrUnsupportedVersion
	}
	if len(ciphertext) < c.aead.NonceSize()+c.aead.Overhead() {
		return "", ErrInvalidCiphertext
	}
	nonce := ciphertext[:c.aead.NonceSize()]
	sealed := ciphertext[c.aead.NonceSize():]
	plaintext, err := c.aead.Open(nil, nonce, sealed, additionalData(scope, recordID))
	if err != nil {
		return "", ErrInvalidCiphertext
	}
	return string(plaintext), nil
}

func additionalData(scope Scope, recordID uuid.UUID) []byte {
	return []byte("midorivpn:data:v1:" + string(scope) + ":" + recordID.String())
}
