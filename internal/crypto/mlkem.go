package crypto

import (
	"crypto/mlkem"
	"encoding/base64"
	"errors"
	"fmt"
)

// MLKEM768Keypair holds a private decapsulation key and public encapsulation key for ML-KEM-768 (Kyber-768).
type MLKEM768Keypair struct {
	DecapsulationKey    *mlkem.DecapsulationKey768
	EncapsulationKeyB64 string
}

// GenerateMLKEM768Keypair generates a new quantum-resistant ML-KEM-768 keypair per NIST FIPS 203.
func GenerateMLKEM768Keypair() (*MLKEM768Keypair, error) {
	decKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, fmt.Errorf("generate mlkem768 key: %w", err)
	}

	encBytes := decKey.EncapsulationKey().Bytes()
	return &MLKEM768Keypair{
		DecapsulationKey:    decKey,
		EncapsulationKeyB64: base64.StdEncoding.EncodeToString(encBytes),
	}, nil
}

// EncapsulateSharedKey performs ML-KEM-768 encapsulation against a public encapsulation key (in base64).
// It returns a 32-byte shared secret (base64) and the ciphertext (base64) that must be sent to the peer.
func EncapsulateSharedKey(encapsulationKeyB64 string) (string, string, error) {
	if encapsulationKeyB64 == "" {
		return "", "", errors.New("empty encapsulation key")
	}

	encBytes, err := base64.StdEncoding.DecodeString(encapsulationKeyB64)
	if err != nil {
		return "", "", fmt.Errorf("decode encapsulation key: %w", err)
	}

	encKey, err := mlkem.NewEncapsulationKey768(encBytes)
	if err != nil {
		return "", "", fmt.Errorf("invalid mlkem768 encapsulation key: %w", err)
	}

	sharedKey, ciphertext := encKey.Encapsulate()

	return base64.StdEncoding.EncodeToString(sharedKey), base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecapsulateSharedKey decapsulates the ciphertext using the private DecapsulationKey768.
// It returns the exact 32-byte shared secret (base64) for WireGuard PSK.
func DecapsulateSharedKey(decKey *mlkem.DecapsulationKey768, ciphertextB64 string) (string, error) {
	if decKey == nil {
		return "", errors.New("nil decapsulation key")
	}
	if ciphertextB64 == "" {
		return "", errors.New("empty ciphertext")
	}

	ctBytes, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}

	sharedKey, err := decKey.Decapsulate(ctBytes)
	if err != nil {
		return "", fmt.Errorf("mlkem768 decapsulation failed: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sharedKey), nil
}
