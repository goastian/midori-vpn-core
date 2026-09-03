package repo

import (
	"errors"
	"fmt"

	"github.com/goastian/midori-vpn-core/internal/dataencryption"
	"github.com/google/uuid"
)

func sealStoredPresharedKey(cipher *dataencryption.Cipher, scope dataencryption.Scope, recordID uuid.UUID, plaintext string) ([]byte, int16, error) {
	if plaintext == "" {
		return nil, 0, nil
	}
	if cipher == nil {
		return nil, 0, dataencryption.ErrUnavailable
	}
	return cipher.SealPresharedKey(scope, recordID, plaintext)
}

func openStoredPresharedKey(cipher *dataencryption.Cipher, scope dataencryption.Scope, recordID uuid.UUID, legacy string, ciphertext []byte, version int16) (string, error) {
	if len(ciphertext) == 0 {
		return legacy, nil
	}
	if legacy != "" {
		return "", errors.New("PSK has multiple stored representations")
	}
	if cipher == nil {
		return "", dataencryption.ErrUnavailable
	}
	plaintext, err := cipher.OpenPresharedKey(scope, recordID, version, ciphertext)
	if err != nil {
		return "", fmt.Errorf("open stored PSK: %w", err)
	}
	return plaintext, nil
}

func nullableEncryptionVersion(version int16) any {
	if version == 0 {
		return nil
	}
	return version
}
