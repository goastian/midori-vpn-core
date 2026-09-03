package dataencryption

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func testCipher(t *testing.T) *Cipher {
	t.Helper()
	cipher, err := New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return cipher
}

func TestPresharedKeyRoundTripUsesUniqueNonce(t *testing.T) {
	cipher := testCipher(t)
	recordID := uuid.New()
	first, version, err := cipher.SealPresharedKey(PeerPresharedKey, recordID, "test-preshared-key")
	if err != nil {
		t.Fatalf("SealPresharedKey: %v", err)
	}
	second, _, err := cipher.SealPresharedKey(PeerPresharedKey, recordID, "test-preshared-key")
	if err != nil {
		t.Fatalf("SealPresharedKey second: %v", err)
	}
	if string(first) == string(second) {
		t.Fatal("two encryptions reused the same nonce")
	}
	plaintext, err := cipher.OpenPresharedKey(PeerPresharedKey, recordID, version, first)
	if err != nil || plaintext != "test-preshared-key" {
		t.Fatalf("OpenPresharedKey = %q, %v", plaintext, err)
	}
}

func TestPresharedKeyAuthenticationBindsScopeAndRecord(t *testing.T) {
	cipher := testCipher(t)
	recordID := uuid.New()
	value, version, err := cipher.SealPresharedKey(PeerPresharedKey, recordID, "secret-value")
	if err != nil {
		t.Fatalf("SealPresharedKey: %v", err)
	}

	for _, test := range []struct {
		name    string
		scope   Scope
		id      uuid.UUID
		version int16
		tamper  bool
	}{
		{name: "tampered", scope: PeerPresharedKey, id: recordID, version: version, tamper: true},
		{name: "wrong scope", scope: PeerOperationPresharedKey, id: recordID, version: version},
		{name: "wrong row", scope: PeerPresharedKey, id: uuid.New(), version: version},
		{name: "wrong version", scope: PeerPresharedKey, id: recordID, version: version + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := append([]byte(nil), value...)
			if test.tamper {
				candidate[len(candidate)-1] ^= 1
			}
			_, err := cipher.OpenPresharedKey(test.scope, test.id, test.version, candidate)
			if err == nil || strings.Contains(err.Error(), "secret-value") {
				t.Fatalf("OpenPresharedKey error = %v", err)
			}
		})
	}
}

func TestParseKeyRequiresCanonicalBase64AndExactLength(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	key, err := ParseKey(valid)
	if err != nil || len(key) != 32 {
		t.Fatalf("ParseKey(valid) = %d bytes, %v", len(key), err)
	}
	for _, invalid := range []string{"", "not-base64", base64.RawStdEncoding.EncodeToString(key), base64.StdEncoding.EncodeToString(key[:31])} {
		if _, err := ParseKey(invalid); !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("ParseKey(%q) error = %v", invalid, err)
		}
	}
}

func TestEmptyPresharedKeyDoesNotCreateCiphertext(t *testing.T) {
	value, version, err := (*Cipher)(nil).SealPresharedKey(PeerPresharedKey, uuid.New(), "")
	if err != nil || value != nil || version != 0 {
		t.Fatalf("empty SealPresharedKey = %x, %d, %v", value, version, err)
	}
}
