package crypto_test

import (
	"encoding/base64"
	"testing"

	"github.com/goastian/midori-vpn-core/internal/crypto"
)

func TestMLKEM768_Roundtrip(t *testing.T) {
	// 1. Client generates ML-KEM-768 keypair
	clientKeypair, err := crypto.GenerateMLKEM768Keypair()
	if err != nil {
		t.Fatalf("GenerateMLKEM768Keypair failed: %v", err)
	}

	if clientKeypair.EncapsulationKeyB64 == "" {
		t.Fatal("EncapsulationKeyB64 is empty")
	}

	// 2. Server encapsulates shared key against client's public key
	serverSharedKeyB64, ciphertextB64, err := crypto.EncapsulateSharedKey(clientKeypair.EncapsulationKeyB64)
	if err != nil {
		t.Fatalf("EncapsulateSharedKey failed: %v", err)
	}

	serverSharedKeyBytes, err := base64.StdEncoding.DecodeString(serverSharedKeyB64)
	if err != nil {
		t.Fatalf("Decode serverSharedKeyB64 failed: %v", err)
	}
	if len(serverSharedKeyBytes) != 32 {
		t.Fatalf("Expected 32-byte shared key, got %d bytes", len(serverSharedKeyBytes))
	}

	// 3. Client decapsulates ciphertext using private key
	clientSharedKeyB64, err := crypto.DecapsulateSharedKey(clientKeypair.DecapsulationKey, ciphertextB64)
	if err != nil {
		t.Fatalf("DecapsulateSharedKey failed: %v", err)
	}

	// 4. Assert both sides share the exact same 32-byte post-quantum secret
	if serverSharedKeyB64 != clientSharedKeyB64 {
		t.Fatalf("Shared keys mismatch:\nserver: %s\nclient: %s", serverSharedKeyB64, clientSharedKeyB64)
	}
}

func TestMLKEM768_InvalidInputs(t *testing.T) {
	// Empty encapsulation key
	_, _, err := crypto.EncapsulateSharedKey("")
	if err == nil {
		t.Error("expected error for empty encapsulation key")
	}

	// Invalid base64 encapsulation key
	_, _, err = crypto.EncapsulateSharedKey("!invalid-base64!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}

	// Decapsulate with nil key
	_, err = crypto.DecapsulateSharedKey(nil, "abc")
	if err == nil {
		t.Error("expected error for nil decapsulation key")
	}

	// Decapsulate with invalid ciphertext
	keypair, _ := crypto.GenerateMLKEM768Keypair()
	_, err = crypto.DecapsulateSharedKey(keypair.DecapsulationKey, "invalid-ciphertext")
	if err == nil {
		t.Error("expected error for invalid ciphertext")
	}
}
