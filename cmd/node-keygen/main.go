package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
)

func main() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate Ed25519 identity: %v", err)
	}
	encoding := base64.RawURLEncoding
	fmt.Printf("CONTROL_NODE_PRIVATE_KEY=%s\n", encoding.EncodeToString(privateKey))
	fmt.Printf("CONTROL_NODE_PUBLIC_KEY=%s\n", encoding.EncodeToString(publicKey))
	credentialSecret := make([]byte, 64)
	if _, err := rand.Read(credentialSecret); err != nil {
		log.Fatalf("generate credential signing secret: %v", err)
	}
	fmt.Printf("CREDENTIAL_SIGNING_SECRET=%s\n", encoding.EncodeToString(credentialSecret))
}
