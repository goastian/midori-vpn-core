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
	fmt.Printf("TRANSPORT_TOKEN_AUTHORIZED_KEYS=<CONTROL_NODE_ID>=%s\n", encoding.EncodeToString(publicKey))
}
