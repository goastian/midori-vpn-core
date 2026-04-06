package crypto

import (
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/curve25519"
)

type Keypair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// String implements fmt.Stringer to prevent accidental logging of private keys.
func (kp *Keypair) String() string {
	return "Keypair{pub=" + kp.PublicKey + "}"
}

func GenerateKeypair() (*Keypair, error) {
	var privKey [32]byte
	if _, err := rand.Read(privKey[:]); err != nil {
		return nil, err
	}

	// Clamp private key per WireGuard/Curve25519 spec
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	pubKey, err := curve25519.X25519(privKey[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	return &Keypair{
		PrivateKey: base64.StdEncoding.EncodeToString(privKey[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(pubKey),
	}, nil
}
