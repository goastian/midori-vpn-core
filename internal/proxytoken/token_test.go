package proxytoken

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestProxyToken_GenerateAndValidate(t *testing.T) {
	secret := "super-secure-secret-for-proxy-token-testing-12345"
	userID := uuid.New()

	token := Generate(userID, secret, 5*time.Minute)
	assert.NotEmpty(t, token)

	extractedUser, ok := Validate(token, secret)
	assert.True(t, ok)
	assert.Equal(t, userID.String(), extractedUser)

	// Tampered signature
	tampered := token + "evil"
	_, ok = Validate(tampered, secret)
	assert.False(t, ok)

	// Wrong secret
	_, ok = Validate(token, "wrong-secret")
	assert.False(t, ok)

	// Expired token
	expiredToken := Generate(userID, secret, -1*time.Minute)
	_, ok = Validate(expiredToken, secret)
	assert.False(t, ok)
}

func TestTunnelTokenBindsDeviceAndServer(t *testing.T) {
	claims := TunnelClaims{UserID: uuid.New(), DeviceID: uuid.New(), ServerID: uuid.New()}
	token := GenerateTunnel(claims, "secret", time.Minute)
	got, ok := ValidateTunnel(token, "secret")
	assert.True(t, ok)
	assert.Equal(t, claims, got)
	_, ok = ValidateTunnel(token, "other")
	assert.False(t, ok)
}
