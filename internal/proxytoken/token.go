package proxytoken

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	AudienceVPNProxy  = "vpn-proxy"
	AudienceVPNTunnel = "vpn-tunnel"
	DefaultTTL        = 15 * time.Minute
)

// Generate creates a cryptographically signed HMAC-SHA256 token scoped strictly
// to the VPN proxy (aud=vpn-proxy).
func Generate(userID uuid.UUID, secret string, ttl time.Duration) string {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	expiresAt := time.Now().Add(ttl).Unix()
	payload := fmt.Sprintf("%s:%d:%s", userID.String(), expiresAt, AudienceVPNProxy)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	return fmt.Sprintf("%s:%s", payload, sig)
}

// TunnelClaims binds a short-lived tunnel credential to one active device and server.
type TunnelClaims struct{ UserID, DeviceID, ServerID uuid.UUID }

func GenerateTunnel(claims TunnelClaims, secret string, ttl time.Duration) string {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	expiresAt := time.Now().Add(ttl).Unix()
	payload := fmt.Sprintf("%s:%s:%s:%s:%d", claims.UserID, claims.DeviceID, claims.ServerID, AudienceVPNTunnel, expiresAt)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return payload + ":" + hex.EncodeToString(mac.Sum(nil))
}

func ValidateTunnel(tokenStr, secret string) (TunnelClaims, bool) {
	parts := strings.Split(tokenStr, ":")
	if len(parts) != 6 || parts[3] != AudienceVPNTunnel {
		return TunnelClaims{}, false
	}
	userID, err1 := uuid.Parse(parts[0])
	deviceID, err2 := uuid.Parse(parts[1])
	serverID, err3 := uuid.Parse(parts[2])
	expiresAt, err4 := strconv.ParseInt(parts[4], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || time.Now().Unix() > expiresAt {
		return TunnelClaims{}, false
	}
	payload := strings.Join(parts[:5], ":")
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	if !hmac.Equal([]byte(parts[5]), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		return TunnelClaims{}, false
	}
	return TunnelClaims{UserID: userID, DeviceID: deviceID, ServerID: serverID}, true
}

// Validate verifies the signature, expiration, and audience of a proxy-scoped token.
// Returns the userID string and true if valid; otherwise ("", false).
func Validate(tokenStr string, secret string) (string, bool) {
	parts := strings.Split(tokenStr, ":")
	if len(parts) != 4 {
		return "", false
	}

	userIDStr := parts[0]
	expiresAtStr := parts[1]
	aud := parts[2]
	signature := parts[3]

	if aud != AudienceVPNProxy {
		return "", false
	}

	if _, err := uuid.Parse(userIDStr); err != nil {
		return "", false
	}

	expiresAt, err := strconv.ParseInt(expiresAtStr, 10, 64)
	if err != nil || time.Now().Unix() > expiresAt {
		return "", false
	}

	payload := fmt.Sprintf("%s:%s:%s", userIDStr, expiresAtStr, aud)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", false
	}

	return userIDStr, true
}
