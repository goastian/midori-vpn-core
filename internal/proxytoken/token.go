// Package proxytoken implements the compact mvpn2 transport credential used by
// browser proxy, WSS and MASQUE gateways. Despite the historical package name,
// production credentials are Ed25519 signatures and never shared-secret MACs.
package proxytoken

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	AudienceVPNProxy  = "vpn-proxy"
	AudienceVPNTunnel = "vpn-tunnel"
	DefaultTTL        = 15 * time.Minute

	tokenPrefix     = "mvpn2"
	signatureDomain = "midorivpn-transport-credential-v2"
	maxTokenSize    = 4096
	clockSkew       = 30 * time.Second
)

var (
	ErrInvalidToken       = errors.New("transport credential is invalid")
	ErrInvalidSignature   = errors.New("transport credential signature is invalid")
	ErrUntrustedKey       = errors.New("transport credential signing key is not trusted")
	ErrExpired            = errors.New("transport credential is expired")
	ErrNotYetValid        = errors.New("transport credential is not yet valid")
	ErrWrongIssuer        = errors.New("transport credential issuer is invalid")
	ErrWrongAudience      = errors.New("transport credential audience is invalid")
	ErrWrongServer        = errors.New("transport credential server is invalid")
	ErrWrongCluster       = errors.New("transport credential cluster is invalid")
	ErrLegacyNotPermitted = errors.New("legacy HMAC transport credentials are disabled")
)

var keyIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Claims is the complete signed authorization. Field order is part of the
// canonical mvpn2 JSON representation and therefore must remain stable.
type Claims struct {
	KeyID      string    `json:"kid"`
	Issuer     string    `json:"iss"`
	Audience   string    `json:"aud"`
	UserID     uuid.UUID `json:"user"`
	DeviceID   uuid.UUID `json:"device"`
	ServerID   uuid.UUID `json:"server"`
	ClusterID  uuid.UUID `json:"cluster"`
	IssuedAt   int64     `json:"iat"`
	ExpiresAt  int64     `json:"exp"`
	TokenID    uuid.UUID `json:"jti"`
	LegacyHMAC bool      `json:"-"`
}

type Signer struct {
	keyID      string
	issuer     string
	privateKey ed25519.PrivateKey
	now        func() time.Time
}

func NewSigner(keyID, issuer, encodedPrivateKey string) (*Signer, error) {
	if !keyIDPattern.MatchString(keyID) || !validIssuer(issuer) {
		return nil, errors.New("transport credential key ID or issuer is invalid")
	}
	privateKey, err := parsePrivateKey(encodedPrivateKey)
	if err != nil {
		return nil, err
	}
	return &Signer{keyID: keyID, issuer: issuer, privateKey: privateKey, now: time.Now}, nil
}

func (s *Signer) PublicKey() ed25519.PublicKey {
	if s == nil || len(s.privateKey) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), s.privateKey.Public().(ed25519.PublicKey)...)
}

func (s *Signer) Issue(audience string, userID, deviceID, serverID, clusterID uuid.UUID, ttl time.Duration) (string, error) {
	if s == nil || len(s.privateKey) != ed25519.PrivateKeySize {
		return "", errors.New("transport credential signer is unavailable")
	}
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if ttl <= 0 || ttl > DefaultTTL || !validAudience(audience) ||
		userID == uuid.Nil || deviceID == uuid.Nil || serverID == uuid.Nil || clusterID == uuid.Nil {
		return "", ErrInvalidToken
	}
	now := s.now().UTC().Truncate(time.Second)
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate transport credential identifier: %w", err)
	}
	claims := Claims{
		KeyID: s.keyID, Issuer: s.issuer, Audience: audience,
		UserID: userID, DeviceID: deviceID, ServerID: serverID, ClusterID: clusterID,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix(), TokenID: tokenID,
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encode transport credential: %w", err)
	}
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signature := ed25519.Sign(s.privateKey, signatureMessage(encodedPayload))
	return tokenPrefix + "." + encodedPayload + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

type Verifier struct {
	issuer       string
	keys         map[string]ed25519.PublicKey
	allowLegacy  bool
	legacySecret string
	now          func() time.Time
}

// NewVerifier builds an asymmetric verifier. Legacy HMAC is accepted only
// when allowLegacy is explicitly true; configuration rejects that mode outside
// development before this constructor is reached.
func NewVerifier(issuer, encodedKeys string, allowLegacy bool, legacySecret string) (*Verifier, error) {
	if !validIssuer(issuer) {
		return nil, errors.New("transport credential issuer is invalid")
	}
	keys, err := parsePublicKeys(encodedKeys)
	if err != nil {
		return nil, err
	}
	if allowLegacy && strings.TrimSpace(legacySecret) == "" {
		return nil, errors.New("legacy HMAC transport credentials require a secret")
	}
	return &Verifier{issuer: issuer, keys: keys, allowLegacy: allowLegacy, legacySecret: legacySecret, now: time.Now}, nil
}

func (v *Verifier) Trusts(keyID string, publicKey ed25519.PublicKey) bool {
	return v != nil && len(publicKey) == ed25519.PublicKeySize && bytes.Equal(v.keys[keyID], publicKey)
}

// Verify authenticates and binds a token to the exact gateway scope. A token
// beginning with mvpn2 never falls back to legacy HMAC after a failed check.
func (v *Verifier) Verify(token, audience string, serverID, clusterID uuid.UUID) (Claims, error) {
	if v == nil || !validAudience(audience) || serverID == uuid.Nil || clusterID == uuid.Nil || len(token) == 0 || len(token) > maxTokenSize {
		return Claims{}, ErrInvalidToken
	}
	if !strings.HasPrefix(token, tokenPrefix+".") {
		if !v.allowLegacy {
			return Claims{}, ErrLegacyNotPermitted
		}
		return v.verifyLegacy(token, audience, serverID, clusterID)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != tokenPrefix {
		return Claims{}, ErrInvalidToken
	}
	payload, err := decodeCanonicalRawURL(parts[1], 1, 2048)
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	var claims Claims
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claims); err != nil {
		return Claims{}, ErrInvalidToken
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Claims{}, ErrInvalidToken
	}
	canonical, err := json.Marshal(claims)
	if err != nil || !bytes.Equal(payload, canonical) || !validClaims(claims) {
		return Claims{}, ErrInvalidToken
	}
	publicKey := v.keys[claims.KeyID]
	if len(publicKey) != ed25519.PublicKeySize {
		return Claims{}, ErrUntrustedKey
	}
	signature, err := decodeCanonicalRawURL(parts[2], ed25519.SignatureSize, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(publicKey, signatureMessage(parts[1]), signature) {
		return Claims{}, ErrInvalidSignature
	}
	if claims.Issuer != v.issuer {
		return Claims{}, ErrWrongIssuer
	}
	if claims.Audience != audience {
		return Claims{}, ErrWrongAudience
	}
	if claims.ServerID != serverID {
		return Claims{}, ErrWrongServer
	}
	if claims.ClusterID != clusterID {
		return Claims{}, ErrWrongCluster
	}
	now := v.now().UTC().Unix()
	if claims.IssuedAt > now+int64(clockSkew/time.Second) {
		return Claims{}, ErrNotYetValid
	}
	if claims.ExpiresAt <= now {
		return Claims{}, ErrExpired
	}
	return claims, nil
}

func validClaims(claims Claims) bool {
	return keyIDPattern.MatchString(claims.KeyID) && validIssuer(claims.Issuer) && validAudience(claims.Audience) &&
		claims.UserID != uuid.Nil && claims.DeviceID != uuid.Nil && claims.ServerID != uuid.Nil && claims.ClusterID != uuid.Nil && claims.TokenID != uuid.Nil &&
		claims.IssuedAt > 0 && claims.ExpiresAt > claims.IssuedAt && claims.ExpiresAt-claims.IssuedAt <= int64(DefaultTTL/time.Second)
}

func validIssuer(issuer string) bool {
	return issuer == strings.TrimSpace(issuer) && len(issuer) >= 1 && len(issuer) <= 256
}

func validAudience(audience string) bool {
	return audience == AudienceVPNProxy || audience == AudienceVPNTunnel
}

func signatureMessage(encodedPayload string) []byte {
	return []byte(signatureDomain + "\n" + tokenPrefix + "." + encodedPayload)
}

func parsePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, err := decodeBase64(strings.TrimSpace(encoded))
	if err != nil {
		return nil, errors.New("transport credential private key is invalid")
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		if !bytes.Equal(raw, ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])) {
			return nil, errors.New("transport credential private key is inconsistent")
		}
		return append(ed25519.PrivateKey(nil), raw...), nil
	default:
		return nil, errors.New("transport credential private key has an invalid size")
	}
}

func parsePublicKeys(encoded string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey)
	for _, entry := range strings.Split(encoded, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		keyID, encodedKey, ok := strings.Cut(entry, "=")
		keyID = strings.TrimSpace(keyID)
		if !ok || !keyIDPattern.MatchString(keyID) || keys[keyID] != nil {
			return nil, errors.New("transport credential trust entries must use unique key-id=base64-public-key values")
		}
		raw, err := decodeBase64(strings.TrimSpace(encodedKey))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("transport credential trust entry contains an invalid Ed25519 key")
		}
		keys[keyID] = append(ed25519.PublicKey(nil), raw...)
	}
	if len(keys) == 0 {
		return nil, errors.New("at least one transport credential public key is required")
	}
	return keys, nil
}

func decodeBase64(encoded string) ([]byte, error) {
	if decoded, err := base64.RawURLEncoding.DecodeString(encoded); err == nil {
		return decoded, nil
	}
	return base64.StdEncoding.DecodeString(encoded)
}

func decodeCanonicalRawURL(encoded string, minimum, maximum int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, ErrInvalidToken
	}
	return decoded, nil
}

// GenerateLegacyProxy and GenerateLegacyTunnel exist solely for explicit
// development compatibility tests. Production code must call Signer.Issue.
func GenerateLegacyProxy(userID uuid.UUID, secret string, ttl time.Duration) string {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	expiresAt := time.Now().Add(ttl).Unix()
	payload := fmt.Sprintf("%s:%d:%s", userID, expiresAt, AudienceVPNProxy)
	return payload + ":" + legacyMAC(payload, secret)
}

func GenerateLegacyTunnel(claims Claims, secret string, ttl time.Duration) string {
	if ttl == 0 {
		ttl = DefaultTTL
	}
	payload := fmt.Sprintf("%s:%s:%s:%s:%d", claims.UserID, claims.DeviceID, claims.ServerID, AudienceVPNTunnel, time.Now().Add(ttl).Unix())
	return payload + ":" + legacyMAC(payload, secret)
}

func (v *Verifier) verifyLegacy(token, audience string, serverID, clusterID uuid.UUID) (Claims, error) {
	parts := strings.Split(token, ":")
	var expiresIndex int
	switch audience {
	case AudienceVPNProxy:
		if len(parts) != 4 || parts[2] != audience {
			return Claims{}, ErrInvalidToken
		}
		expiresIndex = 1
	case AudienceVPNTunnel:
		if len(parts) != 6 || parts[3] != audience {
			return Claims{}, ErrInvalidToken
		}
		expiresIndex = 4
	default:
		return Claims{}, ErrInvalidToken
	}
	expiresAt, err := strconv.ParseInt(parts[expiresIndex], 10, 64)
	if err != nil || expiresAt <= v.now().Unix() {
		return Claims{}, ErrExpired
	}
	payload := strings.Join(parts[:len(parts)-1], ":")
	if !hmac.Equal([]byte(parts[len(parts)-1]), []byte(legacyMAC(payload, v.legacySecret))) {
		return Claims{}, ErrInvalidSignature
	}
	userID, err := uuid.Parse(parts[0])
	if err != nil {
		return Claims{}, ErrInvalidToken
	}
	claims := Claims{Issuer: v.issuer, Audience: audience, UserID: userID, ServerID: serverID, ClusterID: clusterID, ExpiresAt: expiresAt, LegacyHMAC: true}
	if audience == AudienceVPNTunnel {
		deviceID, deviceErr := uuid.Parse(parts[1])
		tokenServerID, serverErr := uuid.Parse(parts[2])
		if deviceErr != nil || serverErr != nil || tokenServerID != serverID {
			return Claims{}, ErrWrongServer
		}
		claims.DeviceID = deviceID
	}
	return claims, nil
}

func legacyMAC(payload, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
