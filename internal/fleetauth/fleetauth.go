// Package fleetauth authenticates Core node requests to the central Control
// plane. Its signature domain is deliberately distinct from nodeauth, which
// authenticates Control requests in the opposite direction.
package fleetauth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

const (
	HeaderNodeID    = "X-Node-ID"
	HeaderTimestamp = "X-Node-Timestamp"
	HeaderNonce     = "X-Node-Nonce"
	HeaderSignature = "X-Node-Signature"

	signatureDomain = "midorivpn-node-control-v1"
	maxClockSkew    = 30 * time.Second
	nonceTTL        = 2 * time.Minute
)

var ErrReplayProtectionUnavailable = errors.New("node replay protection is unavailable")

type ReplayStore interface {
	Use(context.Context, uuid.UUID, string, time.Duration) (bool, error)
}

type Verifier struct {
	replays ReplayStore
	now     func() time.Time
}

func NewVerifier(replays ReplayStore) *Verifier {
	return &Verifier{replays: replays, now: time.Now}
}

func (v *Verifier) Verify(ctx context.Context, req *http.Request, body []byte, nodeID uuid.UUID, publicKey ed25519.PublicKey) error {
	if v == nil || v.replays == nil {
		return ErrReplayProtectionUnavailable
	}
	if nodeID == uuid.Nil || len(publicKey) != ed25519.PublicKeySize || req.Header.Get(HeaderNodeID) != nodeID.String() {
		return errors.New("node identity does not match the signed request")
	}
	timestamp := req.Header.Get(HeaderTimestamp)
	requestTimeUnix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || strconv.FormatInt(requestTimeUnix, 10) != timestamp {
		return errors.New("invalid node timestamp")
	}
	requestTime := time.Unix(requestTimeUnix, 0)
	if delta := v.now().UTC().Sub(requestTime); delta < -maxClockSkew || delta > maxClockSkew {
		return errors.New("node request timestamp is outside the allowed window")
	}
	nonce := req.Header.Get(HeaderNonce)
	if _, err := decodeCanonicalRawURL(nonce, 18); err != nil {
		return errors.New("invalid node nonce")
	}
	signature, err := decodeCanonicalRawURL(req.Header.Get(HeaderSignature), ed25519.SignatureSize)
	if err != nil {
		return errors.New("invalid node signature encoding")
	}
	message := canonicalMessage(nodeID, req.Method, requestTarget(req), body, timestamp, nonce)
	if !ed25519.Verify(publicKey, []byte(message), signature) {
		return errors.New("node signature verification failed")
	}
	accepted, err := v.replays.Use(ctx, nodeID, nonce, nonceTTL)
	if err != nil {
		return fmt.Errorf("%w: persist node nonce", ErrReplayProtectionUnavailable)
	}
	if !accepted {
		return errors.New("node request replay detected")
	}
	return nil
}

func signRequest(req *http.Request, body []byte, nodeID uuid.UUID, privateKey ed25519.PrivateKey, now time.Time) error {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("generate node request nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	timestamp := strconv.FormatInt(now.UTC().Unix(), 10)
	message := canonicalMessage(nodeID, req.Method, requestTarget(req), body, timestamp, nonce)
	req.Header.Set(HeaderNodeID, nodeID.String())
	req.Header.Set(HeaderTimestamp, timestamp)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(message))))
	return nil
}

func requestTarget(req *http.Request) string {
	target := req.URL.EscapedPath()
	if target == "" {
		target = "/"
	}
	if req.URL.RawQuery != "" {
		target += "?" + req.URL.RawQuery
	}
	return target
}

func canonicalMessage(nodeID uuid.UUID, method, target string, body []byte, timestamp, nonce string) string {
	digest := sha256.Sum256(body)
	return strings.Join([]string{
		signatureDomain,
		nodeID.String(),
		strings.ToUpper(method),
		target,
		hex.EncodeToString(digest[:]),
		timestamp,
		nonce,
	}, "\n")
}

func decodeCanonicalRawURL(value string, size int) ([]byte, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return nil, errors.New("non-canonical base64url")
	}
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != size || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, errors.New("non-canonical base64url")
	}
	return raw, nil
}

func DecodePublicKey(value string) (ed25519.PublicKey, error) {
	raw, err := decodeCanonicalRawURL(value, ed25519.PublicKeySize)
	if err != nil {
		return nil, errors.New("public key must be canonical base64url Ed25519")
	}
	return ed25519.PublicKey(raw), nil
}

type RedisReplayStore struct {
	client *redis.Client
}

func NewRedisReplayStore(client *redis.Client) *RedisReplayStore {
	return &RedisReplayStore{client: client}
}

func (s *RedisReplayStore) Use(ctx context.Context, nodeID uuid.UUID, nonce string, ttl time.Duration) (bool, error) {
	if s == nil || s.client == nil {
		return false, errors.New("redis replay store is unavailable")
	}
	return s.client.SetNX(ctx, "fleet-auth:nonce:"+nodeID.String()+":"+nonce, "1", ttl).Result()
}

type MemoryReplayStore struct {
	mu     sync.Mutex
	now    func() time.Time
	nonces map[string]time.Time
}

func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{now: time.Now, nonces: make(map[string]time.Time)}
}

func (s *MemoryReplayStore) Use(_ context.Context, nodeID uuid.UUID, nonce string, ttl time.Duration) (bool, error) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, expiresAt := range s.nonces {
		if !expiresAt.After(now) {
			delete(s.nonces, key)
		}
	}
	key := nodeID.String() + ":" + nonce
	if _, exists := s.nonces[key]; exists {
		return false, nil
	}
	s.nonces[key] = now.Add(ttl)
	return true, nil
}
