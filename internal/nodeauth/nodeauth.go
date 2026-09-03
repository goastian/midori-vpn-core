package nodeauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goastian/midori-vpn-core/internal/respond"
	"github.com/goastian/midori-vpn-core/internal/telemetry"
	"github.com/redis/go-redis/v9"
)

const (
	HeaderNodeID    = "X-Node-ID"
	HeaderTimestamp = "X-Node-Timestamp"
	HeaderNonce     = "X-Node-Nonce"
	HeaderSignature = "X-Node-Signature"

	maxClockSkew = 30 * time.Second
	nonceTTL     = 2 * time.Minute
	maxBodySize  = 1 << 20
)

var (
	ErrReplayDetected              = errors.New("node request replay detected")
	ErrReplayProtectionUnavailable = errors.New("node replay protection is unavailable")
)

type Signer struct {
	nodeID     string
	privateKey ed25519.PrivateKey
	now        func() time.Time
}

func NewSigner(nodeID, encodedPrivateKey string) (*Signer, error) {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || strings.ContainsAny(nodeID, "\r\n:") {
		return nil, fmt.Errorf("invalid CONTROL_NODE_ID")
	}
	raw, err := decodeBase64(encodedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decode CONTROL_NODE_PRIVATE_KEY: %w", err)
	}
	var privateKey ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		privateKey = ed25519.PrivateKey(append([]byte(nil), raw...))
	default:
		return nil, fmt.Errorf("CONTROL_NODE_PRIVATE_KEY must decode to %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
	return &Signer{nodeID: nodeID, privateKey: privateKey, now: time.Now}, nil
}

func (s *Signer) PublicKey() string {
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	return base64.RawURLEncoding.EncodeToString(publicKey)
}

func (s *Signer) Sign(req *http.Request, body []byte) error {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("generate request nonce: %w", err)
	}
	timestamp := strconv.FormatInt(s.now().UTC().Unix(), 10)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	message := canonicalMessage(req.Method, requestTarget(req), body, timestamp, nonce)
	signature := ed25519.Sign(s.privateKey, []byte(message))
	req.Header.Set(HeaderNodeID, s.nodeID)
	req.Header.Set(HeaderTimestamp, timestamp)
	req.Header.Set(HeaderNonce, nonce)
	req.Header.Set(HeaderSignature, base64.RawURLEncoding.EncodeToString(signature))
	return nil
}

type Verifier struct {
	keys       map[string]ed25519.PublicKey
	revoked    map[string]struct{}
	redis      *redis.Client
	now        func() time.Time
	mu         sync.Mutex
	seenNonces map[string]time.Time
}

type RegisteredIdentity struct {
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
	Revoked   bool   `json:"revoked"`
	Source    string `json:"source"`
}

func NewVerifier(encodedKeys, revokedIDs, redisURL string) (*Verifier, error) {
	keys, err := parsePublicKeys(encodedKeys)
	if err != nil {
		return nil, err
	}
	revoked := make(map[string]struct{})
	for _, nodeID := range strings.Split(revokedIDs, ",") {
		if nodeID = strings.TrimSpace(nodeID); nodeID != "" {
			revoked[nodeID] = struct{}{}
		}
	}
	var redisClient *redis.Client
	if strings.TrimSpace(redisURL) != "" {
		options, err := redis.ParseURL(redisURL)
		if err != nil {
			return nil, fmt.Errorf("parse NODE_AUTH_REDIS_URL: %w", err)
		}
		redisClient = redis.NewClient(options)
	}
	return &Verifier{keys: keys, revoked: revoked, redis: redisClient, now: time.Now, seenNonces: make(map[string]time.Time)}, nil
}

func (v *Verifier) Close() error {
	if v.redis == nil {
		return nil
	}
	return v.redis.Close()
}

func (v *Verifier) Register(ctx context.Context, nodeID, encodedPublicKey string) error {
	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" || strings.ContainsAny(nodeID, "\r\n:") {
		return fmt.Errorf("invalid node_id")
	}
	if _, exists := v.keys[nodeID]; exists {
		return fmt.Errorf("node identity is managed by NODE_AUTHORIZED_KEYS")
	}
	raw, err := decodeBase64(encodedPublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("public_key must be a base64-encoded Ed25519 public key")
	}
	if v.redis == nil {
		return fmt.Errorf("shared node identity registry is not configured")
	}
	pipe := v.redis.TxPipeline()
	pipe.HSet(ctx, "nodeauth:public-keys", nodeID, base64.RawURLEncoding.EncodeToString(raw))
	pipe.SRem(ctx, "nodeauth:revoked", nodeID)
	_, err = pipe.Exec(ctx)
	return err
}

func (v *Verifier) Revoke(ctx context.Context, nodeID string) error {
	if v.redis == nil {
		return fmt.Errorf("shared node identity registry is not configured")
	}
	return v.redis.SAdd(ctx, "nodeauth:revoked", strings.TrimSpace(nodeID)).Err()
}

func (v *Verifier) Restore(ctx context.Context, nodeID string) error {
	if v.redis == nil {
		return fmt.Errorf("shared node identity registry is not configured")
	}
	return v.redis.SRem(ctx, "nodeauth:revoked", strings.TrimSpace(nodeID)).Err()
}

func (v *Verifier) List(ctx context.Context) ([]RegisteredIdentity, error) {
	identities := make(map[string]RegisteredIdentity, len(v.keys))
	for nodeID, publicKey := range v.keys {
		identities[nodeID] = RegisteredIdentity{
			NodeID: nodeID, PublicKey: base64.RawURLEncoding.EncodeToString(publicKey), Source: "configuration",
		}
	}
	if v.redis != nil {
		registered, err := v.redis.HGetAll(ctx, "nodeauth:public-keys").Result()
		if err != nil {
			return nil, err
		}
		for nodeID, publicKey := range registered {
			if _, static := identities[nodeID]; !static {
				identities[nodeID] = RegisteredIdentity{NodeID: nodeID, PublicKey: publicKey, Source: "registry"}
			}
		}
		revoked, err := v.redis.SMembers(ctx, "nodeauth:revoked").Result()
		if err != nil {
			return nil, err
		}
		for _, nodeID := range revoked {
			identity := identities[nodeID]
			identity.NodeID = nodeID
			identity.Revoked = true
			identities[nodeID] = identity
		}
	}
	result := make([]RegisteredIdentity, 0, len(identities))
	for _, identity := range identities {
		if _, revoked := v.revoked[identity.NodeID]; revoked {
			identity.Revoked = true
		}
		result = append(result, identity)
	}
	return result, nil
}

func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(io.LimitReader(req.Body, maxBodySize+1))
		if err != nil || len(body) > maxBodySize {
			respond.JsonError(w, "request body is too large", http.StatusRequestEntityTooLarge)
			return
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
		if err := v.Verify(req.Context(), req, body); err != nil {
			reason := telemetry.NodeAuthInvalid
			if errors.Is(err, ErrReplayDetected) {
				reason = telemetry.NodeAuthReplay
			} else if errors.Is(err, ErrReplayProtectionUnavailable) {
				reason = telemetry.NodeAuthUnavailable
			}
			telemetry.RecordNodeAuthFailure(reason)
			respond.JsonError(w, "unauthorized: invalid node signature", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func (v *Verifier) Verify(ctx context.Context, req *http.Request, body []byte) error {
	nodeID := req.Header.Get(HeaderNodeID)
	timestamp := req.Header.Get(HeaderTimestamp)
	nonce := req.Header.Get(HeaderNonce)
	encodedSignature := req.Header.Get(HeaderSignature)
	if nodeID == "" || timestamp == "" || nonce == "" || encodedSignature == "" {
		return fmt.Errorf("missing node signature headers")
	}
	if _, revoked := v.revoked[nodeID]; revoked {
		return fmt.Errorf("node is revoked")
	}
	requestTimeUnix, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid node timestamp")
	}
	requestTime := time.Unix(requestTimeUnix, 0)
	if delta := v.now().UTC().Sub(requestTime); delta < -maxClockSkew || delta > maxClockSkew {
		return fmt.Errorf("node request timestamp is outside the allowed window")
	}
	publicKey, err := v.publicKey(ctx, nodeID)
	if err != nil {
		return err
	}
	signature, err := decodeBase64(encodedSignature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid node signature encoding")
	}
	message := canonicalMessage(req.Method, requestTarget(req), body, timestamp, nonce)
	if !ed25519.Verify(publicKey, []byte(message), signature) {
		return fmt.Errorf("node signature verification failed")
	}
	if err := v.rejectReplay(ctx, nodeID, nonce); err != nil {
		return err
	}
	return nil
}

func (v *Verifier) publicKey(ctx context.Context, nodeID string) (ed25519.PublicKey, error) {
	if publicKey, ok := v.keys[nodeID]; ok {
		return publicKey, nil
	}
	if v.redis == nil {
		return nil, fmt.Errorf("unknown node identity")
	}
	encoded, err := v.redis.HGet(ctx, "nodeauth:public-keys", nodeID).Result()
	if err != nil {
		return nil, fmt.Errorf("lookup node identity: %w", err)
	}
	raw, err := decodeBase64(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("registered node public key is invalid")
	}
	return ed25519.PublicKey(raw), nil
}

func (v *Verifier) rejectReplay(ctx context.Context, nodeID, nonce string) error {
	if _, err := decodeBase64(nonce); err != nil {
		return fmt.Errorf("invalid node nonce")
	}
	if v.redis != nil {
		revoked, err := v.redis.SIsMember(ctx, "nodeauth:revoked", nodeID).Result()
		if err != nil {
			return fmt.Errorf("%w: check node revocation", ErrReplayProtectionUnavailable)
		}
		if revoked {
			return fmt.Errorf("node is revoked")
		}
		accepted, err := v.redis.SetNX(ctx, "nodeauth:nonce:"+nodeID+":"+nonce, "1", nonceTTL).Result()
		if err != nil {
			return fmt.Errorf("%w: store node nonce", ErrReplayProtectionUnavailable)
		}
		if !accepted {
			return ErrReplayDetected
		}
		return nil
	}

	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	for key, expiresAt := range v.seenNonces {
		if !expiresAt.After(now) {
			delete(v.seenNonces, key)
		}
	}
	key := nodeID + ":" + nonce
	if _, exists := v.seenNonces[key]; exists {
		return ErrReplayDetected
	}
	v.seenNonces[key] = now.Add(nonceTTL)
	return nil
}

func parsePublicKeys(encoded string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey)
	for _, entry := range strings.Split(encoded, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		nodeID, value, ok := strings.Cut(entry, "=")
		if !ok || strings.TrimSpace(nodeID) == "" {
			return nil, fmt.Errorf("NODE_AUTHORIZED_KEYS entries must use node-id=base64-public-key")
		}
		raw, err := decodeBase64(strings.TrimSpace(value))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid Ed25519 public key for node %q", nodeID)
		}
		keys[strings.TrimSpace(nodeID)] = ed25519.PublicKey(append([]byte(nil), raw...))
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("NODE_AUTHORIZED_KEYS must register at least one node public key")
	}
	return keys, nil
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, fmt.Errorf("invalid base64 value")
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

func canonicalMessage(method, target string, body []byte, timestamp, nonce string) string {
	digest := sha256.Sum256(body)
	return strings.Join([]string{strings.ToUpper(method), target, hex.EncodeToString(digest[:]), timestamp, nonce}, "\n")
}
