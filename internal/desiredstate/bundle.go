// Package desiredstate defines and verifies the signed configuration contract
// distributed by Control to enrolled Core nodes.
package desiredstate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	SchemaVersion   = 1
	signatureDomain = "midorivpn-desired-state-v1"
	maxBundleAge    = 24 * time.Hour
)

var (
	ErrInvalidBundle       = errors.New("desired state bundle is invalid")
	ErrInvalidSignature    = errors.New("desired state signature is invalid")
	ErrUntrustedSigningKey = errors.New("desired state signing key is not trusted")
	ErrWrongTarget         = errors.New("desired state targets another node")
	ErrExpired             = errors.New("desired state bundle is expired")
	ErrNotYetValid         = errors.New("desired state bundle is not yet valid")
	ErrIncompatibleVersion = errors.New("desired state requires a newer Core version")
	ErrRollback            = errors.New("desired state rollback is forbidden")
	ErrBrokenChain         = errors.New("desired state revision chain is invalid")
	ErrLocalCapability     = errors.New("desired state local capability is unavailable")
)

var (
	identifierPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	hostnamePattern    = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	keyIDPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	fingerprintPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Bundle struct {
	SchemaVersion      int               `json:"schema_version"`
	ClusterID          uuid.UUID         `json:"cluster_id"`
	NodeID             uuid.UUID         `json:"node_id"`
	Revision           int64             `json:"revision"`
	PreviousRevision   *int64            `json:"previous_revision"`
	IssuedAt           time.Time         `json:"issued_at"`
	ExpiresAt          time.Time         `json:"expires_at"`
	MinimumCoreVersion string            `json:"minimum_core_version"`
	ManagementEndpoint string            `json:"management_endpoint"`
	PublicEndpoints    []PublicEndpoint  `json:"public_endpoints"`
	Capacity           Capacity          `json:"capacity"`
	Transports         []Transport       `json:"transports"`
	SecretReferences   []SecretReference `json:"secret_references"`
}

type PublicEndpoint struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type Capacity struct {
	MaxPeers int `json:"max_peers"`
}

type Transport struct {
	Protocol         string   `json:"protocol"`
	Enabled          bool     `json:"enabled"`
	Priority         int      `json:"priority"`
	Endpoint         string   `json:"endpoint"`
	SecretReferences []string `json:"secret_references"`
}

type SecretReference struct {
	Name              string `json:"name"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
}

type SignedBundle struct {
	Bundle       Bundle `json:"bundle"`
	SigningKeyID string `json:"signing_key_id"`
	Signature    string `json:"signature"`
}

type LocalCapabilities struct {
	Transports         map[string]bool
	SecretFingerprints map[string]string
}

type Signer struct {
	keyID      string
	privateKey ed25519.PrivateKey
}

func (s *Signer) PublicKey() ed25519.PublicKey {
	if s == nil || len(s.privateKey) != ed25519.PrivateKeySize {
		return nil
	}
	publicKey := s.privateKey.Public().(ed25519.PublicKey)
	return ed25519.PublicKey(append([]byte(nil), publicKey...))
}

func NewSigner(keyID, encodedPrivateKey string) (*Signer, error) {
	if !keyIDPattern.MatchString(keyID) {
		return nil, errors.New("desired state signing key ID is invalid")
	}
	raw, err := decodeBase64(encodedPrivateKey)
	if err != nil {
		return nil, errors.New("desired state private key is invalid")
	}
	var privateKey ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		if !bytes.Equal(raw, ed25519.NewKeyFromSeed(raw[:ed25519.SeedSize])) {
			return nil, errors.New("desired state private key is inconsistent")
		}
		privateKey = ed25519.PrivateKey(append([]byte(nil), raw...))
	default:
		return nil, errors.New("desired state private key has an invalid size")
	}
	return &Signer{keyID: keyID, privateKey: privateKey}, nil
}

func (s *Signer) Sign(bundle Bundle) (*SignedBundle, []byte, []byte, error) {
	if s == nil || len(s.privateKey) != ed25519.PrivateKeySize {
		return nil, nil, nil, errors.New("desired state signer is unavailable")
	}
	bundle = Normalize(bundle)
	if err := Validate(bundle); err != nil {
		return nil, nil, nil, err
	}
	payload, err := CanonicalPayload(bundle)
	if err != nil {
		return nil, nil, nil, err
	}
	digest := sha256.Sum256(payload)
	signature := ed25519.Sign(s.privateKey, signatureMessage(payload))
	return &SignedBundle{
		Bundle: bundle, SigningKeyID: s.keyID,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, payload, digest[:], nil
}

type Verifier struct {
	keys map[string]ed25519.PublicKey
}

func (v *Verifier) Trusts(keyID string, publicKey ed25519.PublicKey) bool {
	if v == nil || len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	return bytes.Equal(v.keys[keyID], publicKey)
}

func NewVerifier(encodedKeys string) (*Verifier, error) {
	keys := make(map[string]ed25519.PublicKey)
	for _, entry := range strings.Split(encodedKeys, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		keyID, encodedKey, ok := strings.Cut(entry, "=")
		keyID = strings.TrimSpace(keyID)
		if !ok || !keyIDPattern.MatchString(keyID) || keys[keyID] != nil {
			return nil, errors.New("desired state trust entries must use unique key-id=base64-public-key values")
		}
		raw, err := decodeBase64(strings.TrimSpace(encodedKey))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("desired state trust entry contains an invalid Ed25519 key")
		}
		keys[keyID] = ed25519.PublicKey(append([]byte(nil), raw...))
	}
	if len(keys) == 0 {
		return nil, errors.New("at least one desired state signing key is required")
	}
	return &Verifier{keys: keys}, nil
}

func (v *Verifier) Verify(signed SignedBundle, nodeID uuid.UUID, coreVersion string, now time.Time, allowExpired bool) ([]byte, error) {
	if err := Validate(signed.Bundle); err != nil {
		return nil, err
	}
	publicKey := v.keys[signed.SigningKeyID]
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrUntrustedSigningKey
	}
	signature, err := decodeCanonicalRawURL(signed.Signature, ed25519.SignatureSize)
	if err != nil {
		return nil, ErrInvalidSignature
	}
	payload, err := CanonicalPayload(signed.Bundle)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(publicKey, signatureMessage(payload), signature) {
		return nil, ErrInvalidSignature
	}
	if signed.Bundle.NodeID != nodeID {
		return nil, ErrWrongTarget
	}
	if !allowExpired && !signed.Bundle.ExpiresAt.After(now.UTC()) {
		return nil, ErrExpired
	}
	if signed.Bundle.IssuedAt.After(now.UTC().Add(30 * time.Second)) {
		return nil, ErrNotYetValid
	}
	compatible, err := VersionAtLeast(coreVersion, signed.Bundle.MinimumCoreVersion)
	if err != nil || !compatible {
		return nil, ErrIncompatibleVersion
	}
	return payload, nil
}

func Normalize(bundle Bundle) Bundle {
	bundle.IssuedAt = bundle.IssuedAt.UTC().Truncate(time.Second)
	bundle.ExpiresAt = bundle.ExpiresAt.UTC().Truncate(time.Second)
	bundle.MinimumCoreVersion = strings.TrimSpace(bundle.MinimumCoreVersion)
	bundle.ManagementEndpoint = strings.ToLower(strings.TrimSpace(bundle.ManagementEndpoint))
	bundle.PublicEndpoints = append([]PublicEndpoint(nil), bundle.PublicEndpoints...)
	for index := range bundle.PublicEndpoints {
		bundle.PublicEndpoints[index].Name = strings.ToLower(strings.TrimSpace(bundle.PublicEndpoints[index].Name))
		bundle.PublicEndpoints[index].Host = strings.ToLower(strings.TrimSpace(bundle.PublicEndpoints[index].Host))
	}
	sort.Slice(bundle.PublicEndpoints, func(i, j int) bool { return bundle.PublicEndpoints[i].Name < bundle.PublicEndpoints[j].Name })
	bundle.SecretReferences = append([]SecretReference(nil), bundle.SecretReferences...)
	for index := range bundle.SecretReferences {
		bundle.SecretReferences[index].Name = strings.ToLower(strings.TrimSpace(bundle.SecretReferences[index].Name))
		bundle.SecretReferences[index].FingerprintSHA256 = strings.ToLower(strings.TrimSpace(bundle.SecretReferences[index].FingerprintSHA256))
	}
	sort.Slice(bundle.SecretReferences, func(i, j int) bool { return bundle.SecretReferences[i].Name < bundle.SecretReferences[j].Name })
	bundle.Transports = append([]Transport(nil), bundle.Transports...)
	for index := range bundle.Transports {
		bundle.Transports[index].Protocol = strings.ToLower(strings.TrimSpace(bundle.Transports[index].Protocol))
		bundle.Transports[index].Endpoint = strings.ToLower(strings.TrimSpace(bundle.Transports[index].Endpoint))
		bundle.Transports[index].SecretReferences = append([]string(nil), bundle.Transports[index].SecretReferences...)
		for referenceIndex := range bundle.Transports[index].SecretReferences {
			bundle.Transports[index].SecretReferences[referenceIndex] = strings.ToLower(strings.TrimSpace(bundle.Transports[index].SecretReferences[referenceIndex]))
		}
		sort.Strings(bundle.Transports[index].SecretReferences)
		if bundle.Transports[index].SecretReferences == nil {
			bundle.Transports[index].SecretReferences = []string{}
		}
	}
	sort.Slice(bundle.Transports, func(i, j int) bool { return bundle.Transports[i].Protocol < bundle.Transports[j].Protocol })
	if bundle.PublicEndpoints == nil {
		bundle.PublicEndpoints = []PublicEndpoint{}
	}
	if bundle.Transports == nil {
		bundle.Transports = []Transport{}
	}
	if bundle.SecretReferences == nil {
		bundle.SecretReferences = []SecretReference{}
	}
	return bundle
}

func Validate(bundle Bundle) error {
	if !reflect.DeepEqual(bundle, Normalize(bundle)) {
		return ErrInvalidBundle
	}
	if bundle.SchemaVersion != SchemaVersion || bundle.ClusterID == uuid.Nil || bundle.NodeID == uuid.Nil || bundle.Revision < 1 {
		return ErrInvalidBundle
	}
	if (bundle.Revision == 1 && bundle.PreviousRevision != nil) ||
		(bundle.Revision > 1 && (bundle.PreviousRevision == nil || *bundle.PreviousRevision != bundle.Revision-1)) {
		return ErrBrokenChain
	}
	if bundle.IssuedAt.IsZero() || bundle.ExpiresAt.IsZero() || !bundle.ExpiresAt.After(bundle.IssuedAt) ||
		bundle.ExpiresAt.Sub(bundle.IssuedAt) > maxBundleAge {
		return ErrInvalidBundle
	}
	if _, err := parseStableVersion(bundle.MinimumCoreVersion); err != nil {
		return ErrInvalidBundle
	}
	managementURL, err := url.Parse(bundle.ManagementEndpoint)
	if err != nil || managementURL.Scheme != "https" || managementURL.Host == "" || managementURL.User != nil ||
		managementURL.RawQuery != "" || managementURL.Fragment != "" || (managementURL.Path != "" && managementURL.Path != "/") {
		return ErrInvalidBundle
	}
	if bundle.Capacity.MaxPeers < 1 || bundle.Capacity.MaxPeers > 65536 || len(bundle.PublicEndpoints) < 1 || len(bundle.PublicEndpoints) > 16 || len(bundle.Transports) > 6 || len(bundle.SecretReferences) > 32 {
		return ErrInvalidBundle
	}
	endpointNames := make(map[string]struct{}, len(bundle.PublicEndpoints))
	previousName := ""
	for _, endpoint := range bundle.PublicEndpoints {
		if !identifierPattern.MatchString(endpoint.Name) || !validHost(endpoint.Host) || endpoint.Port < 1 || endpoint.Port > 65535 || endpoint.Name <= previousName {
			return ErrInvalidBundle
		}
		endpointNames[endpoint.Name] = struct{}{}
		previousName = endpoint.Name
	}
	secretNames := make(map[string]string, len(bundle.SecretReferences))
	previousName = ""
	for _, reference := range bundle.SecretReferences {
		if !identifierPattern.MatchString(reference.Name) || !fingerprintPattern.MatchString(reference.FingerprintSHA256) || reference.Name <= previousName {
			return ErrInvalidBundle
		}
		secretNames[reference.Name] = reference.FingerprintSHA256
		previousName = reference.Name
	}
	allowedProtocols := map[string]struct{}{
		"wireguard": {}, "wss": {}, "masque": {}, "openvpn": {}, "ikev2": {}, "proxy": {},
	}
	previousProtocol := ""
	for _, transport := range bundle.Transports {
		if _, ok := allowedProtocols[transport.Protocol]; !ok || transport.Protocol <= previousProtocol || transport.Priority < 0 || transport.Priority > 1000 {
			return ErrInvalidBundle
		}
		if _, ok := endpointNames[transport.Endpoint]; !ok {
			return ErrInvalidBundle
		}
		previousReference := ""
		for _, reference := range transport.SecretReferences {
			if _, ok := secretNames[reference]; !ok || reference <= previousReference {
				return ErrInvalidBundle
			}
			previousReference = reference
		}
		previousProtocol = transport.Protocol
	}
	return nil
}

func ValidateLocal(bundle Bundle, local LocalCapabilities) error {
	for _, transport := range bundle.Transports {
		if transport.Enabled && !local.Transports[transport.Protocol] {
			return fmt.Errorf("%w: transport %s", ErrLocalCapability, transport.Protocol)
		}
	}
	for _, reference := range bundle.SecretReferences {
		if local.SecretFingerprints[reference.Name] != reference.FingerprintSHA256 {
			return fmt.Errorf("%w: secret reference %s", ErrLocalCapability, reference.Name)
		}
	}
	return nil
}

func CanonicalPayload(bundle Bundle) ([]byte, error) {
	if err := Validate(bundle); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("encode desired state payload: %w", err)
	}
	return payload, nil
}

func DecodePayload(payload []byte) (Bundle, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return Bundle{}, ErrInvalidBundle
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return Bundle{}, ErrInvalidBundle
	}
	if err := Validate(bundle); err != nil {
		return Bundle{}, err
	}
	return bundle, nil
}

// DecodeStored reconstructs the wire representation from a database record
// while regenerating canonical JSON and proving it matches the stored digest.
func DecodeStored(payload, digest, signature []byte, signingKeyID string) (SignedBundle, error) {
	bundle, err := DecodePayload(payload)
	if err != nil {
		return SignedBundle{}, err
	}
	canonical, err := CanonicalPayload(bundle)
	if err != nil {
		return SignedBundle{}, ErrInvalidBundle
	}
	wantDigest := sha256.Sum256(canonical)
	if len(digest) != sha256.Size || !bytes.Equal(digest, wantDigest[:]) ||
		len(signature) != ed25519.SignatureSize || !keyIDPattern.MatchString(signingKeyID) {
		return SignedBundle{}, ErrInvalidBundle
	}
	return SignedBundle{
		Bundle: bundle, SigningKeyID: signingKeyID,
		Signature: base64.RawURLEncoding.EncodeToString(signature),
	}, nil
}

func VersionAtLeast(current, minimum string) (bool, error) {
	currentParts, err := parseStableVersion(current)
	if err != nil {
		return false, err
	}
	minimumParts, err := parseStableVersion(minimum)
	if err != nil {
		return false, err
	}
	for index := range currentParts {
		if currentParts[index] != minimumParts[index] {
			return currentParts[index] > minimumParts[index], nil
		}
	}
	return true, nil
}

func ParseSecretFingerprints(encoded string) (map[string]string, error) {
	result := make(map[string]string)
	for _, entry := range strings.Split(encoded, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		name, fingerprint, ok := strings.Cut(entry, "=")
		name = strings.TrimSpace(name)
		fingerprint = strings.TrimSpace(fingerprint)
		if !ok || name != strings.ToLower(name) || fingerprint != strings.ToLower(fingerprint) ||
			!identifierPattern.MatchString(name) || !fingerprintPattern.MatchString(fingerprint) || result[name] != "" {
			return nil, errors.New("secret fingerprint entries must use unique name=lowercase-sha256 values")
		}
		result[name] = fingerprint
	}
	return result, nil
}

func parseStableVersion(value string) ([3]uint64, error) {
	var parsed [3]uint64
	parts := strings.Split(value, ".")
	if len(parts) != len(parsed) {
		return parsed, errors.New("version must contain major, minor and patch")
	}
	for index, part := range parts {
		if part == "" || (len(part) > 1 && part[0] == '0') {
			return parsed, errors.New("version contains a non-canonical component")
		}
		number, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return parsed, errors.New("version contains a non-numeric component")
		}
		parsed[index] = number
	}
	return parsed, nil
}

func signatureMessage(payload []byte) []byte {
	digest := sha256.Sum256(payload)
	return []byte(signatureDomain + "\n" + hex.EncodeToString(digest[:]))
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 || strings.ContainsAny(host, " /?#@") {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return !strings.Contains(host, ":") && hostnamePattern.MatchString(host)
}

func decodeBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64 value")
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
