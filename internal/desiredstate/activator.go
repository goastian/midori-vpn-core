package desiredstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

const maxStoredBundleSize = 256 << 10

type PeerLimitApplier interface {
	ApplyPeerLimit(int, func() error) error
}

type Activator struct {
	applyMu     sync.Mutex
	mu          sync.RWMutex
	stateDir    string
	nodeID      uuid.UUID
	coreVersion string
	verifier    *Verifier
	local       LocalCapabilities
	peerLimits  PeerLimitApplier
	now         func() time.Time
	current     *SignedBundle
}

type Snapshot struct {
	AppliedRevision   *int64
	VersionCompatible bool
	MaxPeers          int
	Transports        []Transport
}

func NewActivator(stateDir string, nodeID uuid.UUID, coreVersion, trustedKeys string, local LocalCapabilities, peerLimits PeerLimitApplier) (*Activator, error) {
	if !filepath.IsAbs(stateDir) || nodeID == uuid.Nil || peerLimits == nil {
		return nil, errors.New("valid desired state directory, node and peer limiter are required")
	}
	if _, err := parseStableVersion(coreVersion); err != nil {
		return nil, errors.New("core version must be a stable semantic version")
	}
	verifier, err := NewVerifier(trustedKeys)
	if err != nil {
		return nil, err
	}
	if local.Transports == nil {
		local.Transports = map[string]bool{}
	}
	if local.SecretFingerprints == nil {
		local.SecretFingerprints = map[string]string{}
	}
	return &Activator{
		stateDir: stateDir, nodeID: nodeID, coreVersion: coreVersion,
		verifier: verifier, local: local, peerLimits: peerLimits, now: time.Now,
	}, nil
}

func (a *Activator) LoadLastKnownGood() error {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	path := a.statePath()
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect last-known-good desired state: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxStoredBundleSize {
		return errors.New("last-known-good desired state must be a bounded regular 0600 file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read last-known-good desired state: %w", err)
	}
	signed, err := decodeSignedBundle(contents)
	if err != nil {
		return err
	}
	if _, err := a.verifier.Verify(signed, a.nodeID, a.coreVersion, a.now(), true); err != nil {
		return err
	}
	if err := ValidateLocal(signed.Bundle, a.local); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.peerLimits.ApplyPeerLimit(signed.Bundle.Capacity.MaxPeers, nil); err != nil {
		return err
	}
	a.current = cloneSignedBundle(&signed)
	return nil
}

func (a *Activator) Apply(signed SignedBundle) error {
	a.applyMu.Lock()
	defer a.applyMu.Unlock()
	if _, err := a.verifier.Verify(signed, a.nodeID, a.coreVersion, a.now(), false); err != nil {
		return err
	}
	if err := ValidateLocal(signed.Bundle, a.local); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	current := cloneSignedBundle(a.current)
	if current != nil {
		if signed.Bundle.Revision < current.Bundle.Revision {
			return ErrRollback
		}
		if signed.Bundle.Revision == current.Bundle.Revision {
			if signed.Signature == current.Signature && signed.SigningKeyID == current.SigningKeyID {
				return nil
			}
			return ErrRollback
		}
		if signed.Bundle.Revision != current.Bundle.Revision+1 || signed.Bundle.PreviousRevision == nil || *signed.Bundle.PreviousRevision != current.Bundle.Revision {
			return ErrBrokenChain
		}
	} else if signed.Bundle.Revision != 1 || signed.Bundle.PreviousRevision != nil {
		return ErrBrokenChain
	}
	encoded, err := json.Marshal(signed)
	if err != nil {
		return fmt.Errorf("encode last-known-good desired state: %w", err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxStoredBundleSize {
		return ErrInvalidBundle
	}
	if err := a.peerLimits.ApplyPeerLimit(signed.Bundle.Capacity.MaxPeers, func() error {
		return writeAtomic(a.statePath(), encoded)
	}); err != nil {
		return err
	}
	a.current = cloneSignedBundle(&signed)
	return nil
}

func (a *Activator) Snapshot() Snapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.current == nil {
		return Snapshot{}
	}
	revision := a.current.Bundle.Revision
	return Snapshot{
		AppliedRevision: &revision, VersionCompatible: true,
		MaxPeers:   a.current.Bundle.Capacity.MaxPeers,
		Transports: append([]Transport(nil), a.current.Bundle.Transports...),
	}
}

// WithWireGuardEndpoint holds the desired-state read lock through the peer
// mutation callback. Activation takes the write lock before the manager lock,
// so endpoint/transport intent and capacity cannot be mixed across revisions.
func (a *Activator) WithWireGuardEndpoint(operation func(string, int) error) error {
	if operation == nil {
		return errors.New("wireguard operation is required")
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	host, port, ok := a.wireGuardEndpointLocked()
	if !ok {
		return ErrLocalCapability
	}
	return operation(host, port)
}

func (a *Activator) wireGuardEndpointLocked() (string, int, bool) {
	if a.current == nil {
		return "", 0, false
	}
	endpointByName := make(map[string]PublicEndpoint, len(a.current.Bundle.PublicEndpoints))
	for _, endpoint := range a.current.Bundle.PublicEndpoints {
		endpointByName[endpoint.Name] = endpoint
	}
	for _, transport := range a.current.Bundle.Transports {
		if transport.Protocol == "wireguard" && transport.Enabled {
			endpoint, ok := endpointByName[transport.Endpoint]
			return endpoint.Host, endpoint.Port, ok
		}
	}
	return "", 0, false
}

func (a *Activator) statePath() string {
	return filepath.Join(a.stateDir, "desired-state.json")
}

func decodeSignedBundle(contents []byte) (SignedBundle, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var signed SignedBundle
	if err := decoder.Decode(&signed); err != nil {
		return SignedBundle{}, ErrInvalidBundle
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return SignedBundle{}, ErrInvalidBundle
	}
	return signed, nil
}

func cloneSignedBundle(source *SignedBundle) *SignedBundle {
	if source == nil {
		return nil
	}
	clone := *source
	clone.Bundle = Normalize(source.Bundle)
	return &clone
}

func writeAtomic(path string, contents []byte) (returnErr error) {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".desired-state-*")
	if err != nil {
		return fmt.Errorf("create temporary desired state: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect temporary desired state: %w", err)
	}
	if _, err := temporary.Write(contents); err != nil {
		return fmt.Errorf("write temporary desired state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync temporary desired state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary desired state: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("activate desired state: %w", err)
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("open desired state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync desired state directory: %w", err)
	}
	return nil
}
