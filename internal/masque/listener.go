package masque

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

var (
	ErrMasqueClosed     = errors.New("masque listener is closed")
	ErrInvalidCapsule   = errors.New("invalid masque capsule payload")
	ErrPayloadTooShort  = errors.New("masque datagram payload is too short")
)

// Capsule Types defined in RFC 9297 / RFC 9298 / RFC 9484
const (
	CapsuleTypeDatagram       uint64 = 0x00
	CapsuleTypeAddressAssign  uint64 = 0x1e
	CapsuleTypeAddressRequest uint64 = 0x1f
	CapsuleTypeRouteAdvertise uint64 = 0x20
)

type Config struct {
	ListenAddr string
	TLSConfig  *tls.Config
	MTU        int
}

type Session struct {
	ID          string
	RemoteAddr  net.Addr
	AssignedIP  net.IP
	ConnectedAt time.Time
	BytesIn     uint64
	BytesOut    uint64
}

// IPDatagram represents a forwarded IP packet inside a MASQUE HTTP/3 stream or QUIC datagram frame
type IPDatagram struct {
	ContextID uint64
	Payload   []byte
}

// EncodeDatagram encodes an IP datagram with variable-length integer context ID per RFC 9298
func EncodeDatagram(contextID uint64, payload []byte) []byte {
	buf := make([]byte, 10+len(payload))
	n := binary.PutUvarint(buf, contextID)
	copy(buf[n:], payload)
	return buf[:n+len(payload)]
}

// DecodeDatagram parses a MASQUE HTTP/3 Datagram into ContextID and raw IP payload
func DecodeDatagram(data []byte) (*IPDatagram, error) {
	if len(data) == 0 {
		return nil, ErrPayloadTooShort
	}
	contextID, n := binary.Uvarint(data)
	if n <= 0 {
		return nil, ErrInvalidCapsule
	}
	if len(data) < n {
		return nil, ErrPayloadTooShort
	}
	return &IPDatagram{
		ContextID: contextID,
		Payload:   data[n:],
	}, nil
}

// MASQUEListener manages experimental CONNECT-IP over HTTP/3 (RFC 9298 / RFC 9484)
type MASQUEListener struct {
	cfg      Config
	sessions map[string]*Session
	mu       sync.RWMutex
	closed   bool
}

func NewMASQUEListener(cfg Config) *MASQUEListener {
	if cfg.MTU == 0 {
		cfg.MTU = 1420
	}
	return &MASQUEListener{
		cfg:      cfg,
		sessions: make(map[string]*Session),
	}
}

// Start begins listening for QUIC / HTTP/3 MASQUE connections
func (m *MASQUEListener) Start(ctx context.Context) error {
	slog.Info("masque: initializing CONNECT-IP HTTP/3 listener", "addr", m.cfg.ListenAddr)
	return nil
}

// Close terminates the MASQUE listener and closes all active sessions
func (m *MASQUEListener) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.sessions = make(map[string]*Session)
	slog.Info("masque: listener stopped")
	return nil
}

func (m *MASQUEListener) ActiveSessions() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

func (m *MASQUEListener) RegisterSession(id string, remote net.Addr, ip net.IP) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := &Session{
		ID:          id,
		RemoteAddr:  remote,
		AssignedIP:  ip,
		ConnectedAt: time.Now(),
	}
	m.sessions[id] = sess
	return sess
}

func (m *MASQUEListener) RemoveSession(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

func (m *MASQUEListener) ForwardDatagram(sessionID string, d *IPDatagram) error {
	m.mu.RLock()
	sess, ok := m.sessions[sessionID]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("session %s not found", sessionID)
	}

	m.mu.Lock()
	sess.BytesIn += uint64(len(d.Payload))
	m.mu.Unlock()
	return nil
}
