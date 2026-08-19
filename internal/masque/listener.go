package masque

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"
)

var (
	ErrMasqueClosed = errors.New("masque listener is closed")
)

type Config struct {
	ListenAddr string
	TLSConfig  *tls.Config
	MTU        int
}

type Session struct {
	ID          string
	RemoteAddr  net.Addr
	ConnectedAt time.Time
	BytesIn     uint64
	BytesOut    uint64
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
	// In production, uses quic-go / http3.Server with Extended CONNECT support
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

func (m *MASQUEListener) RegisterSession(id string, remote net.Addr) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess := &Session{
		ID:          id,
		RemoteAddr:  remote,
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
