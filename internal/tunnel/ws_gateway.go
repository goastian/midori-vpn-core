package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"nhooyr.io/websocket"
)

// WSGateway proxies WireGuard binary datagrams between a WebSocket (WSS on TLS 443)
// and the local WireGuard UDP listening port. This provides censorship-resistant
// WireGuard transport through strict firewalls and captive portals without TCP-over-TCP penalty.
type WSGateway struct {
	wgAddr string
}

// NewWSGateway creates a new WebSocket tunnel gateway targeting the local WireGuard port.
func NewWSGateway(wgPort int) *WSGateway {
	if wgPort <= 0 {
		wgPort = 51820
	}
	return &WSGateway{
		wgAddr: fmt.Sprintf("127.0.0.1:%d", wgPort),
	}
}

// Handler handles WebSocket upgrade and bidirectional binary datagram relay.
func (g *WSGateway) Handler(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Origin is checked at reverse proxy layer
	})
	if err != nil {
		slog.Warn("ws-tunnel: upgrade failed", "error", err, "remote", r.RemoteAddr)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "closing tunnel")

	// Open a local UDP socket to communicate with the WireGuard interface
	udpConn, err := net.Dial("udp", g.wgAddr)
	if err != nil {
		slog.Error("ws-tunnel: failed to dial local WireGuard UDP", "error", err)
		conn.Close(websocket.StatusInternalError, "wireguard unavailable")
		return
	}
	defer udpConn.Close()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	slog.Info("ws-tunnel: established session", "remote", r.RemoteAddr, "target", g.wgAddr)

	// Goroutine 1: WebSocket -> UDP WireGuard
	go func() {
		defer cancel()
		buf := make([]byte, 65535)
		for {
			typ, reader, err := conn.Reader(ctx)
			if err != nil {
				return
			}
			if typ != websocket.MessageBinary {
				continue
			}
			n, err := reader.Read(buf)
			if err != nil && err != io.EOF {
				return
			}
			if n > 0 {
				if _, werr := udpConn.Write(buf[:n]); werr != nil {
					return
				}
			}
		}
	}()

	// Goroutine 2: UDP WireGuard -> WebSocket
	udpBuf := make([]byte, 65535)
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := udpConn.Read(udpBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Keepalive ping over WebSocket
				if perr := conn.Ping(ctx); perr != nil {
					break
				}
				continue
			}
			break
		}
		if n > 0 {
			wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
			werr := conn.Write(wctx, websocket.MessageBinary, udpBuf[:n])
			wcancel()
			if werr != nil {
				break
			}
		}
	}

	conn.Close(websocket.StatusNormalClosure, "tunnel closed")
	slog.Info("ws-tunnel: session closed", "remote", r.RemoteAddr)
}
