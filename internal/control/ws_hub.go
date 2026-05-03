package control

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"nhooyr.io/websocket"

	"github.com/goastian/midori-vpn-core/internal/auth"
	"github.com/goastian/midori-vpn-core/internal/config"
)

var (
	ErrWSGlobalLimit = errors.New("global WebSocket connection limit reached")
	ErrWSUserLimit   = errors.New("per-user WebSocket connection limit reached")
)

type WSClient struct {
	conn   *websocket.Conn
	send   chan []byte
	userID string
}

type WSHub struct {
	mu         sync.RWMutex
	cfg        *config.Config
	clients    map[*WSClient]bool
	userConns  map[string]int // userID -> active connection count
	broadcast  chan []byte
	register   chan *WSClient
	unregister chan *WSClient
}

func NewWSHub(cfg *config.Config) *WSHub {
	return &WSHub{
		cfg:        cfg,
		clients:    make(map[*WSClient]bool),
		userConns:  make(map[string]int),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *WSClient),
		unregister: make(chan *WSClient),
	}
}

func (h *WSHub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.userConns[client.userID]++
			h.mu.Unlock()
			slog.Info("ws: client connected", "user", client.userID, "total", len(h.clients), "user_conns", h.userConns[client.userID])

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				h.userConns[client.userID]--
				if h.userConns[client.userID] <= 0 {
					delete(h.userConns, client.userID)
				}
			}
			h.mu.Unlock()
			slog.Info("ws: client disconnected", "user", client.userID, "total", len(h.clients))

		case message := <-h.broadcast:
			h.mu.RLock()
			clientCount := len(h.clients)
			h.mu.RUnlock()
			if clientCount == 0 {
				continue
			}
			h.mu.RLock()
			var dead []*WSClient
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					dead = append(dead, client)
				}
			}
			h.mu.RUnlock()
			if len(dead) > 0 {
				h.mu.Lock()
				for _, client := range dead {
					if _, ok := h.clients[client]; ok {
						close(client.send)
						delete(h.clients, client)
					}
				}
				h.mu.Unlock()
			}
		}
	}
}

// CanAccept checks whether a new WS connection is allowed for the given user
// and groups, respecting global and per-plan limits.
func (h *WSHub) CanAccept(userID string, groups []string) error {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Global limit
	if h.cfg.WSMaxGlobal > 0 && len(h.clients) >= h.cfg.WSMaxGlobal {
		return ErrWSGlobalLimit
	}

	// Per-user limit based on plan
	maxForUser := h.cfg.WSMaxForGroups(groups)
	if maxForUser > 0 && h.userConns[userID] >= maxForUser {
		return ErrWSUserLimit
	}

	return nil
}

func (h *WSHub) Broadcast(data interface{}) {
	msg, err := json.Marshal(data)
	if err != nil {
		return
	}
	select {
	case h.broadcast <- msg:
	default:
	}
}

// BroadcastToUsers sends data only to connected clients whose userID is in userIDs.
func (h *WSHub) BroadcastToUsers(userIDs []string, data interface{}) {
	if len(userIDs) == 0 {
		return
	}
	msg, err := json.Marshal(data)
	if err != nil {
		return
	}
	set := make(map[string]struct{}, len(userIDs))
	for _, id := range userIDs {
		set[id] = struct{}{}
	}

	h.mu.RLock()
	var dead []*WSClient
	for client := range h.clients {
		if _, ok := set[client.userID]; !ok {
			continue
		}
		select {
		case client.send <- msg:
		default:
			dead = append(dead, client)
		}
	}
	h.mu.RUnlock()

	if len(dead) > 0 {
		h.mu.Lock()
		for _, client := range dead {
			if _, ok := h.clients[client]; ok {
				close(client.send)
				delete(h.clients, client)
			}
		}
		h.mu.Unlock()
	}
}

func (h *WSHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *WSHub) HandleWS(w http.ResponseWriter, r *http.Request, cfg *config.Config, jwks *auth.JWKSProvider) {
	// Build origin patterns from CORS config for WebSocket origin validation
	var originPatterns []string
	for _, raw := range strings.Split(cfg.CORSAllowedOrigins, ",") {
		raw = strings.TrimSpace(raw)
		if raw != "" {
			originPatterns = append(originPatterns, raw)
		}
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover,
		OriginPatterns:  originPatterns,
	})
	if err != nil {
		slog.Error("ws: accept error", "error", err)
		return
	}

	// Authenticate via the first message: client must send {"token":"<jwt>"}
	// within 10 seconds of connecting.
	authCtx, authCancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, msg, err := conn.Read(authCtx)
	authCancel()
	if err != nil {
		slog.Warn("ws: auth message timeout or read error", "error", err)
		conn.Close(websocket.StatusPolicyViolation, "authentication timeout")
		return
	}

	var authMsg struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(msg, &authMsg); err != nil || authMsg.Token == "" {
		conn.Close(websocket.StatusPolicyViolation, "invalid auth message")
		return
	}

	claims, err := auth.ValidateTokenAndExtractClaims(cfg, jwks, authMsg.Token)
	if err != nil {
		slog.Warn("ws: invalid token", "error", err)
		conn.Close(websocket.StatusPolicyViolation, "invalid token")
		return
	}

	if err := h.CanAccept(claims.Subject, claims.Groups); err != nil {
		conn.Close(websocket.StatusTryAgainLater, err.Error())
		return
	}

	userID := claims.Subject

	client := &WSClient{
		conn:   conn,
		send:   make(chan []byte, 64),
		userID: userID,
	}

	h.register <- client
	defer func() {
		h.unregister <- client
		conn.Close(websocket.StatusNormalClosure, "")
	}()

	// Writer goroutine
	go func() {
		for msg := range client.send {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := conn.Write(ctx, websocket.MessageText, msg); err != nil {
				cancel()
				return
			}
			cancel()
		}
	}()

	// Reader (keep connection alive, discard incoming)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		_, _, err := conn.Read(ctx)
		cancel()
		if err != nil {
			break
		}
	}
}
