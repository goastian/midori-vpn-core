package control

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"nhooyr.io/websocket"

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
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
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

func (h *WSHub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

func (h *WSHub) HandleWS(w http.ResponseWriter, r *http.Request, userID string) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		slog.Error("ws: accept error", "error", err)
		return
	}

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
