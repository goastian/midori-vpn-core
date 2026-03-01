package control

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

type WSClient struct {
	conn *websocket.Conn
	send chan []byte
}

type WSHub struct {
	mu         sync.RWMutex
	clients    map[*WSClient]bool
	broadcast  chan []byte
	register   chan *WSClient
	unregister chan *WSClient
}

func NewWSHub() *WSHub {
	return &WSHub{
		clients:    make(map[*WSClient]bool),
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
			h.mu.Unlock()
			log.Printf("ws: client connected (%d total)", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("ws: client disconnected (%d total)", len(h.clients))

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

func (h *WSHub) HandleWS(w http.ResponseWriter, r *http.Request) {
	s := websocket.Server{
		Handler: func(conn *websocket.Conn) {
			client := &WSClient{
				conn: conn,
				send: make(chan []byte, 64),
			}

			h.register <- client
			defer func() {
				h.unregister <- client
				conn.Close()
			}()

			// Writer goroutine
			go func() {
				for msg := range client.send {
					if _, err := conn.Write(msg); err != nil {
						break
					}
				}
			}()

			// Reader (keep connection alive, discard incoming)
			buf := make([]byte, 512)
			for {
				conn.SetReadDeadline(time.Now().Add(60 * time.Second))
				if _, err := conn.Read(buf); err != nil {
					break
				}
			}
		},
	}
	s.ServeHTTP(w, r)
}
