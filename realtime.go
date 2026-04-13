package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// RealtimeHub manages multi-chain WebSocket subscriptions.
type RealtimeHub struct {
	mu      sync.RWMutex
	clients map[*wsClient]struct{}
}

type wsClient struct {
	conn   *websocket.Conn
	subs   map[string]bool // "blocks", "transactions", "blocks:cchain", etc.
	mu     sync.Mutex
	closed bool
}

// RealtimeMessage is the wire format for realtime events.
type RealtimeMessage struct {
	Type      string `json:"type"`
	Chain     string `json:"chain,omitempty"`
	Data      any    `json:"data,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

// SubscribeRequest is what clients send to subscribe.
type SubscribeRequest struct {
	Subscribe string `json:"subscribe"` // blocks, transactions, token_transfers
	Chain     string `json:"chain"`     // optional chain slug; empty = default
}

// NewRealtimeHub creates a new hub.
func NewRealtimeHub() *RealtimeHub {
	return &RealtimeHub{
		clients: make(map[*wsClient]struct{}),
	}
}

// Run starts the heartbeat loop. Cancel ctx to stop.
func (h *RealtimeHub) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			h.closeAll()
			return
		case <-ticker.C:
			h.heartbeat()
		}
	}
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // CORS handled at mux level
	},
	HandshakeTimeout: 10 * time.Second,
	ReadBufferSize:   1024,
	WriteBufferSize:  1024,
}

// HandleRealtime is the HTTP handler for /v1/explorer/realtime.
func (h *RealtimeHub) HandleRealtime(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := &wsClient{
		conn: conn,
		subs: make(map[string]bool),
	}

	h.mu.Lock()
	h.clients[client] = struct{}{}
	h.mu.Unlock()

	// Send connected message
	client.send(RealtimeMessage{
		Type:      "connected",
		Timestamp: time.Now().UnixMilli(),
	})

	// Read loop: handle subscribe/unsubscribe/ping
	h.readPump(client)

	// Cleanup
	h.mu.Lock()
	delete(h.clients, client)
	h.mu.Unlock()
	conn.Close()
}

func (h *RealtimeHub) readPump(c *wsClient) {
	c.conn.SetReadLimit(4096)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		var req SubscribeRequest
		if err := json.Unmarshal(msg, &req); err != nil {
			continue
		}

		switch req.Subscribe {
		case "blocks", "transactions", "token_transfers":
			key := req.Subscribe
			if req.Chain != "" {
				key = req.Subscribe + ":" + req.Chain
			}
			c.mu.Lock()
			c.subs[key] = true
			c.mu.Unlock()

			c.send(RealtimeMessage{
				Type:      "subscribed",
				Chain:     req.Chain,
				Data:      map[string]string{"channel": req.Subscribe},
				Timestamp: time.Now().UnixMilli(),
			})

		case "ping":
			c.send(RealtimeMessage{
				Type:      "pong",
				Timestamp: time.Now().UnixMilli(),
			})
		}
	}
}

// Broadcast sends an event to all clients subscribed to the given channel+chain.
func (h *RealtimeHub) Broadcast(eventType, chain string, data any) {
	msg := RealtimeMessage{
		Type:      eventType,
		Chain:     chain,
		Data:      data,
		Timestamp: time.Now().UnixMilli(),
	}

	encoded, err := json.Marshal(msg)
	if err != nil {
		return
	}

	// Match: exact channel, channel:chain, or unscoped channel
	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		client.mu.Lock()
		match := client.subs[eventType] || client.subs[eventType+":"+chain]
		client.mu.Unlock()

		if match {
			client.sendRaw(encoded)
		}
	}
}

func (h *RealtimeHub) heartbeat() {
	msg := RealtimeMessage{
		Type:      "heartbeat",
		Timestamp: time.Now().UnixMilli(),
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for client := range h.clients {
		client.send(msg)
	}
}

func (h *RealtimeHub) closeAll() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for client := range h.clients {
		client.conn.Close()
	}
	h.clients = make(map[*wsClient]struct{})
}

// Stats returns connection statistics.
func (h *RealtimeHub) Stats() map[string]int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	subs := 0
	for client := range h.clients {
		client.mu.Lock()
		subs += len(client.subs)
		client.mu.Unlock()
	}

	return map[string]int{
		"connections":   len(h.clients),
		"subscriptions": subs,
	}
}

func (c *wsClient) send(msg RealtimeMessage) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := c.conn.WriteJSON(msg); err != nil {
		c.closed = true
		log.Printf("[realtime] write error: %v", err)
	}
}

func (c *wsClient) sendRaw(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
		c.closed = true
	}
}
