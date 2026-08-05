package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestRealtimeHubStats(t *testing.T) {
	hub := NewRealtimeHub()
	stats := hub.Stats()
	if stats["connections"] != 0 {
		t.Fatalf("expected 0 connections, got %d", stats["connections"])
	}
}

func TestRealtimeWebSocket(t *testing.T) {
	hub := NewRealtimeHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/explorer/realtime", hub.HandleRealtime)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Connect WebSocket
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/explorer/realtime"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Read connected message
	var msg RealtimeMessage
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	err = conn.ReadJSON(&msg)
	if err != nil {
		t.Fatalf("read connected: %v", err)
	}
	if msg.Type != "connected" {
		t.Fatalf("expected connected, got %s", msg.Type)
	}

	// Subscribe to blocks
	sub := SubscribeRequest{Subscribe: "blocks", Chain: "cchain"}
	conn.WriteJSON(sub)

	// Read subscribed confirmation
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	err = conn.ReadJSON(&msg)
	if err != nil {
		t.Fatalf("read subscribed: %v", err)
	}
	if msg.Type != "subscribed" {
		t.Fatalf("expected subscribed, got %s", msg.Type)
	}

	// Broadcast a block
	hub.Broadcast("blocks", "cchain", map[string]any{"number": 1})

	// Read the broadcast
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	err = conn.ReadJSON(&msg)
	if err != nil {
		t.Fatalf("read broadcast: %v", err)
	}
	if msg.Type != "blocks" {
		t.Fatalf("expected blocks event, got %s", msg.Type)
	}
	if msg.Chain != "cchain" {
		t.Fatalf("expected chain=cchain, got %s", msg.Chain)
	}

	// Verify stats
	stats := hub.Stats()
	if stats["connections"] != 1 {
		t.Fatalf("expected 1 connection, got %d", stats["connections"])
	}
	if stats["subscriptions"] != 1 {
		t.Fatalf("expected 1 subscription, got %d", stats["subscriptions"])
	}
}

func TestRealtimePing(t *testing.T) {
	hub := NewRealtimeHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/explorer/realtime", hub.HandleRealtime)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/explorer/realtime"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Consume connected
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.ReadJSON(&RealtimeMessage{})

	// Send ping
	conn.WriteJSON(SubscribeRequest{Subscribe: "ping"})

	var msg RealtimeMessage
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	err = conn.ReadJSON(&msg)
	if err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if msg.Type != "pong" {
		t.Fatalf("expected pong, got %s", msg.Type)
	}
}

func TestRealtimeUnscopedSubscription(t *testing.T) {
	hub := NewRealtimeHub()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go hub.Run(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/explorer/realtime", hub.HandleRealtime)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/explorer/realtime"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Consume connected
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.ReadJSON(&RealtimeMessage{})

	// Subscribe to transactions without chain scope (gets all chains)
	conn.WriteJSON(SubscribeRequest{Subscribe: "transactions"})

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	conn.ReadJSON(&RealtimeMessage{}) // subscribed

	// Broadcast from any chain should match
	hub.Broadcast("transactions", "zoo", map[string]any{"hash": "0xabc"})

	var msg RealtimeMessage
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	err = conn.ReadJSON(&msg)
	if err != nil {
		t.Fatalf("read broadcast: %v", err)
	}
	if msg.Type != "transactions" {
		t.Fatalf("expected transactions, got %s", msg.Type)
	}
	if msg.Chain != "zoo" {
		t.Fatalf("expected chain=zoo, got %s", msg.Chain)
	}
}

func TestRealtimeStatsEndpoint(t *testing.T) {
	hub := NewRealtimeHub()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/explorer/realtime/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(hub.Stats())
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	resp, err := ts.Client().Get(ts.URL + "/v1/explorer/realtime/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var stats map[string]int
	json.NewDecoder(resp.Body).Decode(&stats)
	if stats["connections"] != 0 {
		t.Fatalf("expected 0 connections, got %d", stats["connections"])
	}
}
