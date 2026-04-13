// Package main is the unified explorer entry point.
//
// Runtime-mutable chain registry with mDNS discovery and WebSocket realtime.
//
// Build: GOWORK=off go build -o explorer .
// Run:   explorer --config chains.yaml
//        explorer --mdns=false --port 8090
//
// Env:
//   PORT             — HTTP port (default 8090)
//   EXPLORER_CONFIG  — path to chains.yaml
//   EXPLORER_MDNS    — enable mDNS discovery (default true)
//   CHAINS           — inline chain list: "cchain:http://...,zoo:http://..."
//
// Admin API:
//   GET    /v1/explorer/admin/chains        — list chains
//   POST   /v1/explorer/admin/chains        — add chain
//   PUT    /v1/explorer/admin/chains/{slug} — update chain
//   DELETE /v1/explorer/admin/chains/{slug} — remove chain
//
// Realtime:
//   WS /v1/explorer/realtime — subscribe to blocks/transactions per chain
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	port := flag.Int("port", envInt("PORT", 8090), "HTTP port")
	configFile := flag.String("config", env("EXPLORER_CONFIG", ""), "chains.yaml path")
	enableMDNS := flag.Bool("mdns", envBool("EXPLORER_MDNS", true), "auto-discover local chains via mDNS")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[explorer] shutdown signal received")
		cancel()
	}()

	// Chain registry (runtime mutable)
	registry := NewChainRegistry()

	// Load from config file
	if *configFile != "" {
		if err := registry.LoadFromFile(*configFile); err != nil {
			log.Fatalf("[explorer] config: %v", err)
		}
	}

	// Load from env
	if chains := env("CHAINS", ""); chains != "" {
		registry.LoadFromEnv(chains)
	}

	// Start mDNS discovery
	if *enableMDNS {
		go registry.StartMDNSDiscovery()
	}

	// Start realtime hub
	go registry.hub.Run(ctx)

	// HTTP mux
	mux := http.NewServeMux()

	// Health
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok",
			"chains": registry.Count(),
		})
	})

	// Admin API
	mux.HandleFunc("GET /v1/explorer/admin/chains", registry.HandleList)
	mux.HandleFunc("POST /v1/explorer/admin/chains", registry.HandleAdd)
	mux.HandleFunc("PUT /v1/explorer/admin/chains/{slug}", registry.HandleUpdate)
	mux.HandleFunc("DELETE /v1/explorer/admin/chains/{slug}", registry.HandleRemove)

	// Realtime WebSocket
	mux.HandleFunc("/v1/explorer/realtime", registry.hub.HandleRealtime)

	// Realtime stats
	mux.HandleFunc("GET /v1/explorer/realtime/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(registry.hub.Stats())
	})

	log.Printf("[explorer] listening :%d (%d chains, mdns=%v)", *port, registry.Count(), *enableMDNS)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[explorer] server: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	srv.Shutdown(shutdownCtx)
	log.Println("[explorer] stopped")
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		fmt.Sscanf(v, "%d", &n)
		return n
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	switch v {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return fallback
	}
}
