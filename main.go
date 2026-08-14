// Package main is the unified Lux explorer: a single Go binary that embeds
// the SPA, indexes one or more chains via github.com/luxfi/indexer, runs a
// per-chain GraphQL engine via github.com/luxfi/graph, and exposes the
// admin/realtime API and frontend assets on one HTTP listener.
//
// Build: go build -o explorer .
// Run:   explorer --config /etc/explorer/chains.yaml
//
// Routes:
//
//	/                                       SPA (embedded; SPA-routing fallback)
//	/envs.js                                runtime config window.ENV = {...}
//	/icon.svg, /logo.svg                    per-host brand assets (disk override)
//	/health                                 service health
//	/v1/indexer/*                           default chain explorer API
//	/v1/indexer/{slug}/*                    per-chain explorer API
//	/v1/explorer/{slug}/*                   legacy alias for /v1/indexer/{slug}
//	/v1/graph/{slug}/{subgraph}/graphql     per-chain, per-subgraph GraphQL
//	/v1/explorer/admin/chains[/{slug}]      runtime registry CRUD
//	/v1/explorer/realtime                   WebSocket realtime hub
//	/v1/explorer/realtime/stats             realtime stats
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
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

var version = "dev"

func main() {
	var (
		httpAddr   = flag.String("http", "", "HTTP listen address (default :8090 / $HTTP_ADDR)")
		dataDir    = flag.String("data", "", "Data directory (default $DATA_DIR or ~/.explorer/data)")
		configPath = flag.String("config", "", "Path to chains.yaml ($EXPLORER_CONFIG)")
		enableMDNS = flag.Bool("mdns", envBool("EXPLORER_MDNS", false), "Auto-discover chains via mDNS")
		showVer    = flag.Bool("version", false, "Show version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("explorer %s (%s)\n", version, fingerprint())
		os.Exit(0)
	}

	if *httpAddr == "" {
		*httpAddr = env("HTTP_ADDR", ":8090")
		if p := os.Getenv("PORT"); p != "" && *httpAddr == ":8090" {
			*httpAddr = ":" + p
		}
	}
	if *dataDir == "" {
		home, _ := os.UserHomeDir()
		*dataDir = env("DATA_DIR", filepath.Join(home, ".explorer", "data"))
	}
	if *configPath == "" {
		*configPath = env("EXPLORER_CONFIG", "")
	}
	if *configPath == "" {
		*configPath = findConfig(*dataDir)
	}

	var cfg Config
	if *configPath != "" {
		c, err := LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("[explorer] config: %v", err)
		}
		cfg = c
	}
	if cfg.DataDir == "" {
		cfg.DataDir = *dataDir
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = *httpAddr
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; log.Println("[explorer] shutdown"); cancel() }()

	registry := NewChainRegistry()
	supervisor := NewChainSupervisor(cfg)
	registry.AttachSupervisor(supervisor)
	// Bridge indexer block events into the realtime hub so WebSocket +
	// SSE subscribers see new blocks as they're ingested. Must happen
	// before any chain starts indexing — runChain installs the
	// Subscriber.OnBroadcast callback off the hub set here.
	supervisor.AttachRealtime(registry.hub)

	for _, c := range cfg.Chains {
		c.Source = "config"
		if err := registry.Add(c); err != nil {
			log.Printf("[explorer] skip %s from config: %v", c.Slug, err)
		}
	}

	if chains := os.Getenv("CHAINS"); chains != "" {
		registry.LoadFromEnv(chains)
	}

	if *enableMDNS {
		go registry.StartMDNSDiscovery()
	}

	go registry.hub.Run(ctx)
	go supervisor.Wait(ctx)

	frontend, err := NewFrontend(cfg, registry)
	if err != nil {
		log.Fatalf("[explorer] frontend: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":  "ok",
			"version": version,
			"chains":  registry.Count(),
		})
	})

	// Blockscout stats-microservice surface (/v1/counters, /v1/lines,
	// /v1/lines/{id}, /v1/pages/*). The Next.js /stats page enables these when
	// NEXT_PUBLIC_STATS_API_HOST is set and shows error banners without them;
	// each answer is read from the live indexer SQLite DB of the chain the
	// request host is served.
	// Warm ahead of the first caller: these answers are whole-table aggregates,
	// so computing one on arrival is the difference between a page that paints
	// and a page still waiting for its numbers.
	stats := NewStatsService(cfg.DataDir, cfg)
	stats.Mount(mux)
	go stats.Warm()

	mux.HandleFunc("GET /v1/explorer/admin/chains", registry.HandleList)
	mux.HandleFunc("POST /v1/explorer/admin/chains", registry.HandleAdd)
	mux.HandleFunc("PUT /v1/explorer/admin/chains/{slug}", registry.HandleUpdate)
	mux.HandleFunc("DELETE /v1/explorer/admin/chains/{slug}", registry.HandleRemove)

	mux.HandleFunc("/v1/explorer/realtime", registry.hub.HandleRealtime)
	mux.HandleFunc("GET /v1/explorer/realtime/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(registry.hub.Stats())
	})

	// /v1/base/realtime — the multiplexed SSE channel, and the only one the SPA
	// opens. One stream carries every broadcast for the host's chain in a JSON
	// envelope `{event, chain, data}` that the SPA routes off via its handler
	// map. HEAD is registered explicitly so the SPA's pre-flight
	// (HEAD-then-EventSource) reaches the same handler; net/http's ServeMux
	// answers 405 for HEAD on a GET-only route, which the SPA's `r.ok` check
	// reads as a dead channel. See realtime_sse.go.
	realtime := registry.hub.HandleMultiplexedSSE(cfg)
	mux.HandleFunc("GET /v1/base/realtime", realtime)
	mux.HandleFunc("HEAD /v1/base/realtime", realtime)

	supervisor.MountRoutes(mux)
	supervisor.MountSwap(mux)
	frontend.Mount(mux)

	log.Printf("[explorer] %s listening %s data=%s chains=%d mdns=%v %s",
		version, cfg.HTTPAddr, cfg.DataDir, registry.Count(), *enableMDNS, fingerprint())

	server := &http.Server{Addr: cfg.HTTPAddr, Handler: withSecurity(mux)}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[explorer] server: %v", err)
		}
	}()
	<-ctx.Done()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	server.Shutdown(shutCtx)
	log.Println("[explorer] stopped")
}

// withSecurity adds the baseline security headers and CORS preflight handler.
func withSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		// Answer the preflight with the headers it actually asked about.
		//
		// A fixed list only permits what someone thought to list, and a browser
		// refuses the whole request over one name missing from it: the exchange
		// sends x-api-key, which was not here, so every call to /v1/quote and
		// /v1/swappable_tokens failed the preflight and the swap panel had
		// neither a token list nor a price.
		//
		// A literal "*" is not the fix — Safari does not honour the wildcard in
		// this header and refuses exactly the same way. Echoing the request's
		// own Access-Control-Request-Headers is precise, needs no maintenance,
		// and is understood everywhere.
		if asked := r.Header.Get("Access-Control-Request-Headers"); asked != "" {
			w.Header().Set("Access-Control-Allow-Headers", asked)
		} else {
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		w.Header().Set("Vary", "Origin, Access-Control-Request-Headers")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	return fallback
}

// findConfig probes for a chains.yaml in the standard locations.
func findConfig(dataDir string) string {
	for _, p := range []string{
		filepath.Join(dataDir, "chains.yaml"),
		"chains.yaml",
		"/etc/explorer/chains.yaml",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}
