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
	supervisor := NewChainSupervisor(cfg.DataDir)
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

	// Optionally mount a hanzoai/vfs object-store-backed filesystem (s3:// in
	// prod, file:// for local) under which DB-backed services keep their SQLite
	// files. Off by default (cfg.VFS.Enabled=false) => empty mountpoint and the
	// services use whatever database_url the config gives them. See vfsmount.go.
	vfsMountpoint, vfsCleanup, err := setupVFS(ctx, cfg.VFS, cfg.DataDir)
	if err != nil {
		log.Fatalf("[explorer] vfs: %v", err)
	}
	defer func() { _ = vfsCleanup() }()
	if vfsMountpoint != "" {
		log.Printf("[explorer] vfs: DB-backed services will use SQLite under %s", vfsMountpoint)
	}

	// Resolve the in-process Blockscout-rs services from config: concrete
	// ports, URL prefixes, and per-service settings JSON. This is the single
	// source of truth both the FFI launcher and the zip reverse-proxy read
	// from (services.go). Empty when services.enabled is false. The vfs
	// mountpoint (if any) supplies the default SQLite url for DB-backed services.
	svcs := resolveServices(cfg.Services, vfsMountpoint)

	// Launch each resolved service in-process via cgo on its own Tokio runtime
	// thread — one binary runs everything (ffi.go). The zip front router
	// reverse-proxies /v1/<prefix>/* to them.
	if len(svcs) > 0 {
		log.Printf("[explorer] ffi: starting %d in-process Rust service(s)", len(svcs))
	}
	startFFIServices(svcs)

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

	mux.HandleFunc("GET /v1/explorer/admin/chains", registry.HandleList)
	mux.HandleFunc("POST /v1/explorer/admin/chains", registry.HandleAdd)
	mux.HandleFunc("PUT /v1/explorer/admin/chains/{slug}", registry.HandleUpdate)
	mux.HandleFunc("DELETE /v1/explorer/admin/chains/{slug}", registry.HandleRemove)

	mux.HandleFunc("/v1/explorer/realtime", registry.hub.HandleRealtime)
	mux.HandleFunc("GET /v1/explorer/realtime/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(registry.hub.Stats())
	})

	// /v1/base/realtime — multiplexed SSE channel the bundled SPA opens.
	// One stream carries every broadcast in a JSON envelope `{event, chain, data}`
	// that the SPA routes off via its handler map. See realtime_sse.go.
	muxRealtimeSSE := registry.hub.HandleMultiplexedSSE()
	mux.HandleFunc("GET /v1/base/realtime", muxRealtimeSSE)
	mux.HandleFunc("HEAD /v1/base/realtime", muxRealtimeSSE)

	// SSE endpoints at the URLs the bundled SPA opens EventSource on.
	// See realtime_sse.go for the channel mapping + the back-story on
	// why each path needs its own handler. Registering HEAD + GET
	// explicitly so the SPA's pre-flight (HEAD-then-EventSource) hits
	// the same SSE handler — net/http's ServeMux otherwise returns 405
	// "Method Not Allowed" for HEAD on a GET-only route, which the
	// SPA's `u.ok` check would reject and disable the channel.
	for path, channel := range map[string]string{
		"/blocks":          "blocks",
		"/transactions":    "transactions",
		"/token-transfers": "token_transfers",
		"/internal-txs":    "internal_transactions",
		"/tokens":          "tokens",
		"/gas-tracker":     "gas_tracker",
		"/validators":      "validators",
		"/stats":           "stats",
	} {
		h := registry.hub.HandleSSE(channel)
		mux.HandleFunc("GET "+path, h)
		mux.HandleFunc("HEAD "+path, h)
	}

	supervisor.MountRoutes(mux)
	frontend.Mount(mux)

	// zip is the FRONT router (front.go): it reverse-proxies /v1/<prefix>/*
	// to each in-process service and serves everything else from the explorer
	// mux built above. When no services are configured the front app is just
	// the mux behind zip's security middleware — identical behaviour, one
	// router.
	app := buildFrontApp(mux, svcs)

	log.Printf("[explorer] %s listening %s data=%s chains=%d services=%d mdns=%v %s",
		version, cfg.HTTPAddr, cfg.DataDir, registry.Count(), len(svcs), *enableMDNS, fingerprint())

	go func() {
		if err := app.Listen(cfg.HTTPAddr); err != nil {
			log.Fatalf("[explorer] server: %v", err)
		}
	}()
	<-ctx.Done()
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()
	_ = app.ShutdownWithContext(shutCtx)
	log.Println("[explorer] stopped")
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
