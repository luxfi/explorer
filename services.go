package main

// services.go — front-router wiring for the in-process Blockscout-rs services.
//
// This file is build-tag agnostic: it is compiled into BOTH the default
// (Go-native) binary and the `-tags ffi` single binary. It owns three
// decomplected concerns, none of which touch cgo:
//
//  1. RESOLVE  — turn ServicesConfig (chains.yaml) into a normalized slice of
//     resolvedService with concrete ports, prefixes, and a settings JSON.
//  2. SETTINGS — build the JSON each service's upstream `Settings` deserializes
//     (server.http.addr / server.grpc.addr, and DB url where applicable).
//  3. PROXY    — mount a reverse-proxy on the zip front App at
//     /v1/<prefix>/* → http://127.0.0.1:<http_port>.
//
// The actual in-process LAUNCH (cgo → liblux_explorer_ffi.a) is the ONLY part
// that differs by build tag and lives in ffi_on.go / ffi_off.go. That split is
// the single seam between "what runs in-process" (Rust, cgo) and "how it is
// fronted" (Go, zip) — orthogonal and complete.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/hanzoai/zip"
)

// servicePortBase is where auto-assigned in-process service HTTP ports start.
// Each service gets HTTP=base+2n, gRPC=base+2n+1, so they never collide with
// each other or with the explorer's own listener (:8090 by default). The
// upstream blockscout-service-launcher default is 0.0.0.0:8050 (http) /
// :8051 (grpc); we keep that family but bind to 127.0.0.1 (loopback only —
// the front router is the sole public surface) and fan out per service.
const servicePortBase = 8050

// defaultPrefix maps an FFI service name to its default URL prefix. The prefix
// is the path segment the SPA / clients hit: /v1/<prefix>/*. Kept short and
// stable so front-end calls don't churn when a service is renamed upstream.
var defaultPrefix = map[string]string{
	"sig-provider":            "sig",
	"smart-contract-verifier": "verifier",
	"stats":                   "stats",
	"multichain-aggregator":   "multichain",
	"visualizer":              "visualizer",
}

// resolvedService is a ServiceConfig with every field made concrete: ports
// assigned, prefix derived, and the settings JSON the FFI entrypoint will
// receive already rendered. Both the proxy layer and the FFI launch layer
// consume this — one resolution, two uses (DRY).
type resolvedService struct {
	Name         string
	Prefix       string
	HTTPPort     int
	GRPCPort     int
	SettingsJSON string
}

// dbBackedServices are the wrapped services that open a sea-orm connection and
// therefore take a `database.url`. When a vfs mountpoint is provided and such a
// service has no explicit database_url in chains.yaml, resolveServices defaults
// it to a SQLite file on the mount — that is the whole point of the vfs wiring:
// a self-contained binary whose service state lives on s3:// via vfs, no
// Postgres. Stateless services (sig-provider, visualizer, verifier) are absent
// here and never get a url.
var dbBackedServices = map[string]bool{
	"stats":                 true,
	"multichain-aggregator": true,
}

// resolveServices normalizes ServicesConfig into concrete resolvedService
// records. Disabled or empty-named entries are dropped. Ports auto-assign in
// listing order from servicePortBase when not pinned. This is the single
// source of truth both the proxy and the FFI launcher read from.
//
// vfsMountpoint, when non-empty, is the local directory (a hanzoai/vfs mount;
// see vfsmount.go) under which DB-backed services keep their SQLite files. It is
// only applied to a DB-backed service that did not set an explicit database_url,
// so an operator can always override per service.
func resolveServices(cfg ServicesConfig, vfsMountpoint string) []resolvedService {
	if !cfg.Enabled {
		return nil
	}
	out := make([]resolvedService, 0, len(cfg.Services))
	next := servicePortBase
	for _, s := range cfg.Services {
		if s.Name == "" {
			continue
		}
		if s.Enabled != nil && !*s.Enabled {
			continue
		}
		// Default a DB-backed service to a SQLite file on the vfs mount when no
		// explicit url was given. sqlite://<mountpoint>/<name>.db?mode=rwc — the
		// launcher's initialize_database creates the file (mode=rwc) and skips
		// the Postgres CREATE DATABASE dance. See database.rs.
		if s.DatabaseURL == "" && vfsMountpoint != "" && dbBackedServices[s.Name] {
			s.DatabaseURL = fmt.Sprintf("sqlite://%s?mode=rwc",
				filepath.Join(vfsMountpoint, s.Name+".db"))
		}
		httpPort := s.HTTPPort
		grpcPort := s.GRPCPort
		if httpPort == 0 {
			httpPort = next
		}
		if grpcPort == 0 {
			grpcPort = httpPort + 1
		}
		// Advance the auto-allocator past whatever this service consumed so
		// the next unpinned service doesn't collide.
		if httpPort >= next {
			next = httpPort + 2
		}
		prefix := s.Prefix
		if prefix == "" {
			if p, ok := defaultPrefix[s.Name]; ok {
				prefix = p
			} else {
				prefix = s.Name
			}
		}
		out = append(out, resolvedService{
			Name:         s.Name,
			Prefix:       strings.Trim(prefix, "/"),
			HTTPPort:     httpPort,
			GRPCPort:     grpcPort,
			SettingsJSON: buildSettingsJSON(s, httpPort, grpcPort),
		})
	}
	return out
}

// buildSettingsJSON renders the JSON the service's upstream `Settings`
// deserializes. Every wrapped service is launcher-based and shares the
// `server.http.addr` / `server.grpc.addr` shape; we bind every service to
// 127.0.0.1 (loopback) so the zip front router is the only thing exposed.
//
// DB-backed services (stats) read their connection + behaviour as FLAT
// top-level keys (`db_url`, `run_migrations`, `create_database`), NOT a nested
// `database` object — and their `Settings` are `deny_unknown_fields`, so an
// unknown key fails the parse. dbSettings() adds exactly the flat keys the
// service expects. Service-specific overrides from ServiceConfig.Settings are
// merged LAST so an operator can override any derived field.
func buildSettingsJSON(s ServiceConfig, httpPort, grpcPort int) string {
	m := map[string]any{
		"server": map[string]any{
			"http": map[string]any{
				"enabled": true,
				"addr":    fmt.Sprintf("127.0.0.1:%d", httpPort),
			},
			"grpc": map[string]any{
				// gRPC stays enabled but on loopback; the front router only
				// proxies HTTP. Disabling it entirely is service-dependent, so
				// we just bind it somewhere harmless.
				"enabled": false,
				"addr":    fmt.Sprintf("127.0.0.1:%d", grpcPort),
			},
		},
		// Quiet the per-service metrics listener onto loopback too; it defaults
		// to 0.0.0.0:6060 which would collide if two services start.
		"metrics": map[string]any{
			"enabled": false,
			"addr":    fmt.Sprintf("127.0.0.1:%d", grpcPort+1),
		},
	}
	addServiceSettings(m, s)
	for k, v := range s.Settings {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		// map[string]any of strings/ints/bools never fails to marshal; keep a
		// safe fallback so a typo can't crash startup.
		return "{}"
	}
	return string(b)
}

// addServiceSettings stamps the service-specific top-level keys onto the
// settings map. Today only stats is wired; its Settings are flat and
// deny_unknown_fields, so we emit exactly what it reads:
//   - `db_url` / `create_database` / `run_migrations` (the SQLite DB on the vfs
//     mount; migrations are ported to SQLite so run_migrations is safe on).
//   - `ignore_blockscout_api_absence: true` so stats boots without a Blockscout
//     API url (the single binary has none — charts that need it are skipped).
//   - `charts_config` / `layout_config` / `update_groups_config` pointing at the
//     service's ConfigDir (absolute) so it finds them regardless of the
//     explorer's CWD. Omitted when ConfigDir is empty (service uses its own
//     relative defaults).
func addServiceSettings(m map[string]any, s ServiceConfig) {
	if !dbBackedServices[s.Name] {
		return
	}
	if s.DatabaseURL != "" {
		m["db_url"] = s.DatabaseURL
		m["create_database"] = true
		m["run_migrations"] = true
	}
	// stats requires a Blockscout API only for a subset of charts; without one
	// it must be told to proceed rather than hard-fail at boot.
	m["ignore_blockscout_api_absence"] = true
	if s.ConfigDir != "" {
		m["charts_config"] = filepath.Join(s.ConfigDir, "charts.json")
		m["layout_config"] = filepath.Join(s.ConfigDir, "layout.json")
		m["update_groups_config"] = filepath.Join(s.ConfigDir, "update_groups.json")
	}
}

// mountServiceProxies registers a reverse-proxy on the zip front App for each
// resolved in-process service: /v1/<prefix>/* → http://127.0.0.1:<http_port>.
//
// We strip the /v1/<prefix> mount prefix before forwarding so the upstream
// service sees the path it expects (e.g. /api/v1/abi/... not
// /v1/sig/api/v1/abi/...). zip.AdaptNetHTTP wraps the stdlib
// httputil.ReverseProxy onto a zip route — the simplest thing that works, per
// the brief: no bespoke fasthttp proxy, no escape hatch.
//
// Mounted via app.Mount which registers `All(prefix+"/*")`. These are
// registered BEFORE the catch-all explorer mux (see buildFrontApp) so Fiber's
// in-order matching routes /v1/<prefix>/* to the service and everything else
// to the explorer.
func mountServiceProxies(app *zip.App, svcs []resolvedService) {
	for _, s := range svcs {
		target := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", s.HTTPPort)}
		mountPrefix := "/v1/" + s.Prefix
		rp := httputil.NewSingleHostReverseProxy(target)
		// Strip the /v1/<prefix> mount prefix so the upstream sees its own
		// native path. NewSingleHostReverseProxy's default Director only sets
		// the host; we extend it to rewrite the path.
		base := rp.Director
		stripped := mountPrefix
		rp.Director = func(req *http.Request) {
			base(req)
			p := strings.TrimPrefix(req.URL.Path, stripped)
			if p == "" {
				p = "/"
			}
			req.URL.Path = p
			req.Host = target.Host
		}
		app.Mount(mountPrefix, rp)
	}
}
