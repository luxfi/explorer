package main

// front.go — zip is the FRONT HTTP router of the explorer binary.
//
// One zip.App owns the public listener. It composes two things, in order:
//
//   1. /v1/<prefix>/*  reverse-proxies to each in-process Blockscout-rs
//      service (mountServiceProxies, services.go). Registered FIRST so Fiber's
//      in-order route matching sends these to the Rust services.
//
//   2. /*  catch-all → the existing Go-native explorer (the *http.ServeMux
//      built in main.go: SPA, indexer, graph, realtime, admin). Adapted onto
//      zip via zip.AdaptNetHTTP — the stdlib mux is mounted whole, unchanged.
//
// This is the LEAST-WORK front: the explorer's net/http routes are reused
// verbatim, the Rust services keep their own HTTP servers, and zip just
// routes + proxies. The single seam to the in-process Rust world is the
// reverse-proxy target host:port — nothing in the Go HTTP layer knows or
// cares that the upstream is a cgo-launched Tokio thread.

import (
	"net/http"

	"github.com/hanzoai/zip"
	luxlog "github.com/luxfi/log"
)

// buildFrontApp constructs the zip front router. base is the fully-wired
// explorer mux (SPA + indexer + graph + realtime + admin) from main.go; svcs
// are the resolved in-process services to reverse-proxy. The returned App owns
// the public listener (App.Listen).
func buildFrontApp(base http.Handler, svcs []resolvedService) *zip.App {
	app := zip.New(zip.Config{
		AppName:               "lux-explorer",
		ServerHeader:          "explorer",
		DisableStartupMessage: true,
		Logger:                luxlog.New("module", "explorer"),
	})

	// Baseline security headers + permissive CORS, mirroring the previous
	// withSecurity wrapper. Runs on every request including the proxied ones.
	app.Use(func(c *zip.Ctx) error {
		c.SetHeader("X-Content-Type-Options", "nosniff")
		c.SetHeader("X-Frame-Options", "DENY")
		c.SetHeader("Referrer-Policy", "strict-origin-when-cross-origin")
		c.SetHeader("Access-Control-Allow-Origin", "*")
		c.SetHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.SetHeader("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Method() == "OPTIONS" {
			return c.NoContent(204)
		}
		return c.Continue()
	})

	// (1) Per-service reverse proxies — registered before the catch-all so
	// /v1/<prefix>/* wins over /*.
	mountServiceProxies(app, svcs)

	// (2) The whole existing explorer mux as the catch-all. zip.AdaptNetHTTP
	// turns the *http.ServeMux into a zip handler; All("/*") makes it the
	// fallback for everything the proxies above didn't claim.
	app.All("/*", zip.AdaptNetHTTP(base))

	return app
}
