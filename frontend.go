package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// staticFS is the embedded SPA. The Dockerfile populates static/ from a
// luxfi/explore build before the Go build runs; for local dev a placeholder
// index.html is committed so go:embed always succeeds.
//
//go:embed all:static
var staticFS embed.FS

// Frontend serves the embedded SPA, runtime config (/envs.js), and per-host
// brand assets (/icon.svg, /logo.svg). Brand assets read from disk on every
// request so a deploy can swap them without rebuilding the binary.
type Frontend struct {
	cfg      Config
	registry *ChainRegistry
	root     fs.FS
	index    []byte
}

// NewFrontend returns a frontend handler bound to a config and chain registry.
func NewFrontend(cfg Config, r *ChainRegistry) (*Frontend, error) {
	root, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	idx, err := fs.ReadFile(root, "index.html")
	if err != nil {
		idx = []byte("<!doctype html><title>Explorer</title>")
	}
	return &Frontend{cfg: cfg, registry: r, root: root, index: idx}, nil
}

// Mount installs / (SPA), /envs.js, /icon.svg, /logo.svg on mux.
func (f *Frontend) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /envs.js", f.handleEnvs)
	mux.HandleFunc("GET /icon.svg", f.handleIcon)
	mux.HandleFunc("GET /logo.svg", f.handleLogo)
	mux.HandleFunc("/", f.handleSPA)
}

// handleSPA serves embedded static assets and falls back to index.html for
// any path the SPA owns (client-side routing).
func (f *Frontend) handleSPA(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/")
	if p == "" {
		f.writeIndex(w)
		return
	}
	file, err := f.root.Open(p)
	if err != nil {
		f.writeIndex(w)
		return
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || stat.IsDir() {
		f.writeIndex(w)
		return
	}
	http.ServeFileFS(w, r, f.root, p)
}

func (f *Frontend) writeIndex(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(f.index)
}

// handleEnvs returns runtime config the SPA reads instead of build-time env
// vars. This is what makes per-network customization possible without a
// rebuild: deploy the same image, mount a different chains.yaml, get a
// different brand + chain list.
func (f *Frontend) handleEnvs(w http.ResponseWriter, r *http.Request) {
	hostBrand := f.brandForHost(r.Host)
	chains := f.chainListJSON()

	env := map[string]any{
		"VITE_CHAINS":   chains,
		"VITE_NETWORKS": f.cfg.Networks,
		"VITE_BRAND":    hostBrand,
	}
	body, _ := json.Marshal(env)

	var buf bytes.Buffer
	buf.WriteString("window.ENV = ")
	buf.Write(body)
	buf.WriteString(";\n")

	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(buf.Bytes())
}

// handleIcon serves the per-host or default icon.svg from disk.
func (f *Frontend) handleIcon(w http.ResponseWriter, r *http.Request) {
	f.serveBrandFile(w, r, func(b Brand) string { return b.IconFile }, "icon.svg")
}

// handleLogo serves the per-host or default logo.svg from disk.
func (f *Frontend) handleLogo(w http.ResponseWriter, r *http.Request) {
	f.serveBrandFile(w, r, func(b Brand) string { return b.LogoFile }, "logo.svg")
}

// serveBrandFile resolves the file path from the matched brand (per-chain or
// default) and sends it. Falls back to the embedded SPA's named asset if no
// disk override is configured.
func (f *Frontend) serveBrandFile(w http.ResponseWriter, r *http.Request, pick func(Brand) string, fallback string) {
	brand := f.brandStruct(r.Host)
	if path := pick(brand); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			w.Header().Set("Content-Type", contentTypeFor(path))
			w.Header().Set("Cache-Control", "public, max-age=300")
			w.Write(data)
			return
		}
	}
	if data, err := fs.ReadFile(f.root, fallback); err == nil {
		w.Header().Set("Content-Type", contentTypeFor(fallback))
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(data)
		return
	}
	http.NotFound(w, r)
}

// brandForHost returns a JSON-shaped brand for /envs.js. It strips file paths.
func (f *Frontend) brandForHost(host string) map[string]any {
	b := f.brandStruct(host)
	return map[string]any{
		"name":        b.Name,
		"coin":        b.Coin,
		"accentColor": b.AccentColor,
		"iconUrl":     b.IconURL,
		"logoUrl":     b.LogoURL,
	}
}

// brandStruct returns the Brand for a request host: a chain whose name or
// slug matches the hostname wins; otherwise the global default.
func (f *Frontend) brandStruct(host string) Brand {
	host = strings.ToLower(strings.SplitN(host, ":", 2)[0])
	for _, c := range f.cfg.Chains {
		if c.Brand == nil {
			continue
		}
		if strings.HasPrefix(host, c.Slug+".") || host == c.Slug {
			return *c.Brand
		}
	}
	return f.cfg.BrandDefault
}

// chainListJSON returns a SPA-friendly chain list from the live registry,
// not the static config — chains added via mDNS/admin show up immediately.
var chainListMu sync.Mutex

func (f *Frontend) chainListJSON() []map[string]any {
	chainListMu.Lock()
	defer chainListMu.Unlock()
	out := []map[string]any{}
	if f.registry == nil {
		return out
	}
	for _, c := range f.registry.List() {
		out = append(out, map[string]any{
			"slug":    c.Slug,
			"name":    c.Name,
			"chainId": c.ChainID,
			"rpc":     c.RPC,
			"coin":    c.CoinSymbol,
			"type":    c.Type,
			"default": c.Default,
		})
	}
	return out
}

// contentTypeFor maps a file extension to a Content-Type, defaulting to
// application/octet-stream.
func contentTypeFor(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".svg":
		return "image/svg+xml"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	case ".ico":
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

// fingerprint returns a short, stable identifier for the embedded asset
// bundle, useful for cache-busting log lines at startup.
func fingerprint() string {
	root, err := fs.Sub(staticFS, "static")
	if err != nil {
		return "0"
	}
	count := 0
	_ = fs.WalkDir(root, ".", func(_ string, _ fs.DirEntry, _ error) error {
		count++
		return nil
	})
	return fmt.Sprintf("assets=%d", count)
}
