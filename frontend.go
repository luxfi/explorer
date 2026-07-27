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

// staticFS embeds named brand assets only — icon.svg and logo.svg
// fallbacks. As of v1.3.0 the Go binary no longer serves the Blockscout
// SPA; each brand's FE runs as its own per-(brand, env) Deployment
// (ghcr.io/{org}/explore-{env}:vX.Y.Z) and the IngressRoute routes the
// catch-all to that FE Service. The Go binary keeps /v1/* (indexer +
// blockscout-compat APIs), /health, /envs.js, and the per-host brand
// SVG endpoints — every other path returns 404.
//
//go:embed all:static
var staticFS embed.FS

// Frontend serves runtime config (/envs.js) and per-host brand assets
// (/icon.svg, /logo.svg). Brand assets read from disk on every request so a
// deploy can swap them without rebuilding the binary.
//
// Static directory override: if cfg.StaticDir (or $EXPLORER_STATIC_DIR)
// points at an existing directory, brand-asset lookups prefer the on-disk
// copy over the embedded FS. This lets a ConfigMap-mounted SVG bundle
// override the in-binary defaults without rebuilding.
//
// SPA serving was removed in v1.3.0 — the catch-all `/` route is gone and
// any path not explicitly registered returns 404. The per-brand
// Blockscout FE Deployment (ghcr.io/{brand-org}/explore-{env}) owns the
// SPA surface.
type Frontend struct {
	cfg      Config
	registry *ChainRegistry
	root     fs.FS // embedded brand-asset FS (always present)
	overlay  fs.FS // disk overlay (nil if cfg.StaticDir not set)
}

// NewFrontend returns a frontend handler bound to a config and chain registry.
func NewFrontend(cfg Config, r *ChainRegistry) (*Frontend, error) {
	root, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	f := &Frontend{cfg: cfg, registry: r, root: root}

	dir := cfg.StaticDir
	if dir == "" {
		dir = os.Getenv("EXPLORER_STATIC_DIR")
	}
	if dir != "" {
		if st, err := os.Stat(dir); err == nil && st.IsDir() {
			f.overlay = os.DirFS(dir)
		}
	}
	return f, nil
}

// readStatic returns the bytes for `name` from the overlay if present,
// otherwise from the embedded FS. Returns nil if neither has the file.
func (f *Frontend) readStatic(name string) []byte {
	if f.overlay != nil {
		if data, err := fs.ReadFile(f.overlay, name); err == nil {
			return data
		}
	}
	if data, err := fs.ReadFile(f.root, name); err == nil {
		return data
	}
	return nil
}

// Mount installs the data-layer endpoints — /envs.js, /icon.svg,
// /logo.svg, plus any extra brand SVGs present in the overlay (e.g.
// /icon-zoo.svg, /logo-lux.svg). No catch-all SPA route: any other path
// returns 404 so the IngressRoute layer routes it to the per-brand
// Blockscout FE Deployment.
func (f *Frontend) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /envs.js", f.handleEnvs)
	mux.HandleFunc("GET /icon.svg", f.handleIcon)
	mux.HandleFunc("GET /logo.svg", f.handleLogo)
	for _, name := range f.brandAssetNames() {
		mux.HandleFunc("GET /"+name, f.handleNamedBrandAsset(name))
	}
}

// brandAssetNames lists every per-brand SVG/PNG file the overlay (or the
// embedded FS) carries. Used to register one explicit handler per file at
// startup so the rest of the path-space cleanly 404s.
func (f *Frontend) brandAssetNames() []string {
	seen := map[string]struct{}{}
	var out []string
	collect := func(dir fs.FS) {
		if dir == nil {
			return
		}
		entries, err := fs.ReadDir(dir, ".")
		if err != nil {
			return
		}
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() || n == "icon.svg" || n == "logo.svg" {
				continue
			}
			switch strings.ToLower(filepath.Ext(n)) {
			case ".svg", ".png", ".jpg", ".jpeg", ".webp", ".ico":
			default:
				continue
			}
			if _, ok := seen[n]; ok {
				continue
			}
			seen[n] = struct{}{}
			out = append(out, n)
		}
	}
	collect(f.overlay)
	collect(f.root)
	return out
}

// handleNamedBrandAsset returns a handler that serves a specific named
// file from the overlay (preferred) or the embedded FS. 404 if neither
// has it.
func (f *Frontend) handleNamedBrandAsset(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if data := f.readStatic(name); data != nil {
			w.Header().Set("Content-Type", contentTypeFor(name))
			w.Header().Set("Cache-Control", "public, max-age=300")
			w.Write(data)
			return
		}
		http.NotFound(w, r)
	}
}

// handleEnvs returns runtime config the SPA reads instead of build-time env
// vars. This is what makes per-network customization possible without a
// rebuild: deploy the same image, mount a different chains.yaml, get a
// different brand + chain list.
func (f *Frontend) handleEnvs(w http.ResponseWriter, r *http.Request) {
	hostBrand := f.brandForHost(r.Host)
	hostSlug := f.chainSlugForHost(r.Host)
	chains := f.chainListJSON()
	// When the host pins a specific chain (e.g. explore.zoo.network →
	// zoo, explorer.zoo-test.network → zoo), promote that chain to
	// default and demote any other config-level default. The SPA's chain
	// switcher honours the "default" flag.
	if hostSlug != "" {
		for i := range chains {
			if chains[i]["slug"] == hostSlug {
				chains[i]["default"] = true
			} else {
				chains[i]["default"] = false
			}
		}
	}

	current, peers := f.networksForHost(r.Host)
	env := map[string]any{
		"VITE_CHAINS":          chains,
		"VITE_NETWORKS":        networkSwitcher(f.cfg.Networks, peers),
		"VITE_BRAND":           hostBrand,
		"VITE_CURRENT_NETWORK": current,
		"VITE_NETWORK_HOSTS":   peers,
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
// default) and sends it. Falls back to the on-disk overlay (if configured)
// then the embedded SPA's named asset.
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
	if data := f.readStatic(fallback); data != nil {
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
//
// See hostMatchesSlug for the list of supported hostname shapes.
func (f *Frontend) brandStruct(host string) Brand {
	if c, ok := f.matchChain(host); ok && c.Brand != nil {
		return *c.Brand
	}
	return f.cfg.BrandDefault
}

// chainSlugForHost returns the slug of the chain pinned by the request host,
// or "" if the host does not name a chain. Used by handleEnvs to promote a
// per-host chain to the SPA's default selection.
func (f *Frontend) chainSlugForHost(host string) string {
	if c, ok := f.matchChain(host); ok {
		return c.Slug
	}
	return ""
}

// matchChain finds the first configured chain whose slug appears in the
// request host. Matches these hostname shapes, in order of specificity:
//   - "{slug}"                             — bare slug (curl localhost)
//   - "{slug}.tld..."                      — {slug}.lux.network, {slug}.hanzo.ai
//   - "explore-{slug}.tld..."              — explore-hanzo.lux.network
//   - "explorer-{slug}.tld..."             — explorer-hanzo.lux.network
//   - "api-explore-{slug}.tld..."          — api-explore-hanzo.lux.network
//   - "explore.{slug}.tld..."              — explore.hanzo.ai, explore.zoo.ngo
//   - "explorer.{slug}.tld..."             — explorer.hanzo.ai, explorer.zoo.network
//   - "api-explore.{slug}.tld..."          — api-explore.hanzo.ai
//   - "explore-{slug}-{env}.tld..."        — explore-hanzo-test.lux.network
//   - "explorer-{slug}-{env}.tld..."       — explorer-hanzo-test.lux.network
//   - "api-explore-{slug}-{env}.tld..."    — api-explore-hanzo-dev.lux.network
//   - "explore.{slug}-{env}.tld..."        — explore.zoo-test.network
//   - "explorer.{slug}-{env}.tld..."       — explorer.zoo-test.network
//   - "api-explore.{slug}-{env}.tld..."    — api-explore.zoo-test.network
//
// First chain match wins on ambiguous hosts.
func (f *Frontend) matchChain(host string) (ChainConfig, bool) {
	host = strings.ToLower(strings.SplitN(host, ":", 2)[0])
	for _, c := range f.cfg.Chains {
		if hostMatchesSlug(host, c.Slug) {
			return c, true
		}
	}
	return ChainConfig{}, false
}

// hostMatchesSlug is the pure string predicate for chain↔host matching.
// Kept separate from matchChain so unit tests can cover it directly.
func hostMatchesSlug(host, slug string) bool {
	if slug == "" {
		return false
	}
	if host == slug {
		return true
	}
	// Direct slug-as-subdomain: zoo.lux.network, hanzo.ai.
	if strings.HasPrefix(host, slug+".") || strings.HasPrefix(host, slug+"-") {
		return true
	}
	// Brand-owned domains: explore.zoo.network, explorer.zoo-test.network,
	// api-explore.zoo.ngo, etc. Each "explore"/"explorer" prefix combines
	// with "." or "-" as the slug separator.
	prefixes := []string{
		"explore-", "explorer-",
		"api-explore-", "api-explorer-",
		"explore.", "explorer.",
		"api-explore.", "api-explorer.",
	}
	for _, p := range prefixes {
		// {prefix}{slug}.tld  — e.g. explore.zoo.network, explore-zoo.lux.network
		if strings.HasPrefix(host, p+slug+".") {
			return true
		}
		// {prefix}{slug}-{env}.tld — e.g. explore-zoo-test.lux.network,
		// explorer.zoo-test.network
		if strings.HasPrefix(host, p+slug+"-") {
			return true
		}
	}
	return false
}

// networksForHost returns (current network label, sibling host map). The
// SPA renders a "Network: mainnet ▾" dropdown — when the user picks
// another label, the SPA redirects to the corresponding host. Hosts are
// derived purely from the request host: explore.zoo.network (mainnet)
// has sibling explorer.zoo-test.network (testnet); explore.lux.network
// has sibling explorer.lux-test.network; and the reverse.
//
// Host shape rules:
//   - mainnet: prefix is "explore.", brand domain is "<brand>.<tld>"
//     (e.g. zoo.network, lux.network, hanzo.ai). Sibling is
//     "explorer.<brand>-test.network".
//   - testnet: prefix is "explorer.", brand domain is "<brand>-test.network".
//     Sibling is "explore.<brand>.network" (or .ai / .ngo per brand
//     when known; we default to .network because all the actual
//     deployed testnet hosts are *.network).
//   - lux.network (no brand prefix, generic explore.lux.network) is
//     special-cased: mainnet=explore.lux.network, testnet=explorer.lux-test.network.
//
// If we can't classify the host (admin tooling on localhost, internal
// service-mesh hostnames), we return ("", nil) and the SPA omits the
// dropdown.
// networkSwitcher renders the cross-network switcher entries. Domains come
// from peers — derived from the request host by networksForHost, which is
// the only thing that knows what a sibling network is actually called. The
// config's `networks[].domain` is a second, hand-maintained copy of that
// same fact, and it had drifted: it advertised
// testnet.explore.lux.network and devnet.explore.lux.network, neither of
// which resolves, while the live hosts are explorer.lux-{test,dev}.network.
// Config keeps what only config knows — the label and the chain ID.
func networkSwitcher(configured []Network, peers map[string]string) []Network {
	out := make([]Network, 0, len(configured))
	for _, n := range configured {
		if derived, ok := peers[strings.ToLower(n.Label)]; ok && derived != "" {
			n.Domain = derived
		}
		out = append(out, n)
	}
	return out
}

func (f *Frontend) networksForHost(host string) (string, map[string]string) {
	host = strings.ToLower(strings.SplitN(host, ":", 2)[0])

	// Find the brand stem and current env from the host. The two
	// shapes we support are "{prefix}.{brand}.{tld}" (mainnet) and
	// "{prefix}.{brand}-{env}.{tld}" (non-mainnet).
	brand, env, dotted, ok := parseBrandEnv(host)
	if !ok {
		return "", nil
	}

	// All deployed testnet/devnet hosts are *.network. Mainnet
	// brand hosts vary: zoo.network, lux.network, hanzo.ai, hanzo.network,
	// zoo.ngo, etc. For the round-trip from testnet back to mainnet
	// we need to know which mainnet TLD the brand uses. When the user
	// is already on a brand-owned domain (explore.{brand}.{tld}),
	// preserve that TLD so the mainnet option is idempotent. When the
	// user is on the lux.network-prefix shape (explore-{brand}.lux.network)
	// or any non-brand-owned shape, default to ".network" — every brand
	// we ship has an X.network mainnet alias.
	mainnetTLD := ".network"
	if env == "" && dotted {
		if dot := strings.Index(host, brand+"."); dot >= 0 {
			mainnetTLD = host[dot+len(brand):]
		}
	}

	mainnetHost := "explore." + brand + mainnetTLD
	testnetHost := "explorer." + brand + "-test.network"

	// Every sibling host is derivable from the brand, so derive all of
	// them unconditionally. Handing back only the ones the current env
	// happened to need left the switcher's remaining entries falling back
	// to hand-written config domains that no longer resolve.
	peers := map[string]string{
		"mainnet": mainnetHost,
		"testnet": testnetHost,
		"devnet":  "explorer." + brand + "-dev.network",
	}
	switch env {
	case "":
		return "mainnet", peers
	case "test", "testnet":
		return "testnet", peers
	case "dev", "devnet":
		return "devnet", peers
	default:
		return env, peers
	}
}

// parseBrandEnv extracts the brand stem and env tag from a host. Recognizes:
//
//	explore.{brand}.{tld}                  → ({brand}, "", dotted=true)
//	explorer.{brand}.{tld}                 → ({brand}, "", dotted=true)
//	explore.{brand}-{env}.{tld}            → ({brand}, {env}, dotted=true)
//	explorer.{brand}-{env}.{tld}           → ({brand}, {env}, dotted=true)
//	explore-{brand}.lux.network            → ({brand}, "", dotted=false)
//	explore-{brand}-{env}.lux.network      → ({brand}, {env}, dotted=false)
//
// Returns ok=false on hosts we can't classify (localhost, IPs, internal
// service-mesh names like *.svc.cluster.local).
//
// `dotted` distinguishes brand-owned hosts (explore.zoo.network — TLD
// belongs to the brand) from lux-prefix hosts (explore-zoo.lux.network —
// brand is just a subdomain on lux.network) so the network switcher can
// pick the right mainnet TLD for the sibling URL.
func parseBrandEnv(host string) (brand, env string, dotted, ok bool) {
	if host == "" || strings.HasSuffix(host, ".svc.cluster.local") || strings.HasSuffix(host, ".local") {
		return "", "", false, false
	}
	stripPrefix := func(s, p string) (string, bool) {
		if strings.HasPrefix(s, p) {
			return s[len(p):], true
		}
		return s, false
	}

	// "explore.{brand}{maybe-env}.{tld}" / "explorer.{brand}{maybe-env}.{tld}"
	for _, p := range []string{"explore.", "explorer.", "api-explore.", "api-explorer."} {
		rest, matched := stripPrefix(host, p)
		if !matched {
			continue
		}
		dot := strings.Index(rest, ".")
		if dot < 1 {
			return "", "", false, false
		}
		stem := rest[:dot]
		brand, env = splitBrandEnv(stem)
		if !isValidBrand(brand) {
			return "", "", false, false
		}
		return brand, env, true, true
	}

	// "explore-{brand}{maybe-env}.lux.network" / "explorer-{brand}{maybe-env}.lux.network"
	for _, p := range []string{"explore-", "explorer-", "api-explore-", "api-explorer-"} {
		rest, matched := stripPrefix(host, p)
		if !matched {
			continue
		}
		dot := strings.Index(rest, ".")
		if dot < 1 {
			return "", "", false, false
		}
		stem := rest[:dot]
		brand, env = splitBrandEnv(stem)
		if !isValidBrand(brand) {
			return "", "", false, false
		}
		return brand, env, false, true
	}

	return "", "", false, false
}

// isValidBrand restricts brand stems to alphabetic (or digit-containing) tokens
// at least 2 chars long. Rejects numeric-only stems (IP addresses), empty,
// and stems beginning with a digit (so "10" from "10.0.0.1" never matches).
func isValidBrand(s string) bool {
	if len(s) < 2 {
		return false
	}
	if s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// splitBrandEnv splits "zoo-test" into ("zoo", "test"); "zoo" stays as ("zoo", "").
// Only recognises known env suffixes (test, testnet, dev, devnet, local) so
// hyphenated brand names ("api-zoo-exchange") still parse as one stem.
func splitBrandEnv(stem string) (brand, env string) {
	for _, e := range []string{"-test", "-testnet", "-dev", "-devnet", "-local"} {
		if strings.HasSuffix(stem, e) {
			return strings.TrimSuffix(stem, e), strings.TrimPrefix(e, "-")
		}
	}
	return stem, ""
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
