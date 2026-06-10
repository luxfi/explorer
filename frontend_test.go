package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFrontendStaticOverlay verifies that NewFrontend prefers the on-disk
// static dir over the embedded FS when cfg.StaticDir points at a real
// directory. The overlay use-case: ConfigMap-mounting a richer SPA shell
// into an existing image without rebuilding.
func TestFrontendStaticOverlay(t *testing.T) {
	dir := t.TempDir()
	want := "<!doctype html><title>OVERLAY</title>"
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte(want), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{StaticDir: dir, BrandDefault: Brand{Name: "Test"}}
	f, err := NewFrontend(cfg, NewChainRegistry())
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	f.Mount(mux)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	got := rec.Body.String()
	if !strings.Contains(got, "OVERLAY") {
		t.Fatalf("expected overlay index.html, got %q", got)
	}
}

// TestFrontendNoOverlay verifies that with no StaticDir, the embedded
// index.html is served (current behaviour — pre-overlay).
func TestFrontendNoOverlay(t *testing.T) {
	cfg := Config{BrandDefault: Brand{Name: "Test"}}
	f, err := NewFrontend(cfg, NewChainRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if f.overlay != nil {
		t.Fatal("expected nil overlay when StaticDir empty")
	}

	mux := http.NewServeMux()
	f.Mount(mux)

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	got := rec.Body.String()
	if !strings.Contains(got, "doctype html") {
		t.Fatalf("expected fallback index.html, got %q", got)
	}
}

// TestFrontendOverlayMissingFileFallsBack covers the case where the
// overlay dir exists but a particular file is missing — the request
// falls through to the embedded FS (and ultimately to index.html for
// SPA-routing).
func TestFrontendOverlayMissingFileFallsBack(t *testing.T) {
	dir := t.TempDir()
	// Only index.html in overlay; no other assets.
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>OVERLAY"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{StaticDir: dir, BrandDefault: Brand{Name: "Test"}}
	f, err := NewFrontend(cfg, NewChainRegistry())
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	f.Mount(mux)

	// Request a path the overlay doesn't have. With SPA-routing, the
	// handler returns index.html — which IS in the overlay.
	req := httptest.NewRequest("GET", "/some/spa/route", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	got := rec.Body.String()
	if !strings.Contains(got, "OVERLAY") {
		t.Fatalf("expected overlay index.html (SPA fallback), got %q", got)
	}
}

// TestFrontendEnvStaticDir verifies $EXPLORER_STATIC_DIR is the env-var
// equivalent of cfg.StaticDir. Empty cfg + env-var-set overlay should
// still pick up the overlay.
func TestFrontendEnvStaticDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("ENV-OVERLAY"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXPLORER_STATIC_DIR", dir)

	cfg := Config{BrandDefault: Brand{Name: "Test"}}
	f, err := NewFrontend(cfg, NewChainRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if f.overlay == nil {
		t.Fatal("expected overlay populated from env var")
	}
	if !strings.Contains(string(f.index), "ENV-OVERLAY") {
		t.Fatalf("expected env-overlay index, got %q", string(f.index))
	}
}

// TestBrandStructHostMatching covers every hostname shape the unified
// explorer's IngressRoutes hand it: the per-chain brand must win over
// BrandDefault for both UI hosts (explore-{slug}, explore.{slug}.tld)
// and API hosts (api-explore-{slug}). The matcher must NOT bleed across
// chains — a hanzo host must not pick zoo's brand or vice versa.
func TestBrandStructHostMatching(t *testing.T) {
	hanzoBrand := Brand{Name: "Hanzo", Coin: "AI", AccentColor: "#0b1220"}
	zooBrand := Brand{Name: "Zoo", Coin: "ZOO", AccentColor: "#7c3aed"}
	cfg := Config{
		BrandDefault: Brand{Name: "Lux Explorer"},
		Chains: []ChainConfig{
			{Slug: "cchain", Brand: &Brand{Name: "Lux C-Chain", Coin: "LUX"}},
			{Slug: "hanzo", Brand: &hanzoBrand},
			{Slug: "zoo", Brand: &zooBrand},
		},
	}
	f, err := NewFrontend(cfg, NewChainRegistry())
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		host string
		want string
	}{
		// Bare slug + slug-prefix shape.
		{"hanzo", "Hanzo"},
		{"hanzo.lux.network", "Hanzo"},
		// explore-{slug} prefix shape (lux.network UI hosts).
		{"explore-hanzo.lux.network", "Hanzo"},
		{"explore-hanzo-test.lux.network", "Hanzo"},
		{"explore-hanzo-dev.lux.network", "Hanzo"},
		{"explore-zoo.lux.network", "Zoo"},
		// api-explore-{slug} prefix shape (lux.network API hosts).
		{"api-explore-hanzo.lux.network", "Hanzo"},
		{"api-explore-hanzo-test.lux.network", "Hanzo"},
		{"api-explore-zoo.lux.network", "Zoo"},
		// explore.{slug}.tld shape (brand-owned domains).
		{"explore.hanzo.ai", "Hanzo"},
		{"explore.hanzo.network", "Hanzo"},
		{"explore.zoo.network", "Zoo"},
		{"explore.zoo.ngo", "Zoo"},
		{"api-explore.hanzo.ai", "Hanzo"},
		{"api-explore.zoo.ngo", "Zoo"},
		// explorer.{slug}.tld shape (alias of explore.* for brand-owned domains).
		{"explorer.zoo.network", "Zoo"},
		{"explorer.hanzo.ai", "Hanzo"},
		// {slug}-{env}.tld shape — brand-owned testnet/devnet domains.
		// explorer.zoo-test.network is the primary case this fixes.
		{"explorer.zoo-test.network", "Zoo"},
		{"explore.zoo-test.network", "Zoo"},
		{"explorer.hanzo-test.network", "Hanzo"},
		{"api-explore.zoo-test.network", "Zoo"},
		// Mismatched hosts fall back to BrandDefault.
		{"explore.lux.network", "Lux Explorer"},
		{"unknown.example.com", "Lux Explorer"},
		// Cross-contamination guard: explore-spcfoo must NOT match spc.
		{"explore-spcfoo.lux.network", "Lux Explorer"},
		// Cross-contamination guard: zoofoo must NOT match zoo.
		{"explore.zoofoo.network", "Lux Explorer"},
		{"explorer.zoofoo.network", "Lux Explorer"},
	}

	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			got := f.brandStruct(tc.host).Name
			if got != tc.want {
				t.Fatalf("host=%q: got brand=%q, want %q", tc.host, got, tc.want)
			}
		})
	}
}

// TestChainSlugForHost covers the host→default-chain promotion that
// handleEnvs uses to set the SPA's initial chain selection. Hosts that
// pin a chain (explore.zoo.network, explorer.zoo-test.network) must
// return the slug; generic hosts (explore.lux.network) must return "".
func TestChainSlugForHost(t *testing.T) {
	zooBrand := Brand{Name: "Zoo"}
	hanzoBrand := Brand{Name: "Hanzo"}
	cfg := Config{
		BrandDefault: Brand{Name: "Lux Explorer"},
		Chains: []ChainConfig{
			{Slug: "cchain", Brand: &Brand{Name: "Lux C-Chain"}},
			{Slug: "hanzo", Brand: &hanzoBrand},
			{Slug: "zoo", Brand: &zooBrand},
		},
	}
	f, err := NewFrontend(cfg, NewChainRegistry())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host string
		want string
	}{
		{"explore.zoo.network", "zoo"},
		{"explore.zoo.ngo", "zoo"},
		{"explorer.zoo.network", "zoo"},
		{"explorer.zoo-test.network", "zoo"},
		{"explore.zoo-test.network", "zoo"},
		{"explore-zoo.lux.network", "zoo"},
		{"explore-zoo-test.lux.network", "zoo"},
		{"explore.hanzo.ai", "hanzo"},
		{"explorer.hanzo-test.network", "hanzo"},
		// Generic / mismatched hosts: no slug.
		{"explore.lux.network", ""},
		{"unknown.example.com", ""},
		{"explore.zoofoo.network", ""},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			got := f.chainSlugForHost(tc.host)
			if got != tc.want {
				t.Fatalf("host=%q: got slug=%q, want %q", tc.host, got, tc.want)
			}
		})
	}
}
