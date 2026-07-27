package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFrontendNoSPA verifies the v1.3.0 contract — the Go binary does
// NOT serve a SPA. Any non-data-layer path returns 404 so the
// IngressRoute hands it off to the per-brand Blockscout FE Deployment.
// Compare to the pre-v1.3.0 behaviour where `/` returned an embedded
// index.html.
func TestFrontendNoSPA(t *testing.T) {
	cfg := Config{BrandDefault: Brand{Name: "Test"}}
	f, err := NewFrontend(cfg, NewChainRegistry())
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	f.Mount(mux)

	for _, p := range []string{"/", "/block/1", "/_next/static/chunks/foo.js", "/some/random/path"} {
		req := httptest.NewRequest("GET", p, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 404 {
			t.Errorf("path %q: got HTTP %d, want 404 (FE Deployment owns this surface now)", p, rec.Code)
		}
	}
}

// TestFrontendBrandAssetsServed verifies the data-layer endpoints still
// work — /envs.js, /icon.svg, /logo.svg, and any extra named asset (e.g.
// /icon-zoo.svg) the overlay carries. These are what the FE depends on
// from the Go binary.
func TestFrontendBrandAssetsServed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "icon.svg"), []byte("<svg/>"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "logo.svg"), []byte("<svg id=logo/>"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "icon-zoo.svg"), []byte("<svg id=zoo/>"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{StaticDir: dir, BrandDefault: Brand{Name: "Test"}}
	f, err := NewFrontend(cfg, NewChainRegistry())
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	f.Mount(mux)

	for _, tc := range []struct {
		path string
		want string
	}{
		{"/icon.svg", "<svg/>"},
		{"/logo.svg", "<svg id=logo/>"},
		{"/icon-zoo.svg", "<svg id=zoo/>"},
	} {
		req := httptest.NewRequest("GET", tc.path, nil)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Errorf("path %q: got HTTP %d, want 200", tc.path, rec.Code)
		}
		if got := rec.Body.String(); got != tc.want {
			t.Errorf("path %q: got body %q, want %q", tc.path, got, tc.want)
		}
	}
}

// TestFrontendOverlayFromEnv verifies $EXPLORER_STATIC_DIR is the env
// equivalent of cfg.StaticDir. The brand asset must be served from the
// overlay even with an empty cfg.
func TestFrontendOverlayFromEnv(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "icon.svg"), []byte("<svg id=env/>"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXPLORER_STATIC_DIR", dir)

	cfg := Config{BrandDefault: Brand{Name: "Test"}}
	f, err := NewFrontend(cfg, NewChainRegistry())
	if err != nil {
		t.Fatal(err)
	}
	if f.overlay == nil {
		t.Fatal("expected overlay populated from $EXPLORER_STATIC_DIR")
	}

	mux := http.NewServeMux()
	f.Mount(mux)
	req := httptest.NewRequest("GET", "/icon.svg", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "id=env") {
		t.Fatalf("expected env-overlay icon, got %q", rec.Body.String())
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

// TestNetworksForHost covers the network dropdown payload the SPA reads
// from /envs.js. Mainnet hosts return ("mainnet", siblings) and testnet
// hosts return ("testnet", siblings); unparseable hosts return ("", nil).
func TestNetworksForHost(t *testing.T) {
	cfg := Config{
		BrandDefault: Brand{Name: "Lux Explorer"},
		Chains: []ChainConfig{
			{Slug: "cchain"}, {Slug: "zoo"}, {Slug: "hanzo"},
		},
	}
	f, err := NewFrontend(cfg, NewChainRegistry())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		host        string
		wantCurrent string
		wantMainnet string
		wantTestnet string
	}{
		// Zoo (brand-owned domains).
		{"explore.zoo.network", "mainnet", "explore.zoo.network", "explorer.zoo-test.network"},
		{"explorer.zoo-test.network", "testnet", "explore.zoo.network", "explorer.zoo-test.network"},
		// Lux (brand-owned domains).
		{"explore.lux.network", "mainnet", "explore.lux.network", "explorer.lux-test.network"},
		{"explorer.lux-test.network", "testnet", "explore.lux.network", "explorer.lux-test.network"},
		// Hanzo brand on .ai mainnet, .network testnet.
		{"explore.hanzo.ai", "mainnet", "explore.hanzo.ai", "explorer.hanzo-test.network"},
		{"explorer.hanzo-test.network", "testnet", "explore.hanzo.network", "explorer.hanzo-test.network"},
		// lux.network prefix shape — explore-{slug}.lux.network.
		{"explore-zoo.lux.network", "mainnet", "explore.zoo.network", "explorer.zoo-test.network"},
		{"explore-zoo-test.lux.network", "testnet", "explore.zoo.network", "explorer.zoo-test.network"},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			cur, peers := f.networksForHost(tc.host)
			if cur != tc.wantCurrent {
				t.Errorf("current: got %q want %q", cur, tc.wantCurrent)
			}
			if peers["mainnet"] != tc.wantMainnet {
				t.Errorf("mainnet: got %q want %q", peers["mainnet"], tc.wantMainnet)
			}
			if peers["testnet"] != tc.wantTestnet {
				t.Errorf("testnet: got %q want %q", peers["testnet"], tc.wantTestnet)
			}
		})
	}

	// Unparseable hosts return empty.
	for _, h := range []string{"localhost", "10.0.0.1", "explorer.lux-mainnet.svc.cluster.local", ""} {
		cur, peers := f.networksForHost(h)
		if cur != "" || peers != nil {
			t.Errorf("expected empty result for %q, got cur=%q peers=%v", h, cur, peers)
		}
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

// The switcher's domains are derived from the request host, never from a
// hand-written config field. Config once carried its own copy and it had
// drifted to testnet.explore.lux.network / devnet.explore.lux.network —
// neither of which resolves — so the network switcher on a live explorer
// linked to nothing.
func TestNetworkSwitcherDerivesDomains(t *testing.T) {
	cfg := Config{
		BrandDefault: Brand{Name: "Lux Explorer"},
		Chains:       []ChainConfig{{Slug: "cchain"}},
		Networks: []Network{
			{Label: "Mainnet", Domain: "stale.example", ChainID: 96369},
			{Label: "Testnet", Domain: "testnet.explore.lux.network", ChainID: 96368},
			{Label: "Devnet", Domain: "devnet.explore.lux.network", ChainID: 96367},
		},
	}
	f, err := NewFrontend(cfg, NewChainRegistry())
	if err != nil {
		t.Fatalf("NewFrontend: %v", err)
	}

	_, peers := f.networksForHost("explore.lux.network")
	got := networkSwitcher(cfg.Networks, peers)

	want := map[string]string{
		"Mainnet": "explore.lux.network",
		"Testnet": "explorer.lux-test.network",
		"Devnet":  "explorer.lux-dev.network",
	}
	if len(got) != len(want) {
		t.Fatalf("want %d entries, got %d", len(want), len(got))
	}
	for _, n := range got {
		if n.Domain != want[n.Label] {
			t.Errorf("%s domain = %q, want %q", n.Label, n.Domain, want[n.Label])
		}
	}
	// Chain IDs are config's to know, and are left alone.
	if got[2].ChainID != 96367 {
		t.Errorf("devnet chainID = %d, want 96367 (genesis cChainGenesis.config.chainId)", got[2].ChainID)
	}
}
