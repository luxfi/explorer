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
