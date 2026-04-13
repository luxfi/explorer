package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryAddAndList(t *testing.T) {
	r := NewChainRegistry()

	err := r.Add(ChainConfig{
		Slug:   "cchain",
		Name:   "C-Chain",
		RPC:    "http://localhost:9650/ext/bc/C/rpc",
		Type:   "evm",
		Source: "config",
	})
	if err != nil {
		t.Fatal(err)
	}

	if r.Count() != 1 {
		t.Fatalf("expected 1 chain, got %d", r.Count())
	}

	chains := r.List()
	if chains[0].Slug != "cchain" {
		t.Fatalf("expected slug cchain, got %s", chains[0].Slug)
	}
}

func TestRegistryInvalidSlug(t *testing.T) {
	r := NewChainRegistry()

	err := r.Add(ChainConfig{Slug: "BAD SLUG", RPC: "http://x"})
	if err == nil {
		t.Fatal("expected error for invalid slug")
	}

	err = r.Add(ChainConfig{Slug: "../escape", RPC: "http://x"})
	if err == nil {
		t.Fatal("expected error for path traversal slug")
	}
}

func TestRegistryMissingRPC(t *testing.T) {
	r := NewChainRegistry()

	err := r.Add(ChainConfig{Slug: "test", Name: "test"})
	if err == nil {
		t.Fatal("expected error for missing RPC")
	}
}

func TestRegistryRemove(t *testing.T) {
	r := NewChainRegistry()
	r.Add(ChainConfig{Slug: "test", Name: "test", RPC: "http://x", Source: "admin"})

	if !r.Remove("test") {
		t.Fatal("expected Remove to return true")
	}
	if r.Count() != 0 {
		t.Fatal("expected 0 chains after remove")
	}
	if r.Remove("nonexistent") {
		t.Fatal("expected Remove to return false for nonexistent")
	}
}

func TestRegistryUpdate(t *testing.T) {
	r := NewChainRegistry()
	r.Add(ChainConfig{Slug: "test", Name: "old", RPC: "http://old", Source: "config"})

	err := r.Update("test", ChainConfig{Name: "new", RPC: "http://new"})
	if err != nil {
		t.Fatal(err)
	}

	cfg, ok := r.Get("test")
	if !ok {
		t.Fatal("chain not found after update")
	}
	if cfg.Name != "new" {
		t.Fatalf("expected name=new, got %s", cfg.Name)
	}
	if cfg.RPC != "http://new" {
		t.Fatalf("expected rpc=http://new, got %s", cfg.RPC)
	}
}

func TestRegistryUpdateNotFound(t *testing.T) {
	r := NewChainRegistry()
	err := r.Update("nonexistent", ChainConfig{Name: "x"})
	if err == nil {
		t.Fatal("expected error for nonexistent chain")
	}
}

func TestRegistryMDNSPriority(t *testing.T) {
	r := NewChainRegistry()

	// Config source takes precedence
	r.Add(ChainConfig{Slug: "cchain", Name: "C-Chain", RPC: "http://config", Source: "config"})

	// mDNS should not override
	err := r.Add(ChainConfig{Slug: "cchain", Name: "C-Chain", RPC: "http://mdns", Source: "mdns"})
	if err == nil {
		t.Fatal("expected error when mdns tries to override config")
	}

	cfg, _ := r.Get("cchain")
	if cfg.RPC != "http://config" {
		t.Fatalf("expected config RPC to persist, got %s", cfg.RPC)
	}
}

func TestRegistryDefaultType(t *testing.T) {
	r := NewChainRegistry()
	r.Add(ChainConfig{Slug: "test", Name: "test", RPC: "http://x", Source: "admin"})

	cfg, _ := r.Get("test")
	if cfg.Type != "evm" {
		t.Fatalf("expected default type=evm, got %s", cfg.Type)
	}
}

func TestRegistryLoadFromEnv(t *testing.T) {
	r := NewChainRegistry()
	r.LoadFromEnv("cchain:http://localhost:9650/ext/bc/C/rpc,zoo:http://localhost:9650/ext/bc/Zoo/rpc")

	if r.Count() != 2 {
		t.Fatalf("expected 2 chains, got %d", r.Count())
	}
}

func TestRegistryLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "chains.yaml")
	os.WriteFile(f, []byte(`chains:
  - slug: cchain
    name: C-Chain
    chain_id: 96369
    rpc: http://localhost:9650/ext/bc/C/rpc
    type: evm
    default: true
  - slug: zoo
    name: Zoo
    chain_id: 200200
    rpc: http://localhost:9650/ext/bc/Zoo/rpc
    type: evm
`), 0644)

	r := NewChainRegistry()
	err := r.LoadFromFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if r.Count() != 2 {
		t.Fatalf("expected 2 chains, got %d", r.Count())
	}

	cfg, ok := r.Get("cchain")
	if !ok {
		t.Fatal("cchain not found")
	}
	if cfg.ChainID != 96369 {
		t.Fatalf("expected chain_id=96369, got %d", cfg.ChainID)
	}
	if cfg.Source != "config" {
		t.Fatalf("expected source=config, got %s", cfg.Source)
	}
}

func TestHandleList(t *testing.T) {
	r := NewChainRegistry()
	r.Add(ChainConfig{Slug: "test", Name: "Test", RPC: "http://x", Source: "admin"})

	req := httptest.NewRequest("GET", "/v1/explorer/admin/chains", nil)
	w := httptest.NewRecorder()
	r.HandleList(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var body map[string]any
	json.NewDecoder(w.Body).Decode(&body)
	if body["count"].(float64) != 1 {
		t.Fatalf("expected count=1, got %v", body["count"])
	}
}

func TestHandleAddAndRemove(t *testing.T) {
	r := NewChainRegistry()

	// Add
	payload := `{"slug":"cchain","name":"C-Chain","rpc":"http://localhost:9650/ext/bc/C/rpc","type":"evm"}`
	req := httptest.NewRequest("POST", "/v1/explorer/admin/chains", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.HandleAdd(w, req)

	if w.Code != 201 {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	if r.Count() != 1 {
		t.Fatalf("expected 1 chain after add")
	}

	// Duplicate should conflict
	req = httptest.NewRequest("POST", "/v1/explorer/admin/chains", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.HandleAdd(w, req)
	if w.Code != 409 {
		t.Fatalf("expected 409 for duplicate, got %d", w.Code)
	}

	// Remove
	req = httptest.NewRequest("DELETE", "/v1/explorer/admin/chains/cchain", nil)
	req.SetPathValue("slug", "cchain")
	w = httptest.NewRecorder()
	r.HandleRemove(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if r.Count() != 0 {
		t.Fatal("expected 0 chains after remove")
	}
}

func TestHandleUpdate(t *testing.T) {
	r := NewChainRegistry()
	r.Add(ChainConfig{Slug: "test", Name: "Old", RPC: "http://old", Source: "config"})

	payload := `{"name":"New","rpc":"http://new"}`
	req := httptest.NewRequest("PUT", "/v1/explorer/admin/chains/test", bytes.NewBufferString(payload))
	req.SetPathValue("slug", "test")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.HandleUpdate(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var cfg ChainConfig
	json.NewDecoder(w.Body).Decode(&cfg)
	if cfg.Name != "New" {
		t.Fatalf("expected name=New, got %s", cfg.Name)
	}
}

func TestHandleUpdateNotFound(t *testing.T) {
	r := NewChainRegistry()

	payload := `{"name":"x"}`
	req := httptest.NewRequest("PUT", "/v1/explorer/admin/chains/nonexistent", bytes.NewBufferString(payload))
	req.SetPathValue("slug", "nonexistent")
	w := httptest.NewRecorder()
	r.HandleUpdate(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleRemoveNotFound(t *testing.T) {
	r := NewChainRegistry()

	req := httptest.NewRequest("DELETE", "/v1/explorer/admin/chains/nonexistent", nil)
	req.SetPathValue("slug", "nonexistent")
	w := httptest.NewRecorder()
	r.HandleRemove(w, req)

	if w.Code != 404 {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestHandleAddInvalid(t *testing.T) {
	r := NewChainRegistry()

	// Bad JSON
	req := httptest.NewRequest("POST", "/v1/explorer/admin/chains", bytes.NewBufferString("not json"))
	w := httptest.NewRecorder()
	r.HandleAdd(w, req)
	if w.Code != 400 {
		t.Fatalf("expected 400 for bad json, got %d", w.Code)
	}

	// Missing slug
	req = httptest.NewRequest("POST", "/v1/explorer/admin/chains", bytes.NewBufferString(`{"rpc":"http://x"}`))
	w = httptest.NewRecorder()
	r.HandleAdd(w, req)
	if w.Code != 409 {
		t.Fatalf("expected 409 for missing slug, got %d", w.Code)
	}
}

func TestEnvHelpers(t *testing.T) {
	if env("NONEXISTENT_KEY_12345", "fallback") != "fallback" {
		t.Fatal("env fallback failed")
	}
	if envInt("NONEXISTENT_KEY_12345", 42) != 42 {
		t.Fatal("envInt fallback failed")
	}
	if envBool("NONEXISTENT_KEY_12345", true) != true {
		t.Fatal("envBool fallback failed")
	}
}

// TestHTTPIntegration uses a real mux + httptest server to verify routing.
func TestHTTPIntegration(t *testing.T) {
	registry := NewChainRegistry()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/explorer/admin/chains", registry.HandleList)
	mux.HandleFunc("POST /v1/explorer/admin/chains", registry.HandleAdd)
	mux.HandleFunc("PUT /v1/explorer/admin/chains/{slug}", registry.HandleUpdate)
	mux.HandleFunc("DELETE /v1/explorer/admin/chains/{slug}", registry.HandleRemove)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "chains": registry.Count()})
	})

	ts := httptest.NewServer(mux)
	defer ts.Close()

	client := ts.Client()

	// Health
	resp, err := client.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("health: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// List (empty)
	resp, err = client.Get(ts.URL + "/v1/explorer/admin/chains")
	if err != nil {
		t.Fatal(err)
	}
	var listBody map[string]any
	json.NewDecoder(resp.Body).Decode(&listBody)
	resp.Body.Close()
	if listBody["count"].(float64) != 0 {
		t.Fatalf("expected 0 chains initially")
	}

	// Add
	addPayload := `{"slug":"cchain","name":"C-Chain","chain_id":96369,"rpc":"http://localhost:9650/ext/bc/C/rpc","type":"evm","default":true}`
	resp, err = client.Post(ts.URL+"/v1/explorer/admin/chains", "application/json", bytes.NewBufferString(addPayload))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 201 {
		t.Fatalf("add: expected 201, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// List (1 chain)
	resp, err = client.Get(ts.URL + "/v1/explorer/admin/chains")
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&listBody)
	resp.Body.Close()
	if listBody["count"].(float64) != 1 {
		t.Fatalf("expected 1 chain after add")
	}

	// Update
	updatePayload := `{"name":"Lux C-Chain","rpc":"http://new:9650/ext/bc/C/rpc"}`
	updateReq, _ := http.NewRequest("PUT", ts.URL+"/v1/explorer/admin/chains/cchain", bytes.NewBufferString(updatePayload))
	updateReq.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(updateReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("update: expected 200, got %d", resp.StatusCode)
	}
	var updated ChainConfig
	json.NewDecoder(resp.Body).Decode(&updated)
	resp.Body.Close()
	if updated.Name != "Lux C-Chain" {
		t.Fatalf("expected updated name, got %s", updated.Name)
	}

	// Delete
	delReq, _ := http.NewRequest("DELETE", ts.URL+"/v1/explorer/admin/chains/cchain", nil)
	resp, err = client.Do(delReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("delete: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Verify empty
	resp, _ = client.Get(ts.URL + "/v1/explorer/admin/chains")
	json.NewDecoder(resp.Body).Decode(&listBody)
	resp.Body.Close()
	if listBody["count"].(float64) != 0 {
		t.Fatalf("expected 0 chains after delete")
	}
}
