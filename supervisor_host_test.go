package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A slug-less /v1/indexer request is answered by the chain the host names.
// Pinned to the configured default, api-explore.hanzo.network and
// api-explore.zoo.network returned the same window of Lux block heights as
// api-explore.lux.network — to the block, on every fetch.
func TestIndexerDispatchFollowsTheHost(t *testing.T) {
	s := NewChainSupervisor(Config{Chains: []ChainConfig{
		{Slug: "cchain", Default: true},
		{Slug: "hanzo"},
		{Slug: "zoo"},
	}})
	s.SetDefaultSlug("cchain")
	for _, slug := range []string{"cchain", "hanzo", "zoo"} {
		slug := slug
		s.indexerRoutes.Store(slug, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]string{"served": slug, "path": r.URL.Path})
		}))
	}

	mux := http.NewServeMux()
	s.MountRoutes(mux)

	for _, tc := range []struct{ host, path, want string }{
		{"api-explore.lux.network", "/v1/indexer/blocks", "cchain"}, // names none -> default
		{"api-explore.hanzo.network", "/v1/indexer/blocks", "hanzo"},
		{"api-explore.zoo.network", "/v1/indexer/blocks", "zoo"},
		{"explore.zoo.ngo", "/v1/indexer/tokens", "zoo"},
		// An explicit slug still wins over the host.
		{"api-explore.hanzo.network", "/v1/indexer/zoo/blocks", "zoo"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Host = tc.host
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)

		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s %s: %v -- %s", tc.host, tc.path, err, rec.Body.String())
		}
		if body["served"] != tc.want {
			t.Errorf("%s %s: served by %q, want %q", tc.host, tc.path, body["served"], tc.want)
		}
	}
}

// A host naming a chain that is not running falls back rather than 404ing —
// chains are added and removed at runtime.
func TestIndexerDispatchFallsBackWhenTheHostsChainIsDown(t *testing.T) {
	s := NewChainSupervisor(Config{Chains: []ChainConfig{
		{Slug: "cchain", Default: true},
		{Slug: "hanzo"},
	}})
	s.SetDefaultSlug("cchain")
	s.indexerRoutes.Store("cchain", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"served": "cchain"})
	}))

	req := httptest.NewRequest(http.MethodGet, "/v1/indexer/blocks", nil)
	req.Host = "api-explore.hanzo.network"
	rec := httptest.NewRecorder()
	mux := http.NewServeMux()
	s.MountRoutes(mux)
	mux.ServeHTTP(rec, req)

	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if body["served"] != "cchain" {
		t.Errorf("served by %q, want cchain", body["served"])
	}
}
