package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// ChainsFile is the legacy `chains: [...]` YAML shape used by tests and the
// minimal config. The full Config struct in config.go is the canonical schema.
type ChainsFile struct {
	Chains []ChainConfig `yaml:"chains"`
}

// ChainEntry holds a chain config plus its runtime state.
type ChainEntry struct {
	Config ChainConfig
}

// ChainRegistry is a thread-safe, runtime-mutable chain store.
type ChainRegistry struct {
	mu     sync.RWMutex
	chains map[string]*ChainEntry
	hub    *RealtimeHub
	sup    *ChainSupervisor // nil = registry-only mode (tests)
}

// NewChainRegistry creates an empty registry.
func NewChainRegistry() *ChainRegistry {
	return &ChainRegistry{
		chains: make(map[string]*ChainEntry),
		hub:    NewRealtimeHub(),
	}
}

// AttachSupervisor wires a ChainSupervisor so admin/config/mdns adds also
// spawn per-chain indexer + graph goroutines, and removes cancel them.
func (r *ChainRegistry) AttachSupervisor(s *ChainSupervisor) { r.sup = s }

// Add registers a chain. mDNS-sourced chains never override higher-priority
// (config/env/admin) entries; admin/config/env duplicates return an error.
func (r *ChainRegistry) Add(cfg ChainConfig) error {
	if !slugPattern.MatchString(cfg.Slug) {
		return fmt.Errorf("invalid slug %q", cfg.Slug)
	}
	if cfg.RPC == "" {
		return fmt.Errorf("rpc required for chain %q", cfg.Slug)
	}
	if cfg.Type == "" {
		cfg.Type = "evm"
	}

	r.mu.Lock()
	if existing, ok := r.chains[cfg.Slug]; ok {
		if cfg.Source == "mdns" && existing.Config.Source != "mdns" {
			r.mu.Unlock()
			return fmt.Errorf("chain %q already configured via %s", cfg.Slug, existing.Config.Source)
		}
		if cfg.Source != "mdns" {
			r.mu.Unlock()
			return fmt.Errorf("chain %q already exists", cfg.Slug)
		}
		existing.Config.RPC = cfg.RPC
		r.mu.Unlock()
		return nil
	}
	r.chains[cfg.Slug] = &ChainEntry{Config: cfg}
	r.mu.Unlock()
	log.Printf("[registry] added chain %s (%s) source=%s", cfg.Slug, cfg.RPC, cfg.Source)

	if r.sup != nil {
		r.sup.start(cfg)
	}
	return nil
}

// Remove deletes a chain by slug.
func (r *ChainRegistry) Remove(slug string) bool {
	r.mu.Lock()
	if _, ok := r.chains[slug]; !ok {
		r.mu.Unlock()
		return false
	}
	delete(r.chains, slug)
	r.mu.Unlock()
	log.Printf("[registry] removed chain %s", slug)

	if r.sup != nil {
		r.sup.stop(slug)
	}
	return true
}

// Update modifies an existing chain's config.
func (r *ChainRegistry) Update(slug string, cfg ChainConfig) error {
	r.mu.Lock()
	entry, ok := r.chains[slug]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("chain %q not found", slug)
	}
	if cfg.Name != "" {
		entry.Config.Name = cfg.Name
	}
	if cfg.RPC != "" {
		entry.Config.RPC = cfg.RPC
	}
	if cfg.ChainID != 0 {
		entry.Config.ChainID = cfg.ChainID
	}
	if cfg.Type != "" {
		entry.Config.Type = cfg.Type
	}
	entry.Config.Default = cfg.Default
	entry.Config.Source = "admin"
	updated := entry.Config
	r.mu.Unlock()

	log.Printf("[registry] updated chain %s", slug)

	if r.sup != nil {
		r.sup.stop(slug)
		r.sup.start(updated)
	}
	return nil
}

// Get returns a chain by slug.
func (r *ChainRegistry) Get(slug string) (ChainConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.chains[slug]
	if !ok {
		return ChainConfig{}, false
	}
	return entry.Config, true
}

// List returns all chains.
func (r *ChainRegistry) List() []ChainConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ChainConfig, 0, len(r.chains))
	for _, e := range r.chains {
		out = append(out, e.Config)
	}
	return out
}

// Count returns the number of registered chains.
func (r *ChainRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.chains)
}

// LoadFromFile loads chains from a YAML file using the legacy `chains: [...]`
// shape. Full Config (with brand, networks, etc.) loads via LoadConfig.
func (r *ChainRegistry) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var f ChainsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	for _, c := range f.Chains {
		c.Source = "config"
		c.RPC = os.Expand(c.RPC, os.Getenv)
		c.WS = os.Expand(c.WS, os.Getenv)
		if err := r.Add(c); err != nil {
			log.Printf("[registry] skip %s from config: %v", c.Slug, err)
		}
	}
	log.Printf("[registry] loaded %d chains from %s", len(f.Chains), path)
	return nil
}

// LoadFromEnv parses CHAINS env var: "slug:rpc,slug:rpc,..."
func (r *ChainRegistry) LoadFromEnv(val string) {
	for _, pair := range strings.Split(val, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			log.Printf("[registry] skip invalid CHAINS entry: %q", pair)
			continue
		}
		cfg := ChainConfig{
			Slug:   strings.TrimSpace(parts[0]),
			Name:   strings.TrimSpace(parts[0]),
			RPC:    strings.TrimSpace(parts[1]),
			Type:   "evm",
			Source: "env",
		}
		if err := r.Add(cfg); err != nil {
			log.Printf("[registry] skip %s from env: %v", cfg.Slug, err)
		}
	}
}

// HandleList returns all chains as JSON.
func (r *ChainRegistry) HandleList(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"chains": r.List(),
		"count":  r.Count(),
	})
}

// HandleAdd creates a new chain from a JSON body.
func (r *ChainRegistry) HandleAdd(w http.ResponseWriter, req *http.Request) {
	var cfg ChainConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096)).Decode(&cfg); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	cfg.Source = "admin"
	if err := r.Add(cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cfg)
}

// HandleUpdate modifies an existing chain.
func (r *ChainRegistry) HandleUpdate(w http.ResponseWriter, req *http.Request) {
	slug := req.PathValue("slug")
	if slug == "" {
		http.Error(w, `{"error":"slug required"}`, http.StatusBadRequest)
		return
	}
	var cfg ChainConfig
	if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096)).Decode(&cfg); err != nil {
		http.Error(w, `{"error":"invalid json"}`, http.StatusBadRequest)
		return
	}
	if err := r.Update(slug, cfg); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	updated, _ := r.Get(slug)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updated)
}

// HandleRemove deletes a chain by slug.
func (r *ChainRegistry) HandleRemove(w http.ResponseWriter, req *http.Request) {
	slug := req.PathValue("slug")
	if slug == "" {
		http.Error(w, `{"error":"slug required"}`, http.StatusBadRequest)
		return
	}
	if !r.Remove(slug) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "removed", "slug": slug})
}
