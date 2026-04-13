package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// ChainConfig defines a single chain to index.
type ChainConfig struct {
	Slug    string `json:"slug" yaml:"slug"`
	Name    string `json:"name" yaml:"name"`
	ChainID int64  `json:"chain_id" yaml:"chain_id"`
	RPC     string `json:"rpc" yaml:"rpc"`
	Type    string `json:"type" yaml:"type"` // evm, dag, pchain, xchain
	Default bool   `json:"default" yaml:"default"`
	Source  string `json:"source" yaml:"-"` // config, env, mdns, admin
}

// ChainsFile is the top-level YAML structure for chains.yaml.
type ChainsFile struct {
	Chains []ChainConfig `yaml:"chains"`
}

// ChainEntry holds a chain config plus its runtime state.
type ChainEntry struct {
	Config ChainConfig
}

// slugPattern restricts slugs to lowercase alphanumeric + hyphen.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// ChainRegistry is a thread-safe, runtime-mutable chain store.
type ChainRegistry struct {
	mu     sync.RWMutex
	chains map[string]*ChainEntry // slug -> entry
	hub    *RealtimeHub
}

// NewChainRegistry creates an empty registry.
func NewChainRegistry() *ChainRegistry {
	return &ChainRegistry{
		chains: make(map[string]*ChainEntry),
		hub:    NewRealtimeHub(),
	}
}

// Add registers a chain. Returns error if slug is invalid or already exists from a higher-priority source.
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
	defer r.mu.Unlock()

	if existing, ok := r.chains[cfg.Slug]; ok {
		// mDNS never overrides manual config
		if cfg.Source == "mdns" && existing.Config.Source != "mdns" {
			return fmt.Errorf("chain %q already configured via %s", cfg.Slug, existing.Config.Source)
		}
		// All other sources: reject duplicate (use Update to modify)
		if cfg.Source != "mdns" {
			return fmt.Errorf("chain %q already exists", cfg.Slug)
		}
		// mDNS re-discovery: update last-seen silently
		existing.Config.RPC = cfg.RPC
		return nil
	}

	r.chains[cfg.Slug] = &ChainEntry{Config: cfg}
	log.Printf("[registry] added chain %s (%s) source=%s", cfg.Slug, cfg.RPC, cfg.Source)
	return nil
}

// Remove deletes a chain by slug.
func (r *ChainRegistry) Remove(slug string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.chains[slug]; !ok {
		return false
	}
	delete(r.chains, slug)
	log.Printf("[registry] removed chain %s", slug)
	return true
}

// Update modifies an existing chain's config.
func (r *ChainRegistry) Update(slug string, cfg ChainConfig) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.chains[slug]
	if !ok {
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

	log.Printf("[registry] updated chain %s", slug)
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

// LoadFromFile loads chains from a YAML file.
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

// --- HTTP Handlers ---

// HandleList returns all chains as JSON.
func (r *ChainRegistry) HandleList(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"chains": r.List(),
		"count":  r.Count(),
	})
}

// HandleAdd creates a new chain from JSON body.
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
