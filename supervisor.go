package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/luxfi/graph/engine"
	graphidx "github.com/luxfi/graph/indexer"
	graphstor "github.com/luxfi/graph/storage"

	"github.com/luxfi/indexer/evm"
	"github.com/luxfi/indexer/explorer"
	idxstor "github.com/luxfi/indexer/storage"
)

// ChainSupervisor owns the per-chain indexer + graph goroutines plus the
// route dispatcher that maps /v1/indexer/{slug}/* and /v1/graph/{slug}/*
// requests to the correct handler. Routes are mutable at runtime: adding a
// chain spawns its workers, removing a chain cancels them.
type ChainSupervisor struct {
	dataDir string
	mu      sync.Mutex
	state   map[string]*chainState

	indexerRoutes sync.Map // map[slug]http.Handler
	graphRoutes   sync.Map // map[slug + "/" + subgraph]http.Handler
	defaultSlug   string   // serves /v1/indexer/* (no slug prefix)
}

type chainState struct {
	cfg    ChainConfig
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewChainSupervisor creates a supervisor rooted at dataDir.
func NewChainSupervisor(dataDir string) *ChainSupervisor {
	return &ChainSupervisor{
		dataDir: dataDir,
		state:   make(map[string]*chainState),
	}
}

// MountRoutes installs the /v1/indexer and /v1/graph dispatchers on mux. The
// dispatchers look up per-chain handlers from the supervisor's route maps so
// chains added at runtime become reachable without re-mounting.
func (s *ChainSupervisor) MountRoutes(mux *http.ServeMux) {
	mux.Handle("/v1/indexer/", http.HandlerFunc(s.dispatchIndexer))
	mux.Handle("/v1/explorer/", http.HandlerFunc(s.dispatchExplorerLegacy))
	mux.Handle("/v1/graph/", http.HandlerFunc(s.dispatchGraph))
}

// SetDefaultSlug picks which chain serves the unprefixed /v1/indexer/* route.
func (s *ChainSupervisor) SetDefaultSlug(slug string) {
	s.mu.Lock()
	s.defaultSlug = slug
	s.mu.Unlock()
}

// start spawns workers for cfg. Idempotent: starting an already-running slug
// is a no-op.
func (s *ChainSupervisor) start(cfg ChainConfig) {
	s.mu.Lock()
	if _, ok := s.state[cfg.Slug]; ok {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	st := &chainState{cfg: cfg, cancel: cancel}
	s.state[cfg.Slug] = st
	if cfg.Default && s.defaultSlug == "" {
		s.defaultSlug = cfg.Slug
	}
	s.mu.Unlock()

	st.wg.Add(1)
	go func() {
		defer st.wg.Done()
		s.runChain(ctx, cfg)
	}()

	if cfg.Graph.Enabled {
		for _, sg := range cfg.Graph.Subgraphs {
			if !sg.Enabled {
				continue
			}
			sg := sg
			st.wg.Add(1)
			go func() {
				defer st.wg.Done()
				s.runSubgraph(ctx, cfg, sg)
			}()
		}
	}
}

// stop cancels and waits for all workers belonging to slug.
func (s *ChainSupervisor) stop(slug string) {
	s.mu.Lock()
	st, ok := s.state[slug]
	if !ok {
		s.mu.Unlock()
		return
	}
	delete(s.state, slug)
	if s.defaultSlug == slug {
		s.defaultSlug = ""
	}
	s.mu.Unlock()

	st.cancel()
	st.wg.Wait()

	s.indexerRoutes.Delete(slug)
	s.graphRoutes.Range(func(k, _ any) bool {
		if key, ok := k.(string); ok && strings.HasPrefix(key, slug+"/") {
			s.graphRoutes.Delete(k)
		}
		return true
	})
	log.Printf("[supervisor] stopped %s", slug)
}

// Wait blocks until ctx is done, then cancels every chain and waits for
// goroutines to drain.
func (s *ChainSupervisor) Wait(ctx context.Context) {
	<-ctx.Done()
	s.mu.Lock()
	slugs := make([]string, 0, len(s.state))
	for k := range s.state {
		slugs = append(slugs, k)
	}
	s.mu.Unlock()
	for _, slug := range slugs {
		s.stop(slug)
	}
}

// runChain runs one chain's indexer to completion or context cancel and then
// mounts the standalone explorer API once the SQLite schema is ready.
func (s *ChainSupervisor) runChain(ctx context.Context, cfg ChainConfig) {
	chainDir := filepath.Join(s.dataDir, cfg.Slug)
	if err := os.MkdirAll(chainDir, 0755); err != nil {
		log.Printf("[%s] mkdir: %v", cfg.Slug, err)
		return
	}
	store, err := idxstor.NewUnified(idxstor.DefaultUnifiedConfig(chainDir))
	if err != nil {
		log.Printf("[%s] storage: %v", cfg.Slug, err)
		return
	}
	defer store.Close()
	if err := store.Init(ctx); err != nil {
		log.Printf("[%s] storage init: %v", cfg.Slug, err)
		return
	}
	dbPath := filepath.Join(chainDir, "query", "indexer.db")
	log.Printf("[%s] indexing %s (%s) -> %s", cfg.Slug, cfg.Name, cfg.CoinSymbol, dbPath)

	go s.mountIndexerAPI(ctx, cfg, dbPath)

	switch cfg.Type {
	case "", "evm":
		poll := 30 * time.Second
		if cfg.Indexer.PollInterval != "" {
			if d, err := time.ParseDuration(cfg.Indexer.PollInterval); err == nil {
				poll = d
			}
		}
		idx, err := evm.NewIndexer(evm.Config{
			ChainName:    cfg.Name,
			ChainID:      cfg.ChainID,
			RPCEndpoint:  cfg.RPC,
			HTTPPort:     0,
			PollInterval: poll,
		}, store)
		if err != nil {
			log.Printf("[%s] evm indexer: %v", cfg.Slug, err)
			return
		}
		if err := idx.Init(ctx); err != nil {
			log.Printf("[%s] evm init: %v", cfg.Slug, err)
			return
		}
		if err := idx.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[%s] evm run: %v", cfg.Slug, err)
		}
	default:
		log.Printf("[%s] %s indexer: passive (no chain-specific implementation)", cfg.Slug, cfg.Type)
		<-ctx.Done()
	}
}

// mountIndexerAPI waits for the per-chain SQLite schema to settle, then
// publishes the standalone explorer API in the indexer/explorer route maps.
func (s *ChainSupervisor) mountIndexerAPI(ctx context.Context, cfg ChainConfig, dbPath string) {
	apiPrefix := "/v1/indexer/" + cfg.Slug
	deadline := time.Now().Add(5 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
		if _, err := os.Stat(dbPath); err != nil {
			if time.Now().After(deadline) {
				log.Printf("[%s] api waiting for %s: %v", cfg.Slug, dbPath, err)
				deadline = time.Now().Add(5 * time.Minute)
			}
			continue
		}
		if cfg.Type == "" || cfg.Type == "evm" {
			db, err := sql.Open("sqlite3", "file:"+dbPath+"?mode=ro")
			if err == nil {
				var n int
				_ = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='evm_blocks'").Scan(&n)
				db.Close()
				if n == 0 {
					if time.Now().After(deadline) {
						log.Printf("[%s] api waiting for evm_blocks", cfg.Slug)
						deadline = time.Now().Add(5 * time.Minute)
					}
					continue
				}
			}
		}
		srv, err := explorer.NewStandaloneServer(explorer.Config{
			IndexerDBPath: dbPath,
			ChainID:       cfg.ChainID,
			ChainName:     cfg.Name,
			CoinSymbol:    cfg.CoinSymbol,
			APIPrefix:     apiPrefix,
		})
		if err != nil {
			if time.Now().After(deadline) {
				log.Printf("[%s] api: %v", cfg.Slug, err)
				deadline = time.Now().Add(5 * time.Minute)
			}
			continue
		}
		s.indexerRoutes.Store(cfg.Slug, srv.Handler())
		log.Printf("[%s] api mounted at %s/*", cfg.Slug, apiPrefix)
		return
	}
}

// runSubgraph spawns a graph indexer + engine for a single subgraph and
// publishes its handler at /v1/graph/{chain-slug}/{subgraph-name}/.
func (s *ChainSupervisor) runSubgraph(ctx context.Context, cfg ChainConfig, sg Subgraph) {
	dir := filepath.Join(s.dataDir, cfg.Slug, "graph", sg.Name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("[%s/%s] mkdir: %v", cfg.Slug, sg.Name, err)
		return
	}
	store, err := graphstor.New(dir)
	if err != nil {
		log.Printf("[%s/%s] storage: %v", cfg.Slug, sg.Name, err)
		return
	}
	defer store.Close()
	if err := store.Init(ctx); err != nil {
		log.Printf("[%s/%s] storage init: %v", cfg.Slug, sg.Name, err)
		return
	}

	idx := graphidx.New(cfg.RPC, store)
	go func() {
		if err := idx.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[%s/%s] indexer: %v", cfg.Slug, sg.Name, err)
		}
	}()

	eng := engine.New(store, &engine.Config{
		MaxQueryDepth:  10,
		MaxResultSize:  1 << 20,
		QueryTimeoutMs: 30000,
	})
	schema := sg.Schema
	if schema == "" {
		schema = "amm"
	}
	if err := eng.LoadBuiltin(schema); err != nil {
		log.Printf("[%s/%s] schema %q: %v", cfg.Slug, sg.Name, schema, err)
		return
	}

	prefix := fmt.Sprintf("/v1/graph/%s/%s", cfg.Slug, sg.Name)
	mux := http.NewServeMux()
	gqlHandler := func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		var req engine.Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"errors":[{"message":"invalid JSON"}]}`, http.StatusBadRequest)
			return
		}
		resp := eng.Execute(r.Context(), &req)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
	statusHandler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		st := idx.Status()
		fmt.Fprintf(w, `{"status":"ok","block":%d,"indexed":%d}`, st.LatestBlock, st.IndexedEvents)
	}
	mux.HandleFunc("POST "+prefix+"/graphql", gqlHandler)
	mux.HandleFunc("GET "+prefix+"/graphql", eng.HandleGraphiQL)
	mux.HandleFunc("POST "+prefix+"/ql", gqlHandler)
	mux.HandleFunc("GET "+prefix+"/ql", eng.HandleGraphiQL)
	mux.HandleFunc("GET "+prefix+"/health", statusHandler)

	s.graphRoutes.Store(cfg.Slug+"/"+sg.Name, http.Handler(mux))
	log.Printf("[%s/%s] graph mounted at %s/{graphql,ql,health} (schema=%s)",
		cfg.Slug, sg.Name, prefix, schema)

	<-ctx.Done()
}

// dispatchIndexer routes /v1/indexer/{slug}/* and /v1/indexer/* (default
// chain) to the per-chain handler installed by mountIndexerAPI.
func (s *ChainSupervisor) dispatchIndexer(w http.ResponseWriter, r *http.Request) {
	slug, rest, ok := splitSlug(r.URL.Path, "/v1/indexer/")
	if !ok {
		s.serveDefault(w, r, "")
		return
	}
	if h, found := s.indexerRoutes.Load(slug); found {
		h.(http.Handler).ServeHTTP(w, r)
		return
	}
	s.serveDefault(w, r, rest)
}

// serveDefault forwards an unprefixed /v1/indexer/* request to the default
// chain. The standalone server is mounted under its slug, so we rewrite the
// URL to include the slug before delegating.
func (s *ChainSupervisor) serveDefault(w http.ResponseWriter, r *http.Request, rest string) {
	s.mu.Lock()
	def := s.defaultSlug
	s.mu.Unlock()
	if def == "" {
		http.Error(w, `{"error":"no default chain"}`, http.StatusNotFound)
		return
	}
	h, ok := s.indexerRoutes.Load(def)
	if !ok {
		http.Error(w, `{"error":"chain not ready"}`, http.StatusServiceUnavailable)
		return
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/v1/indexer/" + def + "/" + strings.TrimPrefix(rest, "/")
	h.(http.Handler).ServeHTTP(w, r2)
}

// dispatchExplorerLegacy preserves the older /v1/explorer/{slug}/* prefix
// for clients that haven't migrated to /v1/indexer/.
func (s *ChainSupervisor) dispatchExplorerLegacy(w http.ResponseWriter, r *http.Request) {
	slug, rest, ok := splitSlug(r.URL.Path, "/v1/explorer/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	h, found := s.indexerRoutes.Load(slug)
	if !found {
		http.NotFound(w, r)
		return
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/v1/indexer/" + slug + "/" + strings.TrimPrefix(rest, "/")
	h.(http.Handler).ServeHTTP(w, r2)
}

// dispatchGraph routes /v1/graph/{slug}/{subgraph}/* to the matching engine.
func (s *ChainSupervisor) dispatchGraph(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/graph/")
	if rest == r.URL.Path {
		http.NotFound(w, r)
		return
	}
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	key := parts[0] + "/" + parts[1]
	h, ok := s.graphRoutes.Load(key)
	if !ok {
		http.NotFound(w, r)
		return
	}
	h.(http.Handler).ServeHTTP(w, r)
}

// splitSlug returns the chain slug and the remainder of the path after a
// known prefix (e.g. "/v1/indexer/"). Returns ok=false if the path does not
// match the prefix or contains no slug.
func splitSlug(path, prefix string) (slug, rest string, ok bool) {
	if !strings.HasPrefix(path, prefix) {
		return "", "", false
	}
	tail := strings.TrimPrefix(path, prefix)
	if tail == "" {
		return "", "", false
	}
	parts := strings.SplitN(tail, "/", 2)
	if !slugPattern.MatchString(parts[0]) {
		return "", "", false
	}
	if len(parts) == 1 {
		return parts[0], "", true
	}
	return parts[0], parts[1], true
}
