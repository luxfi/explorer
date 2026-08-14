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

	// ONE sqlite C library in this binary, under a name nothing else claims.
	// This process links graph and indexer as well as its own store, and
	// csqlite is the house build of the amalgamation all three now open —
	// registered as "sqlite3". Upstream mattn compiles a second copy of the
	// same C, and defining every sqlite3_* symbol twice fails at link on
	// darwin. Not its hanzoai/sqlite wrapper either: that registers
	// "sqlite", and so does modernc.org/sqlite, which arrives with
	// hanzoai/replicate — two packages under one name is a panic in init.
	_ "github.com/hanzoai/csqlite"

	"github.com/luxfi/graph/engine"
	graphidx "github.com/luxfi/graph/indexer"
	graphstor "github.com/luxfi/graph/storage"

	"github.com/luxfi/indexer/chain"
	"github.com/luxfi/indexer/evm"
	"github.com/luxfi/indexer/explorer"
	"github.com/luxfi/indexer/platform"
	idxstor "github.com/luxfi/indexer/storage"
)

// ChainSupervisor owns the per-chain indexer + graph goroutines plus the
// route dispatcher that maps /v1/indexer/{slug}/* and /v1/graph/{slug}/*
// requests to the correct handler. Routes are mutable at runtime: adding a
// chain spawns its workers, removing a chain cancels them.
type ChainSupervisor struct {
	dataDir string
	cfg     Config // resolves a request host to its chain; see Config.Serves
	mu      sync.Mutex
	state   map[string]*chainState

	indexerRoutes sync.Map // map[slug]http.Handler
	graphRoutes   sync.Map // map[slug + "/" + subgraph]http.Handler
	swapRoutes    sync.Map // map[chainID]*swapMount — the swap form's routes, by the chain they name
	defaultSlug   string   // serves /v1/indexer/* when the host names no chain
	// defaultChainID answers a swap request that names no chain. A form that
	// has not finished loading its network sends one, and the alternative to a
	// default is an error on the first render.
	defaultChainID int64

	// realtimeHub is the explorer's RealtimeHub. When set (via
	// AttachRealtime), the supervisor wires each per-chain EVM indexer's
	// Subscriber.OnBroadcast callback so block events flow into the hub
	// → out to WebSocket + SSE subscribers. Nil = no live broadcast.
	realtimeHub *RealtimeHub
}

type chainState struct {
	cfg    ChainConfig
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewChainSupervisor creates a supervisor rooted at cfg.DataDir.
func NewChainSupervisor(cfg Config) *ChainSupervisor {
	return &ChainSupervisor{
		dataDir: cfg.DataDir,
		cfg:     cfg,
		state:   make(map[string]*chainState),
	}
}

// AttachRealtime wires per-chain block events into the explorer's
// RealtimeHub. Called once from main.go after both the supervisor and
// the registry's hub exist. Subsequent chain spawns (runChain below)
// install the Subscriber.OnBroadcast callback automatically.
func (s *ChainSupervisor) AttachRealtime(h *RealtimeHub) {
	s.realtimeHub = h
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
			StartBlock:   cfg.Indexer.StartBlock,
		}, store)
		if err != nil {
			log.Printf("[%s] evm indexer: %v", cfg.Slug, err)
			return
		}
		// Live broadcast bridge — when the supervisor has been given a
		// RealtimeHub (see AttachRealtime), every block the indexer
		// commits is re-published into the hub on the chain's slug. The
		// hub then fans out to WebSocket and SSE subscribers (see
		// realtime.go + realtime_sse.go). slug captured by value so the
		// closure doesn't see a mutated `cfg` if the supervisor loops.
		if s.realtimeHub != nil && idx.Subscriber() != nil {
			slug := cfg.Slug
			hub := s.realtimeHub
			idx.Subscriber().OnBroadcast = func(eventType string, data any) {
				hub.Broadcast(eventType, slug, data)
			}
		}
		if err := idx.Init(ctx); err != nil {
			log.Printf("[%s] evm init: %v", cfg.Slug, err)
			return
		}
		if err := idx.Run(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[%s] evm run: %v", cfg.Slug, err)
		}
	case "linear", "platform":
		// P-Chain (platform VM) indexing. The generic chain indexer supplies
		// the canonical pchain_blocks schema; the platform adapter supplies the
		// validator/delegator/etc schema and the RPC block/validator fetchers.
		poll := 30 * time.Second
		if cfg.Indexer.PollInterval != "" {
			if d, err := time.ParseDuration(cfg.Indexer.PollInterval); err == nil {
				poll = d
			}
		}
		adapter := platform.New(cfg.RPC)
		chainCfg := platform.NewConfig() // ChainType=pchain -> pchain_blocks table
		chainCfg.ChainName = cfg.Name
		chainCfg.RPCEndpoint = cfg.RPC
		chainCfg.PollInterval = poll
		idx, err := chain.New(chainCfg, store, adapter)
		if err != nil {
			log.Printf("[%s] platform indexer: %v", cfg.Slug, err)
			return
		}
		// Init once: creates pchain_blocks (generic schema) and the adapter's
		// pchain_validators/pchain_delegators/... tables. We drive our own poll
		// loop rather than idx.Run() so we don't stand up the chain indexer's
		// WS-gated poller + HTTP server (the standalone API reads the SQLite DB
		// directly). Blocks are written via store.StoreBlock, not idx.StoreBlock,
		// to avoid the indexer's subscriber broadcast (nothing drains it here).
		if err := idx.Init(ctx); err != nil {
			log.Printf("[%s] platform init: %v", cfg.Slug, err)
			return
		}
		const platformBlocksTable = "pchain_blocks"
		sync := func() {
			raw, err := adapter.GetRecentBlocks(ctx, 50)
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("[%s] platform blocks: %v", cfg.Slug, err)
				}
			} else {
				for _, rb := range raw {
					b, perr := adapter.ParseBlock(rb)
					if perr != nil {
						continue
					}
					sb := &idxstor.Block{
						ID:        b.ID,
						ParentID:  b.ParentID,
						Height:    b.Height,
						Timestamp: b.Timestamp,
						Status:    string(b.Status),
						TxCount:   b.TxCount,
						TxIDs:     b.TxIDs,
						Data:      b.Data,
						CreatedAt: time.Now(),
					}
					if err := store.StoreBlock(ctx, platformBlocksTable, sb); err != nil && ctx.Err() == nil {
						log.Printf("[%s] platform store block %d: %v", cfg.Slug, b.Height, err)
					}
				}
			}
			if err := adapter.SyncValidators(ctx, store); err != nil && ctx.Err() == nil {
				log.Printf("[%s] platform validators: %v", cfg.Slug, err)
			}
		}
		sync() // first pass immediately so tables populate before the first tick
		ticker := time.NewTicker(poll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sync()
			}
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
		// Gate readiness on the primary blocks table for this chain type:
		// EVM writes evm_blocks; platform/linear writes pchain_blocks (created
		// by the generic chain indexer's Init — NOT by platform.InitSchema,
		// which only creates the validator/delegator/etc tables).
		gateTable := ""
		switch cfg.Type {
		case "", "evm":
			gateTable = "evm_blocks"
		case "platform", "linear":
			gateTable = "pchain_blocks"
		}
		if gateTable != "" {
			db, err := sql.Open("sqlite3", "file:"+dbPath+"?mode=ro")
			if err == nil {
				var n int
				_ = db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", gateTable).Scan(&n)
				db.Close()
				if n == 0 {
					if time.Now().After(deadline) {
						log.Printf("[%s] api waiting for %s", cfg.Slug, gateTable)
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
			// Native-coin balances come from the chain, not from the
			// index — the same RPC this chain is indexed from.
			RPCEndpoint: cfg.RPC,
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

	idx := graphidx.NewWithConfig(graphidx.Config{
		RPC:         cfg.RPC,
		PoolManager: cfg.PoolManager, // empty => indexer defaults to 0x9999
		FactoryV2:   cfg.FactoryV2,
		FactoryV3:   cfg.FactoryV3,
		Native:      cfg.Native,
		// What the token is actually worth: minted at genesis, less what the
		// treasury still holds and what is bonded to validators.
		GenesisSupply: cfg.GenesisSupply,
		Treasury:      cfg.Treasury,
		StartBlock:    cfg.Indexer.StartBlock,
		// Every other line this supervisor emits is prefixed "[slug/name]"; the
		// graph indexer's were not, so in a six-chain process there was no way to
		// tell which chain a line came from — or which chain had gone quiet.
		Label: cfg.Slug + "/" + sg.Name,
	}, store)
	// What a start is for: ask the chain about the Token rows still short an
	// answer — a symbol an earlier read never got, a supply a build that never
	// asked for one left empty. Before Run, so live indexing is not racing the
	// same writes. A row with everything on it costs nothing, which is why this
	// is simply what a start does rather than something to remember to turn on.
	if n, err := idx.BackfillTokens(ctx); err != nil {
		log.Printf("[%s/%s] token backfill: %v (settled=%d)", cfg.Slug, sg.Name, err, n)
	} else {
		log.Printf("[%s/%s] token backfill: settled=%d", cfg.Slug, sg.Name, n)
	}
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

	// The swap form asks four questions the GraphQL schema does not answer in a
	// shape a form can use: what can I trade, what do I get, may the router
	// spend it, and what do I sign. All four read the same store this subgraph
	// already indexes, so they belong beside it rather than behind a second
	// service with a second copy of the book.
	quoter := engine.NewQuoter(store, cfg.ChainID, cfg.RPC, cfg.QuoterV2, cfg.Native)
	mux.HandleFunc("POST "+prefix+"/quote", engine.HandleQuote(quoter))
	mux.HandleFunc("GET "+prefix+"/swappable_tokens", engine.HandleSwappableTokens(store, cfg.ChainID, cfg.CoinSymbol, cfg.Native))
	// A swap is a transaction addressed to this chain's router, and an approval
	// grants that same router the right to spend. Both are rendered into a
	// twenty-byte argument, as is the wrapped native a route substitutes for
	// the coin, so anything else here produces a call whose arguments have slid
	// — signed against an address nobody configured. Without both the routes
	// are simply absent, which a caller can see.
	if canSwap(cfg) {
		mux.HandleFunc("POST "+prefix+"/swap", engine.HandleSwap(cfg.ChainID, cfg.Router, cfg.Native))
		mux.HandleFunc("POST "+prefix+"/check_approval", engine.HandleCheckApproval(cfg.ChainID, cfg.RPC, cfg.Router))
	} else {
		log.Printf("[%s/%s] router=%q native=%q — both must be addresses; /swap and /check_approval not served",
			cfg.Slug, sg.Name, cfg.Router, cfg.Native)
	}

	s.graphRoutes.Store(cfg.Slug+"/"+sg.Name, http.Handler(mux))

	// The same mux answers the unprefixed /v1/{quote,swap,…} routes for this
	// chain. A swap request already carries the chain it is for, so naming it
	// again in the path is a second place for the two to disagree. Registering
	// the handler VALUES here rather than building a second set is what keeps
	// the prefixed and unprefixed routes one implementation.
	//
	// A chain may declare more than one subgraph holding a book, and each runs
	// in its own goroutine, so "whichever registered last" would pick a
	// different book across restarts. The one named in the config first wins,
	// decided from the config rather than from the scheduler.
	if canSwap(cfg) && sg.Name == firstAMM(cfg) {
		s.swapRoutes.Store(cfg.ChainID, &swapMount{prefix: prefix, h: mux})
		if cfg.Default {
			s.mu.Lock()
			s.defaultChainID = cfg.ChainID
			s.mu.Unlock()
		}
	}

	log.Printf("[%s/%s] graph mounted at %s/{graphql,ql,health,quote,swappable_tokens,swap,check_approval} (schema=%s)",
		cfg.Slug, sg.Name, prefix, schema)

	<-ctx.Done()
}

// dispatchIndexer routes /v1/indexer/{slug}/* and /v1/indexer/* (default
// chain) to the per-chain handler installed by mountIndexerAPI.
//
// Edge case the older code got wrong: when the first path segment matches
// the slug regex but is NOT a registered chain (e.g. `main-page` in
// `/v1/indexer/main-page/blocks`), splitSlug peels it off as a "slug" and
// the dispatcher then forwarded only the REMAINING segments to the
// default chain. That turned `/v1/indexer/main-page/blocks` into
// `/v1/indexer/evm/blocks` server-side — a completely different endpoint
// with a different response shape (paginated envelope vs. raw array). The
// SPA's `?.slice(0,8)` on the home page's Latest Blocks widget tripped
// over the envelope and threw "o.slice is not a function".
//
// Fix: when the parsed slug isn't a real chain, re-join it with the rest
// before delegating, so the unrecognized segment is preserved as part of
// the path under the default chain.
func (s *ChainSupervisor) dispatchIndexer(w http.ResponseWriter, r *http.Request) {
	slug, rest, ok := splitSlug(r.URL.Path, "/v1/indexer/")
	if !ok {
		s.serveHost(w, r, "")
		return
	}
	if h, found := s.indexerRoutes.Load(slug); found {
		h.(http.Handler).ServeHTTP(w, r)
		return
	}
	fullTail := slug
	if rest != "" {
		fullTail = slug + "/" + rest
	}
	s.serveHost(w, r, fullTail)
}

// serveHost forwards a slug-less /v1/indexer/* request to the chain the
// request host is served. The standalone server is mounted under its slug, so
// the URL is rewritten to include the slug before delegating.
//
// Pinning this to the configured default instead of the host answered Lux's
// blocks, addresses and tokens on api-explore.hanzo.network and
// api-explore.zoo.network — the same window of Lux heights, to the block, on
// all three brands.
func (s *ChainSupervisor) serveHost(w http.ResponseWriter, r *http.Request, rest string) {
	slug := s.hostSlug(r.Host)
	if slug == "" {
		http.Error(w, `{"error":"no chain for host"}`, http.StatusNotFound)
		return
	}
	h, ok := s.indexerRoutes.Load(slug)
	if !ok {
		http.Error(w, `{"error":"chain not ready"}`, http.StatusServiceUnavailable)
		return
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/v1/indexer/" + slug + "/" + strings.TrimPrefix(rest, "/")
	h.(http.Handler).ServeHTTP(w, r2)
}

// hostSlug is the chain a slug-less request is answered from: the chain the
// host names, when that chain is running, else the default. Chains can be
// added and removed at runtime, so a host naming a chain that is not up falls
// back rather than 404ing.
func (s *ChainSupervisor) hostSlug(host string) string {
	if c, ok := s.cfg.Chain(host); ok {
		if _, running := s.indexerRoutes.Load(c.Slug); running {
			return c.Slug
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.defaultSlug
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
