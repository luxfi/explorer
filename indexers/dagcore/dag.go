// Package dagcore provides shared DAG indexing infrastructure for LUX chains.
// All DAG-based chains (X, A, B, Q, T) use this core library.
//
// Architecture:
//   - Single implementation for DAG vertex/edge management
//   - Chain-specific adapters for different transaction types
//   - Shared WebSocket streaming for live DAG visualization
//   - Common PostgreSQL schema patterns
package dagcore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

// ChainType identifies the DAG chain variant
type ChainType string

const (
	ChainX ChainType = "xchain" // Exchange - assets, UTXOs
	ChainA ChainType = "achain" // AI - attestations, compute
	ChainB ChainType = "bchain" // Bridge - cross-chain transfers
	ChainQ ChainType = "qchain" // Quantum - finality proofs
	ChainT ChainType = "tchain" // Teleport - MPC signatures
)

// ChainConfig holds configuration for a DAG chain indexer
type ChainConfig struct {
	ChainType    ChainType
	ChainName    string
	RPCEndpoint  string
	RPCMethod    string // e.g., "xvm", "avm", "bvm"
	DatabaseURL  string
	HTTPPort     int
	PollInterval time.Duration
}

// DefaultConfigs returns default configurations for each chain
var DefaultConfigs = map[ChainType]ChainConfig{
	ChainX: {ChainType: ChainX, ChainName: "X-Chain (Exchange)", RPCMethod: "xvm", HTTPPort: 4200},
	ChainA: {ChainType: ChainA, ChainName: "A-Chain (AI)", RPCMethod: "avm", HTTPPort: 4500},
	ChainB: {ChainType: ChainB, ChainName: "B-Chain (Bridge)", RPCMethod: "bvm", HTTPPort: 4600},
	ChainQ: {ChainType: ChainQ, ChainName: "Q-Chain (Quantum)", RPCMethod: "qvm", HTTPPort: 4300},
	ChainT: {ChainType: ChainT, ChainName: "T-Chain (Teleport)", RPCMethod: "tvm", HTTPPort: 4700},
}

// =============================================================================
// DAG Core Types
// =============================================================================

// Vertex represents a node in the DAG (transaction, block, etc.)
type Vertex struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	ParentIDs []string               `json:"parentIds,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Status    VertexStatus           `json:"status"`
	Data      json.RawMessage        `json:"data,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	ChainType ChainType              `json:"chainType"`
}

// VertexStatus represents the consensus status of a vertex
type VertexStatus string

const (
	StatusPending  VertexStatus = "pending"
	StatusAccepted VertexStatus = "accepted"
	StatusRejected VertexStatus = "rejected"
)

// Edge represents a connection between vertices
type Edge struct {
	Source string   `json:"source"`
	Target string   `json:"target"`
	Type   EdgeType `json:"type"`
}

// EdgeType categorizes edge relationships
type EdgeType string

const (
	EdgeInput     EdgeType = "input"     // UTXO input reference
	EdgeOutput    EdgeType = "output"    // UTXO output
	EdgeParent    EdgeType = "parent"    // DAG parent reference
	EdgeReference EdgeType = "reference" // General reference
)

// DAGStats holds statistics for a DAG chain
type DAGStats struct {
	TotalVertices    int64     `json:"total_vertices"`
	PendingVertices  int64     `json:"pending_vertices"`
	AcceptedVertices int64     `json:"accepted_vertices"`
	TotalEdges       int64     `json:"total_edges"`
	LastUpdated      time.Time `json:"last_updated"`
	ChainType        ChainType `json:"chain_type"`
	IsLinearized     bool      `json:"is_linearized"`
}

// =============================================================================
// DAG Indexer Core
// =============================================================================

// DAGIndexer is the core indexer for all DAG-based chains
type DAGIndexer struct {
	config     ChainConfig
	db         *sql.DB
	httpClient *http.Client
	subscriber *DAGSubscriber
	poller     *DAGPoller
	mu         sync.RWMutex

	// Chain-specific adapter
	adapter ChainAdapter
}

// ChainAdapter interface for chain-specific logic
type ChainAdapter interface {
	// ParseVertex converts raw RPC data to a Vertex
	ParseVertex(data json.RawMessage) (*Vertex, error)
	// GetRecentVertices fetches recent vertices from RPC
	GetRecentVertices(ctx context.Context, limit int) ([]json.RawMessage, error)
	// GetVertexByID fetches a specific vertex
	GetVertexByID(ctx context.Context, id string) (json.RawMessage, error)
	// InitializeSchema creates chain-specific database tables
	InitializeSchema(db *sql.DB) error
	// GetChainStats returns chain-specific statistics
	GetChainStats(ctx context.Context, db *sql.DB) (map[string]interface{}, error)
}

// NewDAGIndexer creates a new DAG indexer with the specified config
func NewDAGIndexer(cfg ChainConfig, adapter ChainAdapter) (*DAGIndexer, error) {
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	idx := &DAGIndexer{
		config:     cfg,
		db:         db,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		adapter:    adapter,
	}

	// Initialize shared components
	idx.subscriber = NewDAGSubscriber(cfg.ChainType)
	idx.poller = NewDAGPoller(idx, idx.subscriber)

	return idx, nil
}

// Initialize creates the core DAG tables
func (idx *DAGIndexer) Initialize() error {
	// Core DAG schema (shared across all chains)
	coreSchema := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s_vertices (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			parent_ids JSONB DEFAULT '[]',
			timestamp TIMESTAMPTZ NOT NULL,
			status TEXT DEFAULT 'pending',
			data JSONB,
			metadata JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_%s_vertices_status ON %s_vertices(status);
		CREATE INDEX IF NOT EXISTS idx_%s_vertices_timestamp ON %s_vertices(timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_%s_vertices_parents ON %s_vertices USING GIN(parent_ids);

		CREATE TABLE IF NOT EXISTS %s_edges (
			id SERIAL PRIMARY KEY,
			source TEXT NOT NULL,
			target TEXT NOT NULL,
			type TEXT NOT NULL,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			UNIQUE(source, target, type)
		);
		CREATE INDEX IF NOT EXISTS idx_%s_edges_source ON %s_edges(source);
		CREATE INDEX IF NOT EXISTS idx_%s_edges_target ON %s_edges(target);

		CREATE TABLE IF NOT EXISTS %s_stats (
			id SERIAL PRIMARY KEY,
			total_vertices BIGINT DEFAULT 0,
			pending_vertices BIGINT DEFAULT 0,
			accepted_vertices BIGINT DEFAULT 0,
			total_edges BIGINT DEFAULT 0,
			is_linearized BOOLEAN DEFAULT false,
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);
	`,
		idx.config.ChainType, idx.config.ChainType, idx.config.ChainType,
		idx.config.ChainType, idx.config.ChainType, idx.config.ChainType,
		idx.config.ChainType, idx.config.ChainType, idx.config.ChainType,
		idx.config.ChainType, idx.config.ChainType, idx.config.ChainType,
		idx.config.ChainType,
	)

	if _, err := idx.db.Exec(coreSchema); err != nil {
		return fmt.Errorf("failed to create core schema: %w", err)
	}

	// Chain-specific schema
	if idx.adapter != nil {
		if err := idx.adapter.InitializeSchema(idx.db); err != nil {
			return fmt.Errorf("failed to create chain schema: %w", err)
		}
	}

	return nil
}

// RPCCall makes a JSON-RPC call to the chain
func (idx *DAGIndexer) RPCCall(method string, params interface{}) (json.RawMessage, error) {
	fullMethod := fmt.Sprintf("%s.%s", idx.config.RPCMethod, method)

	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  fullMethod,
		"params":  params,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", idx.config.RPCEndpoint, &jsonBuffer{data: body})
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := idx.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, err
	}

	if result.Error != nil {
		return nil, fmt.Errorf("RPC error %d: %s", result.Error.Code, result.Error.Message)
	}

	return result.Result, nil
}

type jsonBuffer struct {
	data []byte
}

func (b *jsonBuffer) Read(p []byte) (n int, err error) {
	n = copy(p, b.data)
	b.data = b.data[n:]
	if len(b.data) == 0 {
		return n, io.EOF
	}
	return n, nil
}

// StoreVertex stores a vertex in the database
func (idx *DAGIndexer) StoreVertex(ctx context.Context, v *Vertex) error {
	parentJSON, _ := json.Marshal(v.ParentIDs)
	metaJSON, _ := json.Marshal(v.Metadata)

	_, err := idx.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s_vertices (id, type, parent_ids, timestamp, status, data, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			metadata = EXCLUDED.metadata
	`, idx.config.ChainType),
		v.ID, v.Type, parentJSON, v.Timestamp, v.Status, v.Data, metaJSON,
	)

	if err == nil {
		// Store edges for parent relationships
		for _, parentID := range v.ParentIDs {
			idx.StoreEdge(ctx, Edge{Source: parentID, Target: v.ID, Type: EdgeParent})
		}

		// Broadcast to subscribers
		idx.subscriber.BroadcastVertex(v)
	}

	return err
}

// StoreEdge stores an edge in the database
func (idx *DAGIndexer) StoreEdge(ctx context.Context, e Edge) error {
	_, err := idx.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s_edges (source, target, type)
		VALUES ($1, $2, $3)
		ON CONFLICT (source, target, type) DO NOTHING
	`, idx.config.ChainType), e.Source, e.Target, e.Type)

	if err == nil {
		idx.subscriber.BroadcastEdge(e)
	}

	return err
}

// UpdateStats updates the DAG statistics
func (idx *DAGIndexer) UpdateStats(ctx context.Context) error {
	var stats DAGStats
	stats.ChainType = idx.config.ChainType

	idx.db.QueryRowContext(ctx, fmt.Sprintf(
		"SELECT COUNT(*) FROM %s_vertices", idx.config.ChainType,
	)).Scan(&stats.TotalVertices)

	idx.db.QueryRowContext(ctx, fmt.Sprintf(
		"SELECT COUNT(*) FROM %s_vertices WHERE status = 'pending'", idx.config.ChainType,
	)).Scan(&stats.PendingVertices)

	idx.db.QueryRowContext(ctx, fmt.Sprintf(
		"SELECT COUNT(*) FROM %s_vertices WHERE status = 'accepted'", idx.config.ChainType,
	)).Scan(&stats.AcceptedVertices)

	idx.db.QueryRowContext(ctx, fmt.Sprintf(
		"SELECT COUNT(*) FROM %s_edges", idx.config.ChainType,
	)).Scan(&stats.TotalEdges)

	_, err := idx.db.ExecContext(ctx, fmt.Sprintf(`
		INSERT INTO %s_stats (id, total_vertices, pending_vertices, accepted_vertices, total_edges, updated_at)
		VALUES (1, $1, $2, $3, $4, NOW())
		ON CONFLICT (id) DO UPDATE SET
			total_vertices = EXCLUDED.total_vertices,
			pending_vertices = EXCLUDED.pending_vertices,
			accepted_vertices = EXCLUDED.accepted_vertices,
			total_edges = EXCLUDED.total_edges,
			updated_at = NOW()
	`, idx.config.ChainType),
		stats.TotalVertices, stats.PendingVertices, stats.AcceptedVertices, stats.TotalEdges,
	)

	return err
}

// =============================================================================
// HTTP Server
// =============================================================================

// StartHTTPServer starts the REST API server
func (idx *DAGIndexer) StartHTTPServer(ctx context.Context) error {
	r := mux.NewRouter()

	// API v2 compatible endpoints (Blockscout-style)
	api := r.PathPrefix("/api/v2").Subrouter()

	// Core DAG endpoints
	api.HandleFunc("/stats", idx.handleStats).Methods("GET")
	api.HandleFunc("/vertices", idx.handleVertices).Methods("GET")
	api.HandleFunc("/vertices/{id}", idx.handleVertex).Methods("GET")
	api.HandleFunc("/edges", idx.handleEdges).Methods("GET")

	// DAG WebSocket for live streaming
	api.HandleFunc("/dag/subscribe", idx.subscriber.HandleWebSocket)

	// Health check
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"chain":     idx.config.ChainName,
			"chainType": idx.config.ChainType,
			"type":      "DAG",
		})
	}).Methods("GET")

	// CORS middleware
	handler := corsMiddleware(r)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", idx.config.HTTPPort),
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	log.Printf("%s indexer API listening on port %d", idx.config.ChainName, idx.config.HTTPPort)
	return server.ListenAndServe()
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Content-Type", "application/json")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (idx *DAGIndexer) handleStats(w http.ResponseWriter, r *http.Request) {
	var stats DAGStats
	stats.ChainType = idx.config.ChainType
	stats.LastUpdated = time.Now()

	idx.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s_vertices", idx.config.ChainType)).Scan(&stats.TotalVertices)
	idx.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s_vertices WHERE status = 'pending'", idx.config.ChainType)).Scan(&stats.PendingVertices)
	idx.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s_vertices WHERE status = 'accepted'", idx.config.ChainType)).Scan(&stats.AcceptedVertices)
	idx.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s_edges", idx.config.ChainType)).Scan(&stats.TotalEdges)

	// Add chain-specific stats
	response := map[string]interface{}{
		"dag_stats": stats,
	}

	if idx.adapter != nil {
		chainStats, _ := idx.adapter.GetChainStats(r.Context(), idx.db)
		response["chain_stats"] = chainStats
	}

	json.NewEncoder(w).Encode(response)
}

func (idx *DAGIndexer) handleVertices(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0

	rows, err := idx.db.Query(fmt.Sprintf(`
		SELECT id, type, parent_ids, timestamp, status, data, metadata
		FROM %s_vertices
		ORDER BY timestamp DESC
		LIMIT $1 OFFSET $2
	`, idx.config.ChainType), limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var vertices []Vertex
	for rows.Next() {
		var v Vertex
		var parentIDs, data, metadata []byte
		rows.Scan(&v.ID, &v.Type, &parentIDs, &v.Timestamp, &v.Status, &data, &metadata)
		json.Unmarshal(parentIDs, &v.ParentIDs)
		v.Data = data
		json.Unmarshal(metadata, &v.Metadata)
		v.ChainType = idx.config.ChainType
		vertices = append(vertices, v)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items": vertices,
	})
}

func (idx *DAGIndexer) handleVertex(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	var v Vertex
	var parentIDs, data, metadata []byte
	err := idx.db.QueryRow(fmt.Sprintf(`
		SELECT id, type, parent_ids, timestamp, status, data, metadata
		FROM %s_vertices WHERE id = $1
	`, idx.config.ChainType), id).Scan(
		&v.ID, &v.Type, &parentIDs, &v.Timestamp, &v.Status, &data, &metadata,
	)

	if err != nil {
		http.Error(w, "Vertex not found", http.StatusNotFound)
		return
	}

	json.Unmarshal(parentIDs, &v.ParentIDs)
	v.Data = data
	json.Unmarshal(metadata, &v.Metadata)
	v.ChainType = idx.config.ChainType

	json.NewEncoder(w).Encode(v)
}

func (idx *DAGIndexer) handleEdges(w http.ResponseWriter, r *http.Request) {
	vertexID := r.URL.Query().Get("vertex")

	var rows *sql.Rows
	var err error

	if vertexID != "" {
		rows, err = idx.db.Query(fmt.Sprintf(`
			SELECT source, target, type FROM %s_edges
			WHERE source = $1 OR target = $1
		`, idx.config.ChainType), vertexID)
	} else {
		rows, err = idx.db.Query(fmt.Sprintf(`
			SELECT source, target, type FROM %s_edges
			ORDER BY created_at DESC LIMIT 100
		`, idx.config.ChainType))
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var edges []Edge
	for rows.Next() {
		var e Edge
		rows.Scan(&e.Source, &e.Target, &e.Type)
		edges = append(edges, e)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items": edges,
	})
}

// Run starts the DAG indexer
func (idx *DAGIndexer) Run(ctx context.Context) error {
	if err := idx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}

	// Start WebSocket subscriber
	go idx.subscriber.Run(ctx)
	log.Printf("[%s] DAG WebSocket streaming enabled at /api/v2/dag/subscribe", idx.config.ChainType)

	// Start DAG poller
	go idx.poller.Run(ctx)
	log.Printf("[%s] DAG poller started", idx.config.ChainType)

	// Start HTTP server
	go idx.StartHTTPServer(ctx)

	// Stats update loop
	ticker := time.NewTicker(idx.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := idx.UpdateStats(ctx); err != nil {
				log.Printf("[%s] Error updating stats: %v", idx.config.ChainType, err)
			}
		}
	}
}

// =============================================================================
// WebSocket Subscriber
// =============================================================================

// DAGSubscriber handles WebSocket connections for live DAG streaming
type DAGSubscriber struct {
	chainType  ChainType
	clients    map[*websocket.Conn]bool
	broadcast  chan interface{}
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
	mu         sync.RWMutex
	upgrader   websocket.Upgrader
}

// NewDAGSubscriber creates a new subscriber
func NewDAGSubscriber(chainType ChainType) *DAGSubscriber {
	return &DAGSubscriber{
		chainType:  chainType,
		clients:    make(map[*websocket.Conn]bool),
		broadcast:  make(chan interface{}, 100),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// Run starts the subscriber
func (ds *DAGSubscriber) Run(ctx context.Context) {
	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			ds.mu.Lock()
			for client := range ds.clients {
				client.Close()
			}
			ds.mu.Unlock()
			return

		case client := <-ds.register:
			ds.mu.Lock()
			ds.clients[client] = true
			log.Printf("[%s WS] Client connected (%d total)", ds.chainType, len(ds.clients))
			ds.mu.Unlock()

		case client := <-ds.unregister:
			ds.mu.Lock()
			if _, ok := ds.clients[client]; ok {
				delete(ds.clients, client)
				client.Close()
				log.Printf("[%s WS] Client disconnected (%d total)", ds.chainType, len(ds.clients))
			}
			ds.mu.Unlock()

		case msg := <-ds.broadcast:
			ds.mu.RLock()
			for client := range ds.clients {
				if err := client.WriteJSON(msg); err != nil {
					go func(c *websocket.Conn) { ds.unregister <- c }(client)
				}
			}
			ds.mu.RUnlock()

		case <-heartbeat.C:
			ds.broadcast <- map[string]interface{}{
				"type":      "heartbeat",
				"chainType": ds.chainType,
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			}
		}
	}
}

// HandleWebSocket handles WebSocket upgrade
func (ds *DAGSubscriber) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := ds.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	ds.register <- conn

	// Send initial state
	conn.WriteJSON(map[string]interface{}{
		"type":      "initial_state",
		"chainType": ds.chainType,
		"data":      map[string]interface{}{"nodes": []interface{}{}, "edges": []interface{}{}},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})

	// Read loop (detect disconnect)
	go func() {
		defer func() { ds.unregister <- conn }()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				break
			}
		}
	}()
}

// BroadcastVertex broadcasts a new vertex
func (ds *DAGSubscriber) BroadcastVertex(v *Vertex) {
	ds.broadcast <- map[string]interface{}{
		"type":      "vertex_added",
		"chainType": ds.chainType,
		"data":      map[string]interface{}{"node": v},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
}

// BroadcastEdge broadcasts a new edge
func (ds *DAGSubscriber) BroadcastEdge(e Edge) {
	ds.broadcast <- map[string]interface{}{
		"type":      "edge_added",
		"chainType": ds.chainType,
		"data":      map[string]interface{}{"edge": e},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
}

// GetClientCount returns connected client count
func (ds *DAGSubscriber) GetClientCount() int {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	return len(ds.clients)
}

// =============================================================================
// DAG Poller
// =============================================================================

// DAGPoller polls chain for new vertices
type DAGPoller struct {
	indexer    *DAGIndexer
	subscriber *DAGSubscriber
	lastID     string
	mu         sync.Mutex
}

// NewDAGPoller creates a new poller
func NewDAGPoller(idx *DAGIndexer, sub *DAGSubscriber) *DAGPoller {
	return &DAGPoller{indexer: idx, subscriber: sub}
}

// Run starts polling
func (dp *DAGPoller) Run(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if dp.subscriber.GetClientCount() == 0 {
				continue
			}
			dp.poll(ctx)
		}
	}
}

func (dp *DAGPoller) poll(ctx context.Context) {
	if dp.indexer.adapter == nil {
		return
	}

	rawVertices, err := dp.indexer.adapter.GetRecentVertices(ctx, 10)
	if err != nil {
		return
	}

	dp.mu.Lock()
	lastID := dp.lastID
	dp.mu.Unlock()

	var newLastID string
	for _, raw := range rawVertices {
		vertex, err := dp.indexer.adapter.ParseVertex(raw)
		if err != nil {
			continue
		}

		if newLastID == "" {
			newLastID = vertex.ID
		}

		if vertex.ID == lastID {
			break
		}

		dp.indexer.StoreVertex(ctx, vertex)
	}

	if newLastID != "" {
		dp.mu.Lock()
		dp.lastID = newLastID
		dp.mu.Unlock()
	}
}
