// P-Chain Explorer Indexer
// Lightweight indexer for LUX Platform Chain (validators, staking, networks)
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// Config holds indexer configuration
type Config struct {
	RPCEndpoint  string
	DatabaseURL  string
	HTTPPort     int
	PollInterval time.Duration
}

// Validator represents a P-Chain validator
type Validator struct {
	NodeID          string    `json:"nodeId"`
	StartTime       time.Time `json:"startTime"`
	EndTime         time.Time `json:"endTime"`
	StakeAmount     string    `json:"stakeAmount"`
	Weight          string    `json:"weight"`
	ValidationID    string    `json:"validationId,omitempty"`
	Connected       bool      `json:"connected"`
	Uptime          float64   `json:"uptime"`
	DelegatorCount  int       `json:"delegatorCount,omitempty"`
	DelegatorWeight string    `json:"delegatorWeight,omitempty"`
}

// Delegator represents a delegator to a validator
type Delegator struct {
	NodeID      string    `json:"nodeId"`
	StartTime   time.Time `json:"startTime"`
	EndTime     time.Time `json:"endTime"`
	StakeAmount string    `json:"stakeAmount"`
	RewardOwner string    `json:"rewardOwner"`
}

// Block represents a P-Chain block
type Block struct {
	ID        string    `json:"id"`
	ParentID  string    `json:"parentId"`
	Height    uint64    `json:"height"`
	Timestamp time.Time `json:"timestamp"`
	TxCount   int       `json:"txCount"`
}

// Network represents a subnet/network
type Network struct {
	ID           string   `json:"id"`
	ControlKeys  []string `json:"controlKeys"`
	Threshold    uint32   `json:"threshold"`
	Owner        string   `json:"owner,omitempty"`
	Blockchains  []string `json:"blockchains,omitempty"`
	ValidatorSet []string `json:"validatorSet,omitempty"`
}

// Indexer handles P-Chain indexing
type Indexer struct {
	config     Config
	db         *sql.DB
	httpClient *http.Client
	mu         sync.RWMutex
	lastHeight uint64
}

// NewIndexer creates a new P-Chain indexer
func NewIndexer(cfg Config) (*Indexer, error) {
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &Indexer{
		config:     cfg,
		db:         db,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// Initialize creates database tables
func (idx *Indexer) Initialize() error {
	schema := `
		CREATE TABLE IF NOT EXISTS pchain_blocks (
			id TEXT PRIMARY KEY,
			parent_id TEXT,
			height BIGINT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL,
			tx_count INT DEFAULT 0,
			raw_data JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_pchain_blocks_height ON pchain_blocks(height);

		CREATE TABLE IF NOT EXISTS pchain_validators (
			node_id TEXT PRIMARY KEY,
			validation_id TEXT,
			start_time TIMESTAMPTZ NOT NULL,
			end_time TIMESTAMPTZ NOT NULL,
			stake_amount NUMERIC NOT NULL,
			weight NUMERIC NOT NULL,
			connected BOOLEAN DEFAULT false,
			uptime DECIMAL(5,2) DEFAULT 0,
			delegator_count INT DEFAULT 0,
			delegator_weight NUMERIC DEFAULT 0,
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_pchain_validators_stake ON pchain_validators(stake_amount DESC);

		CREATE TABLE IF NOT EXISTS pchain_delegators (
			id SERIAL PRIMARY KEY,
			node_id TEXT NOT NULL REFERENCES pchain_validators(node_id),
			start_time TIMESTAMPTZ NOT NULL,
			end_time TIMESTAMPTZ NOT NULL,
			stake_amount NUMERIC NOT NULL,
			reward_owner TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_pchain_delegators_node ON pchain_delegators(node_id);

		CREATE TABLE IF NOT EXISTS pchain_networks (
			id TEXT PRIMARY KEY,
			threshold INT NOT NULL,
			owner TEXT,
			control_keys JSONB,
			blockchains JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS pchain_transactions (
			id TEXT PRIMARY KEY,
			block_id TEXT REFERENCES pchain_blocks(id),
			type TEXT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL,
			fee NUMERIC,
			inputs JSONB,
			outputs JSONB,
			raw_data JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_pchain_transactions_block ON pchain_transactions(block_id);
		CREATE INDEX IF NOT EXISTS idx_pchain_transactions_type ON pchain_transactions(type);
	`

	_, err := idx.db.Exec(schema)
	return err
}

// RPCCall makes a JSON-RPC call to the P-Chain
func (idx *Indexer) RPCCall(method string, params interface{}) (json.RawMessage, error) {
	reqBody := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := idx.httpClient.Post(idx.config.RPCEndpoint, "application/json",
		&jsonBuffer{data: body})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
		return n, nil
	}
	return n, nil
}

// FetchCurrentValidators fetches and stores current validators
func (idx *Indexer) FetchCurrentValidators(ctx context.Context) error {
	result, err := idx.RPCCall("platform.getCurrentValidators", map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to get validators: %w", err)
	}

	var response struct {
		Validators []struct {
			NodeID          string  `json:"nodeID"`
			StartTime       string  `json:"startTime"`
			EndTime         string  `json:"endTime"`
			StakeAmount     string  `json:"stakeAmount"`
			Weight          string  `json:"weight"`
			ValidationID    string  `json:"validationID"`
			Connected       bool    `json:"connected"`
			Uptime          string  `json:"uptime"`
			DelegatorCount  int     `json:"delegatorCount"`
			DelegatorWeight string  `json:"delegatorWeight"`
		} `json:"validators"`
	}

	if err := json.Unmarshal(result, &response); err != nil {
		return fmt.Errorf("failed to parse validators: %w", err)
	}

	tx, err := idx.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, v := range response.Validators {
		startTime, _ := time.Parse(time.RFC3339, v.StartTime)
		endTime, _ := time.Parse(time.RFC3339, v.EndTime)

		_, err := tx.ExecContext(ctx, `
			INSERT INTO pchain_validators
			(node_id, validation_id, start_time, end_time, stake_amount, weight, connected, uptime, delegator_count, delegator_weight, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
			ON CONFLICT (node_id) DO UPDATE SET
				validation_id = EXCLUDED.validation_id,
				start_time = EXCLUDED.start_time,
				end_time = EXCLUDED.end_time,
				stake_amount = EXCLUDED.stake_amount,
				weight = EXCLUDED.weight,
				connected = EXCLUDED.connected,
				uptime = EXCLUDED.uptime,
				delegator_count = EXCLUDED.delegator_count,
				delegator_weight = EXCLUDED.delegator_weight,
				updated_at = NOW()
		`, v.NodeID, v.ValidationID, startTime, endTime, v.StakeAmount, v.Weight,
			v.Connected, v.Uptime, v.DelegatorCount, v.DelegatorWeight)
		if err != nil {
			return fmt.Errorf("failed to upsert validator: %w", err)
		}
	}

	return tx.Commit()
}

// FetchHeight gets current chain height
func (idx *Indexer) FetchHeight(ctx context.Context) (uint64, error) {
	result, err := idx.RPCCall("platform.getHeight", map[string]interface{}{})
	if err != nil {
		return 0, err
	}

	var response struct {
		Height string `json:"height"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return 0, err
	}

	var height uint64
	fmt.Sscanf(response.Height, "%d", &height)
	return height, nil
}

// IndexBlocks indexes blocks from last known height
func (idx *Indexer) IndexBlocks(ctx context.Context) error {
	height, err := idx.FetchHeight(ctx)
	if err != nil {
		return err
	}

	idx.mu.RLock()
	lastHeight := idx.lastHeight
	idx.mu.RUnlock()

	if height <= lastHeight {
		return nil // Nothing new to index
	}

	for h := lastHeight + 1; h <= height; h++ {
		if err := idx.IndexBlockByHeight(ctx, h); err != nil {
			log.Printf("Failed to index block %d: %v", h, err)
			continue
		}
		idx.mu.Lock()
		idx.lastHeight = h
		idx.mu.Unlock()
	}

	return nil
}

// IndexBlockByHeight indexes a single block
func (idx *Indexer) IndexBlockByHeight(ctx context.Context, height uint64) error {
	result, err := idx.RPCCall("platform.getBlockByHeight", map[string]interface{}{
		"height":   fmt.Sprintf("%d", height),
		"encoding": "json",
	})
	if err != nil {
		return err
	}

	var blockData map[string]interface{}
	if err := json.Unmarshal(result, &blockData); err != nil {
		return err
	}

	blockID, _ := blockData["id"].(string)
	parentID, _ := blockData["parentID"].(string)
	timestamp, _ := blockData["timestamp"].(string)
	ts, _ := time.Parse(time.RFC3339, timestamp)

	rawJSON, _ := json.Marshal(blockData)

	_, err = idx.db.ExecContext(ctx, `
		INSERT INTO pchain_blocks (id, parent_id, height, timestamp, raw_data)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO NOTHING
	`, blockID, parentID, height, ts, rawJSON)

	return err
}

// StartHTTPServer starts the REST API server
func (idx *Indexer) StartHTTPServer(ctx context.Context) error {
	r := mux.NewRouter()

	// API v2 compatible endpoints (like Blockscout)
	api := r.PathPrefix("/api/v2").Subrouter()

	api.HandleFunc("/stats", idx.handleStats).Methods("GET")
	api.HandleFunc("/blocks", idx.handleBlocks).Methods("GET")
	api.HandleFunc("/blocks/{id}", idx.handleBlock).Methods("GET")
	api.HandleFunc("/validators", idx.handleValidators).Methods("GET")
	api.HandleFunc("/validators/{nodeId}", idx.handleValidator).Methods("GET")
	api.HandleFunc("/networks", idx.handleNetworks).Methods("GET")
	api.HandleFunc("/networks/{id}", idx.handleNetwork).Methods("GET")

	// Health check
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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

	log.Printf("P-Chain indexer API listening on port %d", idx.config.HTTPPort)
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

func (idx *Indexer) handleStats(w http.ResponseWriter, r *http.Request) {
	var stats struct {
		TotalBlocks     int64  `json:"total_blocks"`
		TotalValidators int64  `json:"total_validators"`
		TotalNetworks   int64  `json:"total_networks"`
		TotalStake      string `json:"total_stake"`
		LastHeight      uint64 `json:"last_height"`
	}

	idx.db.QueryRow("SELECT COUNT(*) FROM pchain_blocks").Scan(&stats.TotalBlocks)
	idx.db.QueryRow("SELECT COUNT(*) FROM pchain_validators").Scan(&stats.TotalValidators)
	idx.db.QueryRow("SELECT COUNT(*) FROM pchain_networks").Scan(&stats.TotalNetworks)
	idx.db.QueryRow("SELECT COALESCE(SUM(stake_amount), 0) FROM pchain_validators").Scan(&stats.TotalStake)

	idx.mu.RLock()
	stats.LastHeight = idx.lastHeight
	idx.mu.RUnlock()

	json.NewEncoder(w).Encode(stats)
}

func (idx *Indexer) handleBlocks(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0

	rows, err := idx.db.Query(`
		SELECT id, parent_id, height, timestamp, tx_count
		FROM pchain_blocks
		ORDER BY height DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var blocks []Block
	for rows.Next() {
		var b Block
		rows.Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.TxCount)
		blocks = append(blocks, b)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":      blocks,
		"next_page_params": nil,
	})
}

func (idx *Indexer) handleBlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	blockID := vars["id"]

	var b Block
	var rawData []byte
	err := idx.db.QueryRow(`
		SELECT id, parent_id, height, timestamp, tx_count, raw_data
		FROM pchain_blocks WHERE id = $1
	`, blockID).Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.TxCount, &rawData)
	if err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(b)
}

func (idx *Indexer) handleValidators(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT node_id, validation_id, start_time, end_time, stake_amount, weight,
		       connected, uptime, delegator_count, delegator_weight
		FROM pchain_validators
		ORDER BY stake_amount DESC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var validators []Validator
	for rows.Next() {
		var v Validator
		rows.Scan(&v.NodeID, &v.ValidationID, &v.StartTime, &v.EndTime,
			&v.StakeAmount, &v.Weight, &v.Connected, &v.Uptime,
			&v.DelegatorCount, &v.DelegatorWeight)
		validators = append(validators, v)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items": validators,
	})
}

func (idx *Indexer) handleValidator(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nodeID := vars["nodeId"]

	var v Validator
	err := idx.db.QueryRow(`
		SELECT node_id, validation_id, start_time, end_time, stake_amount, weight,
		       connected, uptime, delegator_count, delegator_weight
		FROM pchain_validators WHERE node_id = $1
	`, nodeID).Scan(&v.NodeID, &v.ValidationID, &v.StartTime, &v.EndTime,
		&v.StakeAmount, &v.Weight, &v.Connected, &v.Uptime,
		&v.DelegatorCount, &v.DelegatorWeight)
	if err != nil {
		http.Error(w, "Validator not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(v)
}

func (idx *Indexer) handleNetworks(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, threshold, owner, control_keys, blockchains
		FROM pchain_networks
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var networks []Network
	for rows.Next() {
		var n Network
		var controlKeys, blockchains []byte
		rows.Scan(&n.ID, &n.Threshold, &n.Owner, &controlKeys, &blockchains)
		json.Unmarshal(controlKeys, &n.ControlKeys)
		json.Unmarshal(blockchains, &n.Blockchains)
		networks = append(networks, n)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items": networks,
	})
}

func (idx *Indexer) handleNetwork(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	netID := vars["id"]

	var n Network
	var controlKeys, blockchains []byte
	err := idx.db.QueryRow(`
		SELECT id, threshold, owner, control_keys, blockchains
		FROM pchain_networks WHERE id = $1
	`, netID).Scan(&n.ID, &n.Threshold, &n.Owner, &controlKeys, &blockchains)
	if err != nil {
		http.Error(w, "Network not found", http.StatusNotFound)
		return
	}
	json.Unmarshal(controlKeys, &n.ControlKeys)
	json.Unmarshal(blockchains, &n.Blockchains)

	json.NewEncoder(w).Encode(n)
}

// Run starts the indexer
func (idx *Indexer) Run(ctx context.Context) error {
	// Initialize database
	if err := idx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}

	// Get last indexed height from DB
	var lastHeight sql.NullInt64
	idx.db.QueryRow("SELECT MAX(height) FROM pchain_blocks").Scan(&lastHeight)
	if lastHeight.Valid {
		idx.lastHeight = uint64(lastHeight.Int64)
	}

	// Start HTTP server in background
	go idx.StartHTTPServer(ctx)

	// Start indexing loop
	ticker := time.NewTicker(idx.config.PollInterval)
	defer ticker.Stop()

	// Initial fetch
	idx.FetchCurrentValidators(ctx)
	idx.IndexBlocks(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := idx.FetchCurrentValidators(ctx); err != nil {
				log.Printf("Error fetching validators: %v", err)
			}
			if err := idx.IndexBlocks(ctx); err != nil {
				log.Printf("Error indexing blocks: %v", err)
			}
		}
	}
}

func main() {
	cfg := Config{
		RPCEndpoint:  os.Getenv("RPC_ENDPOINT"),
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		HTTPPort:     4100,
		PollInterval: 10 * time.Second,
	}

	// Parse flags
	flag.StringVar(&cfg.RPCEndpoint, "rpc", cfg.RPCEndpoint, "P-Chain RPC endpoint")
	flag.StringVar(&cfg.DatabaseURL, "db", cfg.DatabaseURL, "PostgreSQL connection string")
	flag.IntVar(&cfg.HTTPPort, "port", cfg.HTTPPort, "HTTP API port")
	flag.Parse()

	if cfg.RPCEndpoint == "" {
		cfg.RPCEndpoint = "http://localhost:9630/ext/bc/P"
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://blockscout:blockscout@localhost:5432/explorer_pchain?sslmode=disable"
	}

	indexer, err := NewIndexer(cfg)
	if err != nil {
		log.Fatalf("Failed to create indexer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	log.Printf("Starting P-Chain indexer...")
	log.Printf("RPC Endpoint: %s", cfg.RPCEndpoint)
	log.Printf("Database: %s", cfg.DatabaseURL)

	if err := indexer.Run(ctx); err != nil {
		log.Fatalf("Indexer error: %v", err)
	}
}
