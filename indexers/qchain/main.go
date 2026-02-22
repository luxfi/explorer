// Q-Chain Explorer Indexer
// Lightweight indexer for LUX Quantum Chain (quantum stamps, finality, cross-chain references)
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

// QuantumStamp represents a Q-Chain quantum stamp (cross-chain finality proof)
type QuantumStamp struct {
	ID              string    `json:"id"`
	CChainBlockHash string    `json:"cChainBlockHash"`
	CChainBlockNum  uint64    `json:"cChainBlockNum"`
	QChainBlockHash string    `json:"qChainBlockHash"`
	QChainBlockNum  uint64    `json:"qChainBlockNum"`
	StampMode       string    `json:"stampMode"` // MLDSA44, MLDSA65, MLDSA87, SLHDSA, Hybrid
	Signature       string    `json:"signature"`
	PublicKey       string    `json:"publicKey,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	Verified        bool      `json:"verified"`
}

// QuantumBlock represents a Q-Chain block
type QuantumBlock struct {
	ID               string    `json:"id"`
	ParentID         string    `json:"parentId"`
	Height           uint64    `json:"height"`
	Timestamp        time.Time `json:"timestamp"`
	TxCount          int       `json:"txCount"`
	QuantumSignature string    `json:"quantumSignature,omitempty"`
	Algorithm        string    `json:"algorithm,omitempty"` // ML-DSA, SLH-DSA, etc.
	StampCount       int       `json:"stampCount"`
}

// QuantumTransaction represents a Q-Chain transaction
type QuantumTransaction struct {
	ID               string          `json:"id"`
	Type             string          `json:"type"` // stamp, verify, key_gen
	BlockID          string          `json:"blockId"`
	BlockHeight      uint64          `json:"blockHeight"`
	Timestamp        time.Time       `json:"timestamp"`
	QuantumSignature string          `json:"quantumSignature,omitempty"`
	Payload          json.RawMessage `json:"payload,omitempty"`
}

// RingtailKey represents a quantum-resistant key
type RingtailKey struct {
	ID        string    `json:"id"`
	PublicKey string    `json:"publicKey"`
	Version   int       `json:"version"`
	KeySize   int       `json:"keySize"`
	CreatedAt time.Time `json:"createdAt"`
	Owner     string    `json:"owner,omitempty"`
}

// FinalityStatus represents cross-chain finality status
type FinalityStatus struct {
	ChainID          string    `json:"chainId"`
	ChainName        string    `json:"chainName"`
	LastStampedBlock uint64    `json:"lastStampedBlock"`
	LastStampTime    time.Time `json:"lastStampTime"`
	TotalStamps      int64     `json:"totalStamps"`
	VerifiedStamps   int64     `json:"verifiedStamps"`
}

// Indexer handles Q-Chain indexing
type Indexer struct {
	config     Config
	db         *sql.DB
	httpClient *http.Client
	mu         sync.RWMutex
	lastHeight uint64
}

// NewIndexer creates a new Q-Chain indexer
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
		CREATE TABLE IF NOT EXISTS qchain_blocks (
			id TEXT PRIMARY KEY,
			parent_id TEXT,
			height BIGINT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL,
			tx_count INT DEFAULT 0,
			quantum_signature TEXT,
			algorithm TEXT,
			stamp_count INT DEFAULT 0,
			raw_data JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_qchain_blocks_height ON qchain_blocks(height);

		CREATE TABLE IF NOT EXISTS qchain_transactions (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			block_id TEXT REFERENCES qchain_blocks(id),
			block_height BIGINT,
			timestamp TIMESTAMPTZ NOT NULL,
			quantum_signature TEXT,
			payload JSONB,
			raw_data JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_qchain_transactions_block ON qchain_transactions(block_id);
		CREATE INDEX IF NOT EXISTS idx_qchain_transactions_type ON qchain_transactions(type);

		CREATE TABLE IF NOT EXISTS qchain_stamps (
			id TEXT PRIMARY KEY,
			cchain_block_hash TEXT NOT NULL,
			cchain_block_num BIGINT NOT NULL,
			qchain_block_hash TEXT NOT NULL,
			qchain_block_num BIGINT NOT NULL,
			stamp_mode TEXT NOT NULL,
			signature TEXT NOT NULL,
			public_key TEXT,
			timestamp TIMESTAMPTZ NOT NULL,
			verified BOOLEAN DEFAULT false,
			verified_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_qchain_stamps_cchain ON qchain_stamps(cchain_block_num);
		CREATE INDEX IF NOT EXISTS idx_qchain_stamps_qchain ON qchain_stamps(qchain_block_num);
		CREATE INDEX IF NOT EXISTS idx_qchain_stamps_mode ON qchain_stamps(stamp_mode);
		CREATE INDEX IF NOT EXISTS idx_qchain_stamps_verified ON qchain_stamps(verified);

		CREATE TABLE IF NOT EXISTS qchain_ringtail_keys (
			id TEXT PRIMARY KEY,
			public_key TEXT NOT NULL,
			version INT DEFAULT 1,
			key_size INT DEFAULT 1024,
			owner TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_qchain_ringtail_keys_owner ON qchain_ringtail_keys(owner);

		CREATE TABLE IF NOT EXISTS qchain_finality_status (
			chain_id TEXT PRIMARY KEY,
			chain_name TEXT NOT NULL,
			last_stamped_block BIGINT DEFAULT 0,
			last_stamp_time TIMESTAMPTZ,
			total_stamps BIGINT DEFAULT 0,
			verified_stamps BIGINT DEFAULT 0,
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);

		-- Initialize finality tracking for known chains
		INSERT INTO qchain_finality_status (chain_id, chain_name) VALUES
			('96369', 'LUX Mainnet'),
			('96368', 'LUX Testnet'),
			('1337', 'LUX Devnet'),
			('200200', 'ZOO Mainnet'),
			('200201', 'ZOO Testnet')
		ON CONFLICT (chain_id) DO NOTHING;
	`

	_, err := idx.db.Exec(schema)
	return err
}

// RPCCall makes a JSON-RPC call to the Q-Chain
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

// FetchBlock fetches a Q-Chain block
func (idx *Indexer) FetchBlock(ctx context.Context, blockID string) (*QuantumBlock, error) {
	result, err := idx.RPCCall("qvm.getBlock", map[string]interface{}{
		"blockID":  blockID,
		"encoding": "json",
	})
	if err != nil {
		return nil, err
	}

	var block QuantumBlock
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, err
	}

	return &block, nil
}

// FetchPendingTransactions fetches pending transactions
func (idx *Indexer) FetchPendingTransactions(ctx context.Context) ([]QuantumTransaction, error) {
	result, err := idx.RPCCall("qvm.getPendingTransactions", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	var response struct {
		Transactions []QuantumTransaction `json:"txs"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, err
	}

	return response.Transactions, nil
}

// FetchHealth fetches Q-Chain health status
func (idx *Indexer) FetchHealth(ctx context.Context) (map[string]interface{}, error) {
	result, err := idx.RPCCall("qvm.getHealth", map[string]interface{}{})
	if err != nil {
		return nil, err
	}

	var health map[string]interface{}
	if err := json.Unmarshal(result, &health); err != nil {
		return nil, err
	}

	return health, nil
}

// IndexBlocks indexes blocks (placeholder - Q-Chain may have different block structure)
func (idx *Indexer) IndexBlocks(ctx context.Context) error {
	// Q-Chain block indexing would be similar to other chains
	// but focuses on quantum stamps and finality proofs
	return nil
}

// StartHTTPServer starts the REST API server
func (idx *Indexer) StartHTTPServer(ctx context.Context) error {
	r := mux.NewRouter()

	// API v2 compatible endpoints
	api := r.PathPrefix("/api/v2").Subrouter()

	api.HandleFunc("/stats", idx.handleStats).Methods("GET")
	api.HandleFunc("/blocks", idx.handleBlocks).Methods("GET")
	api.HandleFunc("/blocks/{id}", idx.handleBlock).Methods("GET")
	api.HandleFunc("/transactions", idx.handleTransactions).Methods("GET")
	api.HandleFunc("/transactions/{id}", idx.handleTransaction).Methods("GET")
	api.HandleFunc("/stamps", idx.handleStamps).Methods("GET")
	api.HandleFunc("/stamps/{id}", idx.handleStamp).Methods("GET")
	api.HandleFunc("/stamps/by-cchain/{blockNum}", idx.handleStampByCChainBlock).Methods("GET")
	api.HandleFunc("/finality", idx.handleFinalityStatus).Methods("GET")
	api.HandleFunc("/finality/{chainId}", idx.handleChainFinality).Methods("GET")
	api.HandleFunc("/keys", idx.handleRingtailKeys).Methods("GET")
	api.HandleFunc("/keys/{id}", idx.handleRingtailKey).Methods("GET")

	// Health check
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		health, err := idx.FetchHealth(context.Background())
		if err != nil {
			json.NewEncoder(w).Encode(map[string]string{"status": "ok", "rpc": "unavailable"})
			return
		}
		json.NewEncoder(w).Encode(health)
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

	log.Printf("Q-Chain indexer API listening on port %d", idx.config.HTTPPort)
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
		TotalBlocks       int64            `json:"total_blocks"`
		TotalTransactions int64            `json:"total_transactions"`
		TotalStamps       int64            `json:"total_stamps"`
		VerifiedStamps    int64            `json:"verified_stamps"`
		TotalKeys         int64            `json:"total_keys"`
		LastHeight        uint64           `json:"last_height"`
		StampModes        map[string]int64 `json:"stamp_modes"`
	}

	idx.db.QueryRow("SELECT COUNT(*) FROM qchain_blocks").Scan(&stats.TotalBlocks)
	idx.db.QueryRow("SELECT COUNT(*) FROM qchain_transactions").Scan(&stats.TotalTransactions)
	idx.db.QueryRow("SELECT COUNT(*) FROM qchain_stamps").Scan(&stats.TotalStamps)
	idx.db.QueryRow("SELECT COUNT(*) FROM qchain_stamps WHERE verified").Scan(&stats.VerifiedStamps)
	idx.db.QueryRow("SELECT COUNT(*) FROM qchain_ringtail_keys").Scan(&stats.TotalKeys)

	// Get stamp mode distribution
	stats.StampModes = make(map[string]int64)
	rows, _ := idx.db.Query("SELECT stamp_mode, COUNT(*) FROM qchain_stamps GROUP BY stamp_mode")
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var mode string
			var count int64
			rows.Scan(&mode, &count)
			stats.StampModes[mode] = count
		}
	}

	idx.mu.RLock()
	stats.LastHeight = idx.lastHeight
	idx.mu.RUnlock()

	json.NewEncoder(w).Encode(stats)
}

func (idx *Indexer) handleBlocks(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0

	rows, err := idx.db.Query(`
		SELECT id, parent_id, height, timestamp, tx_count, quantum_signature, algorithm, stamp_count
		FROM qchain_blocks
		ORDER BY height DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var blocks []QuantumBlock
	for rows.Next() {
		var b QuantumBlock
		var sig, algo sql.NullString
		rows.Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.TxCount, &sig, &algo, &b.StampCount)
		if sig.Valid {
			b.QuantumSignature = sig.String
		}
		if algo.Valid {
			b.Algorithm = algo.String
		}
		blocks = append(blocks, b)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":            blocks,
		"next_page_params": nil,
	})
}

func (idx *Indexer) handleBlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	blockID := vars["id"]

	var b QuantumBlock
	var sig, algo sql.NullString
	err := idx.db.QueryRow(`
		SELECT id, parent_id, height, timestamp, tx_count, quantum_signature, algorithm, stamp_count
		FROM qchain_blocks WHERE id = $1
	`, blockID).Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.TxCount, &sig, &algo, &b.StampCount)
	if err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}
	if sig.Valid {
		b.QuantumSignature = sig.String
	}
	if algo.Valid {
		b.Algorithm = algo.String
	}

	json.NewEncoder(w).Encode(b)
}

func (idx *Indexer) handleTransactions(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0

	rows, err := idx.db.Query(`
		SELECT id, type, block_id, block_height, timestamp, quantum_signature, payload
		FROM qchain_transactions
		ORDER BY timestamp DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var txs []QuantumTransaction
	for rows.Next() {
		var tx QuantumTransaction
		var sig sql.NullString
		rows.Scan(&tx.ID, &tx.Type, &tx.BlockID, &tx.BlockHeight, &tx.Timestamp, &sig, &tx.Payload)
		if sig.Valid {
			tx.QuantumSignature = sig.String
		}
		txs = append(txs, tx)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":            txs,
		"next_page_params": nil,
	})
}

func (idx *Indexer) handleTransaction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	txID := vars["id"]

	var tx QuantumTransaction
	var sig sql.NullString
	err := idx.db.QueryRow(`
		SELECT id, type, block_id, block_height, timestamp, quantum_signature, payload
		FROM qchain_transactions WHERE id = $1
	`, txID).Scan(&tx.ID, &tx.Type, &tx.BlockID, &tx.BlockHeight, &tx.Timestamp, &sig, &tx.Payload)
	if err != nil {
		http.Error(w, "Transaction not found", http.StatusNotFound)
		return
	}
	if sig.Valid {
		tx.QuantumSignature = sig.String
	}

	json.NewEncoder(w).Encode(tx)
}

func (idx *Indexer) handleStamps(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0
	mode := r.URL.Query().Get("mode") // Filter by stamp mode

	query := `
		SELECT id, cchain_block_hash, cchain_block_num, qchain_block_hash, qchain_block_num,
		       stamp_mode, signature, public_key, timestamp, verified
		FROM qchain_stamps
	`
	args := []interface{}{limit, offset}

	if mode != "" {
		query += " WHERE stamp_mode = $3"
		args = append(args, mode)
	}
	query += " ORDER BY timestamp DESC LIMIT $1 OFFSET $2"

	rows, err := idx.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var stamps []QuantumStamp
	for rows.Next() {
		var s QuantumStamp
		var pubKey sql.NullString
		rows.Scan(&s.ID, &s.CChainBlockHash, &s.CChainBlockNum, &s.QChainBlockHash,
			&s.QChainBlockNum, &s.StampMode, &s.Signature, &pubKey, &s.Timestamp, &s.Verified)
		if pubKey.Valid {
			s.PublicKey = pubKey.String
		}
		stamps = append(stamps, s)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":            stamps,
		"next_page_params": nil,
	})
}

func (idx *Indexer) handleStamp(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stampID := vars["id"]

	var s QuantumStamp
	var pubKey sql.NullString
	err := idx.db.QueryRow(`
		SELECT id, cchain_block_hash, cchain_block_num, qchain_block_hash, qchain_block_num,
		       stamp_mode, signature, public_key, timestamp, verified
		FROM qchain_stamps WHERE id = $1
	`, stampID).Scan(&s.ID, &s.CChainBlockHash, &s.CChainBlockNum, &s.QChainBlockHash,
		&s.QChainBlockNum, &s.StampMode, &s.Signature, &pubKey, &s.Timestamp, &s.Verified)
	if err != nil {
		http.Error(w, "Stamp not found", http.StatusNotFound)
		return
	}
	if pubKey.Valid {
		s.PublicKey = pubKey.String
	}

	json.NewEncoder(w).Encode(s)
}

func (idx *Indexer) handleStampByCChainBlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	blockNum := vars["blockNum"]

	var s QuantumStamp
	var pubKey sql.NullString
	err := idx.db.QueryRow(`
		SELECT id, cchain_block_hash, cchain_block_num, qchain_block_hash, qchain_block_num,
		       stamp_mode, signature, public_key, timestamp, verified
		FROM qchain_stamps WHERE cchain_block_num = $1
		ORDER BY timestamp DESC LIMIT 1
	`, blockNum).Scan(&s.ID, &s.CChainBlockHash, &s.CChainBlockNum, &s.QChainBlockHash,
		&s.QChainBlockNum, &s.StampMode, &s.Signature, &pubKey, &s.Timestamp, &s.Verified)
	if err != nil {
		http.Error(w, "Stamp not found for block", http.StatusNotFound)
		return
	}
	if pubKey.Valid {
		s.PublicKey = pubKey.String
	}

	json.NewEncoder(w).Encode(s)
}

func (idx *Indexer) handleFinalityStatus(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT chain_id, chain_name, last_stamped_block, last_stamp_time, total_stamps, verified_stamps
		FROM qchain_finality_status
		ORDER BY chain_name
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var statuses []FinalityStatus
	for rows.Next() {
		var s FinalityStatus
		var lastStampTime sql.NullTime
		rows.Scan(&s.ChainID, &s.ChainName, &s.LastStampedBlock, &lastStampTime, &s.TotalStamps, &s.VerifiedStamps)
		if lastStampTime.Valid {
			s.LastStampTime = lastStampTime.Time
		}
		statuses = append(statuses, s)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items": statuses,
	})
}

func (idx *Indexer) handleChainFinality(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	chainID := vars["chainId"]

	var s FinalityStatus
	var lastStampTime sql.NullTime
	err := idx.db.QueryRow(`
		SELECT chain_id, chain_name, last_stamped_block, last_stamp_time, total_stamps, verified_stamps
		FROM qchain_finality_status WHERE chain_id = $1
	`, chainID).Scan(&s.ChainID, &s.ChainName, &s.LastStampedBlock, &lastStampTime, &s.TotalStamps, &s.VerifiedStamps)
	if err != nil {
		http.Error(w, "Chain not found", http.StatusNotFound)
		return
	}
	if lastStampTime.Valid {
		s.LastStampTime = lastStampTime.Time
	}

	json.NewEncoder(w).Encode(s)
}

func (idx *Indexer) handleRingtailKeys(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, public_key, version, key_size, owner, created_at
		FROM qchain_ringtail_keys
		ORDER BY created_at DESC
		LIMIT 50
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var keys []RingtailKey
	for rows.Next() {
		var k RingtailKey
		var owner sql.NullString
		rows.Scan(&k.ID, &k.PublicKey, &k.Version, &k.KeySize, &owner, &k.CreatedAt)
		if owner.Valid {
			k.Owner = owner.String
		}
		keys = append(keys, k)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items": keys,
	})
}

func (idx *Indexer) handleRingtailKey(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	keyID := vars["id"]

	var k RingtailKey
	var owner sql.NullString
	err := idx.db.QueryRow(`
		SELECT id, public_key, version, key_size, owner, created_at
		FROM qchain_ringtail_keys WHERE id = $1
	`, keyID).Scan(&k.ID, &k.PublicKey, &k.Version, &k.KeySize, &owner, &k.CreatedAt)
	if err != nil {
		http.Error(w, "Key not found", http.StatusNotFound)
		return
	}
	if owner.Valid {
		k.Owner = owner.String
	}

	json.NewEncoder(w).Encode(k)
}

// Run starts the indexer
func (idx *Indexer) Run(ctx context.Context) error {
	// Initialize database
	if err := idx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}

	// Get last indexed height from DB
	var lastHeight sql.NullInt64
	idx.db.QueryRow("SELECT MAX(height) FROM qchain_blocks").Scan(&lastHeight)
	if lastHeight.Valid {
		idx.lastHeight = uint64(lastHeight.Int64)
	}

	// Start HTTP server in background
	go idx.StartHTTPServer(ctx)

	// Start indexing loop
	ticker := time.NewTicker(idx.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
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
		HTTPPort:     4300,
		PollInterval: 10 * time.Second,
	}

	// Parse flags
	flag.StringVar(&cfg.RPCEndpoint, "rpc", cfg.RPCEndpoint, "Q-Chain RPC endpoint")
	flag.StringVar(&cfg.DatabaseURL, "db", cfg.DatabaseURL, "PostgreSQL connection string")
	flag.IntVar(&cfg.HTTPPort, "port", cfg.HTTPPort, "HTTP API port")
	flag.Parse()

	if cfg.RPCEndpoint == "" {
		cfg.RPCEndpoint = "http://localhost:9630/ext/bc/Q"
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://blockscout:blockscout@localhost:5432/explorer_qchain?sslmode=disable"
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

	log.Printf("Starting Q-Chain indexer...")
	log.Printf("RPC Endpoint: %s", cfg.RPCEndpoint)
	log.Printf("Database: %s", cfg.DatabaseURL)

	if err := indexer.Run(ctx); err != nil {
		log.Fatalf("Indexer error: %v", err)
	}
}
