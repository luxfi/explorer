// Z-Chain Explorer Indexer
// Lightweight indexer for LUX Z-Chain (Privacy - ZK proofs, shielded transfers, nullifiers)
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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

// ShieldedUTXO represents a shielded UTXO (commitment-based)
type ShieldedUTXO struct {
	Commitment    string    `json:"commitment"`
	EncryptedNote string    `json:"encryptedNote,omitempty"`
	BlockHeight   uint64    `json:"blockHeight"`
	TxID          string    `json:"txId"`
	Spent         bool      `json:"spent"`
	CreatedAt     time.Time `json:"createdAt"`
}

// Nullifier represents a spent note nullifier
type Nullifier struct {
	Nullifier   string    `json:"nullifier"`
	TxID        string    `json:"txId"`
	BlockHeight uint64    `json:"blockHeight"`
	SpentAt     time.Time `json:"spentAt"`
}

// ZKProof represents a zero-knowledge proof
type ZKProof struct {
	ID           string          `json:"id"`
	ProofType    string          `json:"proofType"` // transfer, shield, unshield
	ProofData    string          `json:"proofData,omitempty"`
	PublicInputs json.RawMessage `json:"publicInputs,omitempty"`
	Verified     bool            `json:"verified"`
	TxID         string          `json:"txId"`
	CreatedAt    time.Time       `json:"createdAt"`
}

// ShieldedTransaction represents a Z-Chain shielded transaction
type ShieldedTransaction struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"` // shield, unshield, transfer
	BlockHeight uint64          `json:"blockHeight"`
	Timestamp   time.Time       `json:"timestamp"`
	Nullifiers  []string        `json:"nullifiers,omitempty"`
	Commitments []string        `json:"commitments,omitempty"`
	ProofID     string          `json:"proofId"`
	Fee         string          `json:"fee,omitempty"`
	Raw         json.RawMessage `json:"raw,omitempty"`
}

// Block represents a Z-Chain block
type Block struct {
	ID           string    `json:"id"`
	ParentID     string    `json:"parentId"`
	Height       uint64    `json:"height"`
	Timestamp    time.Time `json:"timestamp"`
	TxCount      int       `json:"txCount"`
	NullifierCt  int       `json:"nullifierCount"`
	CommitmentCt int       `json:"commitmentCount"`
}

// ProofStats holds proof verification statistics
type ProofStats struct {
	VerifyCount int64 `json:"verifyCount"`
	CacheHits   int64 `json:"cacheHits"`
	CacheMisses int64 `json:"cacheMisses"`
	CacheSize   int64 `json:"cacheSize"`
}

// ChainStats holds Z-Chain statistics
type ChainStats struct {
	TotalBlocks       int64      `json:"total_blocks"`
	TotalTransactions int64      `json:"total_transactions"`
	TotalNullifiers   int64      `json:"total_nullifiers"`
	TotalCommitments  int64      `json:"total_commitments"`
	TotalProofs       int64      `json:"total_proofs"`
	LastBlockHeight   uint64     `json:"last_block_height"`
	ProofStats        ProofStats `json:"proof_stats"`
	LastUpdated       time.Time  `json:"last_updated"`
}

// Indexer handles Z-Chain indexing
type Indexer struct {
	config     Config
	db         *sql.DB
	httpClient *http.Client
	mu         sync.RWMutex
	lastHeight uint64
}

// NewIndexer creates a new Z-Chain indexer
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
		CREATE TABLE IF NOT EXISTS zchain_blocks (
			id TEXT PRIMARY KEY,
			parent_id TEXT,
			height BIGINT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL,
			tx_count INT DEFAULT 0,
			nullifier_count INT DEFAULT 0,
			commitment_count INT DEFAULT 0,
			raw_data JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_zchain_blocks_height ON zchain_blocks(height);

		CREATE TABLE IF NOT EXISTS zchain_transactions (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			block_height BIGINT,
			timestamp TIMESTAMPTZ NOT NULL,
			nullifiers JSONB,
			commitments JSONB,
			proof_id TEXT,
			fee NUMERIC,
			raw_data JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_zchain_transactions_type ON zchain_transactions(type);
		CREATE INDEX IF NOT EXISTS idx_zchain_transactions_height ON zchain_transactions(block_height);

		CREATE TABLE IF NOT EXISTS zchain_utxos (
			commitment TEXT PRIMARY KEY,
			encrypted_note TEXT,
			block_height BIGINT,
			tx_id TEXT,
			spent BOOLEAN DEFAULT false,
			spent_nullifier TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_zchain_utxos_spent ON zchain_utxos(spent);
		CREATE INDEX IF NOT EXISTS idx_zchain_utxos_height ON zchain_utxos(block_height);

		CREATE TABLE IF NOT EXISTS zchain_nullifiers (
			nullifier TEXT PRIMARY KEY,
			tx_id TEXT NOT NULL,
			block_height BIGINT,
			spent_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_zchain_nullifiers_height ON zchain_nullifiers(block_height);

		CREATE TABLE IF NOT EXISTS zchain_proofs (
			id TEXT PRIMARY KEY,
			proof_type TEXT NOT NULL,
			proof_data TEXT,
			public_inputs JSONB,
			verified BOOLEAN DEFAULT false,
			tx_id TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_zchain_proofs_type ON zchain_proofs(proof_type);
		CREATE INDEX IF NOT EXISTS idx_zchain_proofs_verified ON zchain_proofs(verified);

		CREATE TABLE IF NOT EXISTS zchain_stats (
			id SERIAL PRIMARY KEY,
			total_blocks BIGINT DEFAULT 0,
			total_transactions BIGINT DEFAULT 0,
			total_nullifiers BIGINT DEFAULT 0,
			total_commitments BIGINT DEFAULT 0,
			total_proofs BIGINT DEFAULT 0,
			verify_count BIGINT DEFAULT 0,
			cache_hits BIGINT DEFAULT 0,
			cache_misses BIGINT DEFAULT 0,
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);
	`

	_, err := idx.db.Exec(schema)
	return err
}

// RPCCall makes an HTTP call to the Z-Chain
func (idx *Indexer) RPCCall(endpoint string, params map[string]string) (json.RawMessage, error) {
	url := idx.config.RPCEndpoint + endpoint
	if len(params) > 0 {
		url += "?"
		for k, v := range params {
			url += k + "=" + v + "&"
		}
	}

	resp, err := idx.httpClient.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// FetchLatestBlock fetches the latest block from Z-Chain
func (idx *Indexer) FetchLatestBlock(ctx context.Context) (*Block, error) {
	result, err := idx.RPCCall("/getLatestBlock", nil)
	if err != nil {
		return nil, err
	}

	var block Block
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, err
	}

	return &block, nil
}

// FetchBlock fetches a specific block by ID
func (idx *Indexer) FetchBlock(ctx context.Context, blockID string) (*Block, error) {
	result, err := idx.RPCCall("/getBlock", map[string]string{"blockID": blockID})
	if err != nil {
		return nil, err
	}

	var block Block
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, err
	}

	return &block, nil
}

// FetchUTXOCount fetches the total UTXO count
func (idx *Indexer) FetchUTXOCount(ctx context.Context) (int64, error) {
	result, err := idx.RPCCall("/getUTXOCount", nil)
	if err != nil {
		return 0, err
	}

	var response struct {
		Count int64 `json:"count"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return 0, err
	}

	return response.Count, nil
}

// FetchProofStats fetches proof verification statistics
func (idx *Indexer) FetchProofStats(ctx context.Context) (*ProofStats, error) {
	result, err := idx.RPCCall("/getProofStats", nil)
	if err != nil {
		return nil, err
	}

	var stats ProofStats
	if err := json.Unmarshal(result, &stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

// CheckNullifierSpent checks if a nullifier has been spent
func (idx *Indexer) CheckNullifierSpent(ctx context.Context, nullifier string) (bool, error) {
	result, err := idx.RPCCall("/isNullifierSpent", map[string]string{"nullifier": nullifier})
	if err != nil {
		return false, err
	}

	var response struct {
		IsSpent bool `json:"isSpent"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return false, err
	}

	return response.IsSpent, nil
}

// FetchStatus fetches chain status
func (idx *Indexer) FetchStatus(ctx context.Context) (map[string]interface{}, error) {
	result, err := idx.RPCCall("/getStatus", nil)
	if err != nil {
		return nil, err
	}

	var status map[string]interface{}
	if err := json.Unmarshal(result, &status); err != nil {
		return nil, err
	}

	return status, nil
}

// UpdateStats updates chain statistics
func (idx *Indexer) UpdateStats(ctx context.Context) error {
	var stats ChainStats

	idx.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM zchain_blocks").Scan(&stats.TotalBlocks)
	idx.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM zchain_transactions").Scan(&stats.TotalTransactions)
	idx.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM zchain_nullifiers").Scan(&stats.TotalNullifiers)
	idx.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM zchain_utxos").Scan(&stats.TotalCommitments)
	idx.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM zchain_proofs").Scan(&stats.TotalProofs)

	// Try to get proof stats from RPC
	proofStats, err := idx.FetchProofStats(ctx)
	if err == nil {
		stats.ProofStats = *proofStats
	}

	idx.mu.RLock()
	stats.LastBlockHeight = idx.lastHeight
	idx.mu.RUnlock()

	_, err = idx.db.ExecContext(ctx, `
		INSERT INTO zchain_stats (id, total_blocks, total_transactions, total_nullifiers, total_commitments, total_proofs, verify_count, cache_hits, cache_misses, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (id) DO UPDATE SET
			total_blocks = EXCLUDED.total_blocks,
			total_transactions = EXCLUDED.total_transactions,
			total_nullifiers = EXCLUDED.total_nullifiers,
			total_commitments = EXCLUDED.total_commitments,
			total_proofs = EXCLUDED.total_proofs,
			verify_count = EXCLUDED.verify_count,
			cache_hits = EXCLUDED.cache_hits,
			cache_misses = EXCLUDED.cache_misses,
			updated_at = NOW()
	`, stats.TotalBlocks, stats.TotalTransactions, stats.TotalNullifiers, stats.TotalCommitments,
		stats.TotalProofs, stats.ProofStats.VerifyCount, stats.ProofStats.CacheHits, stats.ProofStats.CacheMisses)

	return err
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
	api.HandleFunc("/utxos", idx.handleUTXOs).Methods("GET")
	api.HandleFunc("/utxos/{commitment}", idx.handleUTXO).Methods("GET")
	api.HandleFunc("/nullifiers", idx.handleNullifiers).Methods("GET")
	api.HandleFunc("/nullifiers/{nullifier}", idx.handleNullifier).Methods("GET")
	api.HandleFunc("/nullifiers/{nullifier}/spent", idx.handleNullifierSpent).Methods("GET")
	api.HandleFunc("/proofs", idx.handleProofs).Methods("GET")
	api.HandleFunc("/proofs/{id}", idx.handleProof).Methods("GET")
	api.HandleFunc("/proofs/stats", idx.handleProofStats).Methods("GET")

	// Health check
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "chain": "Z-Chain", "type": "privacy"})
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

	log.Printf("Z-Chain indexer API listening on port %d", idx.config.HTTPPort)
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
	var stats ChainStats

	idx.db.QueryRow("SELECT COUNT(*) FROM zchain_blocks").Scan(&stats.TotalBlocks)
	idx.db.QueryRow("SELECT COUNT(*) FROM zchain_transactions").Scan(&stats.TotalTransactions)
	idx.db.QueryRow("SELECT COUNT(*) FROM zchain_nullifiers").Scan(&stats.TotalNullifiers)
	idx.db.QueryRow("SELECT COUNT(*) FROM zchain_utxos").Scan(&stats.TotalCommitments)
	idx.db.QueryRow("SELECT COUNT(*) FROM zchain_proofs").Scan(&stats.TotalProofs)

	// Try to get live proof stats
	proofStats, err := idx.FetchProofStats(context.Background())
	if err == nil {
		stats.ProofStats = *proofStats
	}

	idx.mu.RLock()
	stats.LastBlockHeight = idx.lastHeight
	idx.mu.RUnlock()
	stats.LastUpdated = time.Now()

	json.NewEncoder(w).Encode(stats)
}

func (idx *Indexer) handleBlocks(w http.ResponseWriter, r *http.Request) {
	limit := 50
	rows, err := idx.db.Query(`
		SELECT id, parent_id, height, timestamp, tx_count, nullifier_count, commitment_count
		FROM zchain_blocks ORDER BY height DESC LIMIT $1
	`, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var blocks []Block
	for rows.Next() {
		var b Block
		rows.Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.TxCount, &b.NullifierCt, &b.CommitmentCt)
		blocks = append(blocks, b)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": blocks})
}

func (idx *Indexer) handleBlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	blockID := vars["id"]

	// Try database first
	var b Block
	err := idx.db.QueryRow(`
		SELECT id, parent_id, height, timestamp, tx_count, nullifier_count, commitment_count
		FROM zchain_blocks WHERE id = $1
	`, blockID).Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.TxCount, &b.NullifierCt, &b.CommitmentCt)

	if err == nil {
		json.NewEncoder(w).Encode(b)
		return
	}

	// Try RPC
	block, err := idx.FetchBlock(context.Background(), blockID)
	if err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(block)
}

func (idx *Indexer) handleTransactions(w http.ResponseWriter, r *http.Request) {
	limit := 50
	txType := r.URL.Query().Get("type")

	var rows *sql.Rows
	var err error

	if txType != "" {
		rows, err = idx.db.Query(`
			SELECT id, type, block_height, timestamp, nullifiers, commitments, proof_id, fee
			FROM zchain_transactions WHERE type = $1 ORDER BY timestamp DESC LIMIT $2
		`, txType, limit)
	} else {
		rows, err = idx.db.Query(`
			SELECT id, type, block_height, timestamp, nullifiers, commitments, proof_id, fee
			FROM zchain_transactions ORDER BY timestamp DESC LIMIT $1
		`, limit)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var txs []ShieldedTransaction
	for rows.Next() {
		var tx ShieldedTransaction
		var nullifiers, commitments []byte
		var fee sql.NullString
		rows.Scan(&tx.ID, &tx.Type, &tx.BlockHeight, &tx.Timestamp, &nullifiers, &commitments, &tx.ProofID, &fee)
		json.Unmarshal(nullifiers, &tx.Nullifiers)
		json.Unmarshal(commitments, &tx.Commitments)
		if fee.Valid {
			tx.Fee = fee.String
		}
		txs = append(txs, tx)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": txs})
}

func (idx *Indexer) handleTransaction(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	txID := vars["id"]

	var tx ShieldedTransaction
	var nullifiers, commitments []byte
	var fee sql.NullString

	err := idx.db.QueryRow(`
		SELECT id, type, block_height, timestamp, nullifiers, commitments, proof_id, fee
		FROM zchain_transactions WHERE id = $1
	`, txID).Scan(&tx.ID, &tx.Type, &tx.BlockHeight, &tx.Timestamp, &nullifiers, &commitments, &tx.ProofID, &fee)

	if err != nil {
		// Try RPC
		result, err := idx.RPCCall("/getTransaction", map[string]string{"txID": txID})
		if err != nil {
			http.Error(w, "Transaction not found", http.StatusNotFound)
			return
		}
		w.Write(result)
		return
	}

	json.Unmarshal(nullifiers, &tx.Nullifiers)
	json.Unmarshal(commitments, &tx.Commitments)
	if fee.Valid {
		tx.Fee = fee.String
	}

	json.NewEncoder(w).Encode(tx)
}

func (idx *Indexer) handleUTXOs(w http.ResponseWriter, r *http.Request) {
	spent := r.URL.Query().Get("spent")
	limit := 50

	var rows *sql.Rows
	var err error

	if spent == "true" {
		rows, err = idx.db.Query(`SELECT commitment, block_height, tx_id, spent, created_at FROM zchain_utxos WHERE spent = true ORDER BY created_at DESC LIMIT $1`, limit)
	} else if spent == "false" {
		rows, err = idx.db.Query(`SELECT commitment, block_height, tx_id, spent, created_at FROM zchain_utxos WHERE spent = false ORDER BY created_at DESC LIMIT $1`, limit)
	} else {
		rows, err = idx.db.Query(`SELECT commitment, block_height, tx_id, spent, created_at FROM zchain_utxos ORDER BY created_at DESC LIMIT $1`, limit)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var utxos []ShieldedUTXO
	for rows.Next() {
		var u ShieldedUTXO
		rows.Scan(&u.Commitment, &u.BlockHeight, &u.TxID, &u.Spent, &u.CreatedAt)
		utxos = append(utxos, u)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": utxos})
}

func (idx *Indexer) handleUTXO(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	commitment := vars["commitment"]

	var u ShieldedUTXO
	err := idx.db.QueryRow(`
		SELECT commitment, encrypted_note, block_height, tx_id, spent, created_at
		FROM zchain_utxos WHERE commitment = $1
	`, commitment).Scan(&u.Commitment, &u.EncryptedNote, &u.BlockHeight, &u.TxID, &u.Spent, &u.CreatedAt)

	if err != nil {
		// Try RPC
		result, err := idx.RPCCall("/getUTXO", map[string]string{"commitment": commitment})
		if err != nil {
			http.Error(w, "UTXO not found", http.StatusNotFound)
			return
		}
		w.Write(result)
		return
	}

	json.NewEncoder(w).Encode(u)
}

func (idx *Indexer) handleNullifiers(w http.ResponseWriter, r *http.Request) {
	limit := 50
	rows, err := idx.db.Query(`SELECT nullifier, tx_id, block_height, spent_at FROM zchain_nullifiers ORDER BY spent_at DESC LIMIT $1`, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var nullifiers []Nullifier
	for rows.Next() {
		var n Nullifier
		rows.Scan(&n.Nullifier, &n.TxID, &n.BlockHeight, &n.SpentAt)
		nullifiers = append(nullifiers, n)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": nullifiers})
}

func (idx *Indexer) handleNullifier(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nullifier := vars["nullifier"]

	var n Nullifier
	err := idx.db.QueryRow(`
		SELECT nullifier, tx_id, block_height, spent_at FROM zchain_nullifiers WHERE nullifier = $1
	`, nullifier).Scan(&n.Nullifier, &n.TxID, &n.BlockHeight, &n.SpentAt)

	if err != nil {
		http.Error(w, "Nullifier not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(n)
}

func (idx *Indexer) handleNullifierSpent(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	nullifier := vars["nullifier"]

	// Try RPC first for live data
	isSpent, err := idx.CheckNullifierSpent(context.Background(), nullifier)
	if err == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"nullifier": nullifier,
			"isSpent":   isSpent,
		})
		return
	}

	// Fall back to database
	var exists bool
	idx.db.QueryRow(`SELECT EXISTS(SELECT 1 FROM zchain_nullifiers WHERE nullifier = $1)`, nullifier).Scan(&exists)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"nullifier": nullifier,
		"isSpent":   exists,
	})
}

func (idx *Indexer) handleProofs(w http.ResponseWriter, r *http.Request) {
	proofType := r.URL.Query().Get("type")
	limit := 50

	var rows *sql.Rows
	var err error

	if proofType != "" {
		rows, err = idx.db.Query(`SELECT id, proof_type, verified, tx_id, created_at FROM zchain_proofs WHERE proof_type = $1 ORDER BY created_at DESC LIMIT $2`, proofType, limit)
	} else {
		rows, err = idx.db.Query(`SELECT id, proof_type, verified, tx_id, created_at FROM zchain_proofs ORDER BY created_at DESC LIMIT $1`, limit)
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var proofs []ZKProof
	for rows.Next() {
		var p ZKProof
		rows.Scan(&p.ID, &p.ProofType, &p.Verified, &p.TxID, &p.CreatedAt)
		proofs = append(proofs, p)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": proofs})
}

func (idx *Indexer) handleProof(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	proofID := vars["id"]

	var p ZKProof
	var publicInputs []byte
	err := idx.db.QueryRow(`
		SELECT id, proof_type, proof_data, public_inputs, verified, tx_id, created_at
		FROM zchain_proofs WHERE id = $1
	`, proofID).Scan(&p.ID, &p.ProofType, &p.ProofData, &publicInputs, &p.Verified, &p.TxID, &p.CreatedAt)

	if err != nil {
		http.Error(w, "Proof not found", http.StatusNotFound)
		return
	}

	p.PublicInputs = publicInputs
	json.NewEncoder(w).Encode(p)
}

func (idx *Indexer) handleProofStats(w http.ResponseWriter, r *http.Request) {
	// Try RPC for live stats
	stats, err := idx.FetchProofStats(context.Background())
	if err == nil {
		json.NewEncoder(w).Encode(stats)
		return
	}

	// Fall back to database stats
	var dbStats struct {
		TotalProofs    int64 `json:"totalProofs"`
		VerifiedProofs int64 `json:"verifiedProofs"`
	}
	idx.db.QueryRow(`SELECT COUNT(*) FROM zchain_proofs`).Scan(&dbStats.TotalProofs)
	idx.db.QueryRow(`SELECT COUNT(*) FROM zchain_proofs WHERE verified = true`).Scan(&dbStats.VerifiedProofs)

	json.NewEncoder(w).Encode(dbStats)
}

// Run starts the indexer
func (idx *Indexer) Run(ctx context.Context) error {
	// Initialize database
	if err := idx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}

	// Get last indexed height from DB
	var lastHeight sql.NullInt64
	idx.db.QueryRow("SELECT MAX(height) FROM zchain_blocks").Scan(&lastHeight)
	if lastHeight.Valid {
		idx.lastHeight = uint64(lastHeight.Int64)
	}

	// Start HTTP server in background
	go idx.StartHTTPServer(ctx)

	// Start update loop
	ticker := time.NewTicker(idx.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Try to fetch latest block
			block, err := idx.FetchLatestBlock(ctx)
			if err != nil {
				log.Printf("Z-Chain not available: %v", err)
				continue
			}

			idx.mu.Lock()
			if block.Height > idx.lastHeight {
				idx.lastHeight = block.Height
				log.Printf("Z-Chain new block height: %d", block.Height)
			}
			idx.mu.Unlock()

			// Update stats
			if err := idx.UpdateStats(ctx); err != nil {
				log.Printf("Error updating stats: %v", err)
			}
		}
	}
}

func main() {
	cfg := Config{
		RPCEndpoint:  os.Getenv("RPC_ENDPOINT"),
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		HTTPPort:     4400,
		PollInterval: 30 * time.Second,
	}

	// Parse flags
	flag.StringVar(&cfg.RPCEndpoint, "rpc", cfg.RPCEndpoint, "Z-Chain RPC endpoint")
	flag.StringVar(&cfg.DatabaseURL, "db", cfg.DatabaseURL, "PostgreSQL connection string")
	flag.IntVar(&cfg.HTTPPort, "port", cfg.HTTPPort, "HTTP API port")
	flag.Parse()

	if cfg.RPCEndpoint == "" {
		cfg.RPCEndpoint = "http://localhost:9630/ext/bc/Z"
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://blockscout:blockscout@localhost:5432/explorer_zchain?sslmode=disable"
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

	log.Printf("Starting Z-Chain (Privacy) indexer...")
	log.Printf("RPC Endpoint: %s", cfg.RPCEndpoint)
	log.Printf("Features: Shielded UTXOs, Nullifiers, ZK Proofs")

	if err := indexer.Run(ctx); err != nil {
		log.Fatalf("Indexer error: %v", err)
	}
}
