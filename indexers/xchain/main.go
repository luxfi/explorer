// X-Chain Explorer Indexer
// Lightweight indexer for LUX Exchange Chain (assets, UTXOs, transfers)
// Uses DAG-based API calls (no linearization required)
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

// Asset represents an X-Chain asset
type Asset struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Symbol       string `json:"symbol"`
	Denomination uint8  `json:"denomination"`
	AssetType    string `json:"assetType"` // fixed, variable, nft
	TotalSupply  string `json:"totalSupply,omitempty"`
	MinterSets   []struct {
		Minters   []string `json:"minters"`
		Threshold uint32   `json:"threshold"`
	} `json:"minterSets,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

// UTXO represents an unspent transaction output
type UTXO struct {
	UTXOID      string    `json:"utxoId"`
	TxID        string    `json:"txId"`
	OutputIndex uint32    `json:"outputIndex"`
	AssetID     string    `json:"assetId"`
	Amount      string    `json:"amount"`
	Addresses   []string  `json:"addresses"`
	Threshold   uint32    `json:"threshold"`
	Locktime    uint64    `json:"locktime"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Transaction represents an X-Chain transaction
type Transaction struct {
	ID          string          `json:"id"`
	Type        string          `json:"type"` // base, create_asset, operation, import, export
	Timestamp   time.Time       `json:"timestamp"`
	Fee         string          `json:"fee"`
	Inputs      json.RawMessage `json:"inputs"`
	Outputs     json.RawMessage `json:"outputs"`
	Memo        string          `json:"memo,omitempty"`
	Status      string          `json:"status"`
}

// AddressBalance represents balances for an address
type AddressBalance struct {
	Address  string            `json:"address"`
	Balances map[string]string `json:"balances"` // assetID -> balance
}

// ChainStats holds X-Chain statistics
type ChainStats struct {
	TotalAssets       int64     `json:"total_assets"`
	TotalTransactions int64     `json:"total_transactions"`
	TotalUTXOs        int64     `json:"total_utxos"`
	TotalAddresses    int64     `json:"total_addresses"`
	LastUpdated       time.Time `json:"last_updated"`
	IsLinearized      bool      `json:"is_linearized"`
	ChainType         string    `json:"chain_type"`
}

// Indexer handles X-Chain indexing
type Indexer struct {
	config        Config
	db            *sql.DB
	httpClient    *http.Client
	mu            sync.RWMutex
	isLinearized  bool
	dagSubscriber *DAGSubscriber
	dagPoller     *DAGPoller
}

// NewIndexer creates a new X-Chain indexer
func NewIndexer(cfg Config) (*Indexer, error) {
	db, err := sql.Open("postgres", cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	idx := &Indexer{
		config:     cfg,
		db:         db,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}

	// Initialize DAG subscriber and poller for live streaming
	idx.dagSubscriber = NewDAGSubscriber()
	idx.dagPoller = NewDAGPoller(idx, idx.dagSubscriber)

	return idx, nil
}

// Initialize creates database tables
func (idx *Indexer) Initialize() error {
	schema := `
		CREATE TABLE IF NOT EXISTS xchain_assets (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			symbol TEXT NOT NULL,
			denomination SMALLINT DEFAULT 0,
			asset_type TEXT NOT NULL,
			total_supply NUMERIC,
			minter_sets JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_xchain_assets_symbol ON xchain_assets(symbol);

		CREATE TABLE IF NOT EXISTS xchain_transactions (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL,
			fee NUMERIC,
			memo TEXT,
			inputs JSONB,
			outputs JSONB,
			status TEXT DEFAULT 'accepted',
			raw_data JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_xchain_transactions_type ON xchain_transactions(type);
		CREATE INDEX IF NOT EXISTS idx_xchain_transactions_timestamp ON xchain_transactions(timestamp DESC);

		CREATE TABLE IF NOT EXISTS xchain_utxos (
			utxo_id TEXT PRIMARY KEY,
			tx_id TEXT NOT NULL,
			output_index INT NOT NULL,
			asset_id TEXT REFERENCES xchain_assets(id),
			amount NUMERIC NOT NULL,
			addresses JSONB,
			threshold INT DEFAULT 1,
			locktime BIGINT DEFAULT 0,
			spent BOOLEAN DEFAULT false,
			spent_tx_id TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_xchain_utxos_asset ON xchain_utxos(asset_id);
		CREATE INDEX IF NOT EXISTS idx_xchain_utxos_addresses ON xchain_utxos USING GIN(addresses);
		CREATE INDEX IF NOT EXISTS idx_xchain_utxos_unspent ON xchain_utxos(spent) WHERE NOT spent;

		CREATE TABLE IF NOT EXISTS xchain_address_balances (
			address TEXT NOT NULL,
			asset_id TEXT NOT NULL,
			balance NUMERIC DEFAULT 0,
			utxo_count INT DEFAULT 0,
			updated_at TIMESTAMPTZ DEFAULT NOW(),
			PRIMARY KEY (address, asset_id)
		);
		CREATE INDEX IF NOT EXISTS idx_xchain_address_balances_address ON xchain_address_balances(address);

		CREATE TABLE IF NOT EXISTS xchain_stats (
			id SERIAL PRIMARY KEY,
			total_assets INT DEFAULT 0,
			total_transactions BIGINT DEFAULT 0,
			total_utxos INT DEFAULT 0,
			total_addresses INT DEFAULT 0,
			is_linearized BOOLEAN DEFAULT false,
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);
	`

	_, err := idx.db.Exec(schema)
	return err
}

// RPCCall makes a JSON-RPC call to the X-Chain
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

// CheckLinearization checks if the chain is linearized
func (idx *Indexer) CheckLinearization() bool {
	_, err := idx.RPCCall("xvm.getHeight", map[string]interface{}{})
	isLinearized := err == nil
	idx.mu.Lock()
	idx.isLinearized = isLinearized
	idx.mu.Unlock()
	return isLinearized
}

// FetchAssetDescription fetches and stores asset info
func (idx *Indexer) FetchAssetDescription(ctx context.Context, assetID string) (*Asset, error) {
	result, err := idx.RPCCall("xvm.getAssetDescription", map[string]interface{}{
		"assetID": assetID,
	})
	if err != nil {
		return nil, err
	}

	var response struct {
		Name         string `json:"name"`
		Symbol       string `json:"symbol"`
		Denomination string `json:"denomination"`
		AssetID      string `json:"assetID"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return nil, err
	}

	asset := &Asset{
		ID:        response.AssetID,
		Name:      response.Name,
		Symbol:    response.Symbol,
		AssetType: "fixed",
		CreatedAt: time.Now(),
	}
	fmt.Sscanf(response.Denomination, "%d", &asset.Denomination)

	// Store in database
	_, err = idx.db.ExecContext(ctx, `
		INSERT INTO xchain_assets (id, name, symbol, denomination, asset_type)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (id) DO UPDATE SET
			name = EXCLUDED.name,
			symbol = EXCLUDED.symbol,
			denomination = EXCLUDED.denomination,
			updated_at = NOW()
	`, asset.ID, asset.Name, asset.Symbol, asset.Denomination, asset.AssetType)

	return asset, err
}

// FetchLUXAsset ensures the LUX native asset is indexed
func (idx *Indexer) FetchLUXAsset(ctx context.Context) error {
	_, err := idx.FetchAssetDescription(ctx, "LUX")
	return err
}

// FetchTxFee fetches current transaction fees
func (idx *Indexer) FetchTxFee(ctx context.Context) (uint64, uint64, error) {
	result, err := idx.RPCCall("xvm.getTxFee", map[string]interface{}{})
	if err != nil {
		return 0, 0, err
	}

	var response struct {
		TxFee        string `json:"txFee"`
		CreationTxFee string `json:"creationTxFee"`
	}
	if err := json.Unmarshal(result, &response); err != nil {
		return 0, 0, err
	}

	var txFee, creationFee uint64
	fmt.Sscanf(response.TxFee, "%d", &txFee)
	fmt.Sscanf(response.CreationTxFee, "%d", &creationFee)

	return txFee, creationFee, nil
}

// UpdateStats updates chain statistics
func (idx *Indexer) UpdateStats(ctx context.Context) error {
	var stats ChainStats

	idx.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM xchain_assets").Scan(&stats.TotalAssets)
	idx.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM xchain_transactions").Scan(&stats.TotalTransactions)
	idx.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM xchain_utxos WHERE NOT spent").Scan(&stats.TotalUTXOs)
	idx.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT address) FROM xchain_address_balances").Scan(&stats.TotalAddresses)

	idx.mu.RLock()
	stats.IsLinearized = idx.isLinearized
	idx.mu.RUnlock()

	_, err := idx.db.ExecContext(ctx, `
		INSERT INTO xchain_stats (id, total_assets, total_transactions, total_utxos, total_addresses, is_linearized, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, NOW())
		ON CONFLICT (id) DO UPDATE SET
			total_assets = EXCLUDED.total_assets,
			total_transactions = EXCLUDED.total_transactions,
			total_utxos = EXCLUDED.total_utxos,
			total_addresses = EXCLUDED.total_addresses,
			is_linearized = EXCLUDED.is_linearized,
			updated_at = NOW()
	`, stats.TotalAssets, stats.TotalTransactions, stats.TotalUTXOs, stats.TotalAddresses, stats.IsLinearized)

	return err
}

// StartHTTPServer starts the REST API server
func (idx *Indexer) StartHTTPServer(ctx context.Context) error {
	r := mux.NewRouter()

	// API v2 compatible endpoints (like Blockscout)
	api := r.PathPrefix("/api/v2").Subrouter()

	api.HandleFunc("/stats", idx.handleStats).Methods("GET")
	api.HandleFunc("/transactions", idx.handleTransactions).Methods("GET")
	api.HandleFunc("/transactions/{id}", idx.handleTransaction).Methods("GET")
	api.HandleFunc("/assets", idx.handleAssets).Methods("GET")
	api.HandleFunc("/assets/{id}", idx.handleAsset).Methods("GET")
	api.HandleFunc("/addresses/{address}/utxos", idx.handleAddressUTXOs).Methods("GET")
	api.HandleFunc("/addresses/{address}/balances", idx.handleAddressBalances).Methods("GET")
	api.HandleFunc("/addresses/{address}/transactions", idx.handleAddressTransactions).Methods("GET")
	api.HandleFunc("/fees", idx.handleFees).Methods("GET")

	// DAG WebSocket endpoint for live streaming
	api.HandleFunc("/dag/subscribe", idx.dagSubscriber.HandleWebSocket)

	// Health check
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "chain": "X-Chain", "type": "DAG"})
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

	log.Printf("X-Chain indexer API listening on port %d", idx.config.HTTPPort)
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

	idx.db.QueryRow("SELECT COUNT(*) FROM xchain_assets").Scan(&stats.TotalAssets)
	idx.db.QueryRow("SELECT COUNT(*) FROM xchain_transactions").Scan(&stats.TotalTransactions)
	idx.db.QueryRow("SELECT COUNT(*) FROM xchain_utxos WHERE NOT spent").Scan(&stats.TotalUTXOs)
	idx.db.QueryRow("SELECT COUNT(DISTINCT address) FROM xchain_address_balances").Scan(&stats.TotalAddresses)

	idx.mu.RLock()
	stats.IsLinearized = idx.isLinearized
	idx.mu.RUnlock()
	stats.ChainType = "DAG"
	stats.LastUpdated = time.Now()

	json.NewEncoder(w).Encode(stats)
}

func (idx *Indexer) handleTransactions(w http.ResponseWriter, r *http.Request) {
	limit := 50
	offset := 0

	rows, err := idx.db.Query(`
		SELECT id, type, timestamp, fee, memo, inputs, outputs, status
		FROM xchain_transactions
		ORDER BY timestamp DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var txs []Transaction
	for rows.Next() {
		var tx Transaction
		var memo sql.NullString
		var fee sql.NullString
		rows.Scan(&tx.ID, &tx.Type, &tx.Timestamp, &fee, &memo, &tx.Inputs, &tx.Outputs, &tx.Status)
		if memo.Valid {
			tx.Memo = memo.String
		}
		if fee.Valid {
			tx.Fee = fee.String
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

	// First try from database
	var tx Transaction
	var memo sql.NullString
	var fee sql.NullString
	err := idx.db.QueryRow(`
		SELECT id, type, timestamp, fee, memo, inputs, outputs, status
		FROM xchain_transactions WHERE id = $1
	`, txID).Scan(&tx.ID, &tx.Type, &tx.Timestamp, &fee, &memo, &tx.Inputs, &tx.Outputs, &tx.Status)

	if err == nil {
		if memo.Valid {
			tx.Memo = memo.String
		}
		if fee.Valid {
			tx.Fee = fee.String
		}
		json.NewEncoder(w).Encode(tx)
		return
	}

	// Try to fetch from RPC
	result, err := idx.RPCCall("xvm.getTx", map[string]interface{}{
		"txID":     txID,
		"encoding": "json",
	})
	if err != nil {
		http.Error(w, "Transaction not found", http.StatusNotFound)
		return
	}

	var txData map[string]interface{}
	json.Unmarshal(result, &txData)
	json.NewEncoder(w).Encode(txData)
}

func (idx *Indexer) handleAssets(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, name, symbol, denomination, asset_type, total_supply, created_at
		FROM xchain_assets
		ORDER BY created_at DESC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var assets []Asset
	for rows.Next() {
		var a Asset
		var totalSupply sql.NullString
		rows.Scan(&a.ID, &a.Name, &a.Symbol, &a.Denomination, &a.AssetType, &totalSupply, &a.CreatedAt)
		if totalSupply.Valid {
			a.TotalSupply = totalSupply.String
		}
		assets = append(assets, a)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items": assets,
	})
}

func (idx *Indexer) handleAsset(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	assetID := vars["id"]

	var a Asset
	var totalSupply sql.NullString
	err := idx.db.QueryRow(`
		SELECT id, name, symbol, denomination, asset_type, total_supply, created_at
		FROM xchain_assets WHERE id = $1
	`, assetID).Scan(&a.ID, &a.Name, &a.Symbol, &a.Denomination, &a.AssetType, &totalSupply, &a.CreatedAt)
	if err != nil {
		// Try to fetch from RPC
		asset, err := idx.FetchAssetDescription(context.Background(), assetID)
		if err != nil {
			http.Error(w, "Asset not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(asset)
		return
	}
	if totalSupply.Valid {
		a.TotalSupply = totalSupply.String
	}

	json.NewEncoder(w).Encode(a)
}

func (idx *Indexer) handleAddressUTXOs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	address := vars["address"]

	// First try from database
	rows, err := idx.db.Query(`
		SELECT utxo_id, tx_id, output_index, asset_id, amount, addresses, threshold, locktime, created_at
		FROM xchain_utxos
		WHERE addresses @> $1 AND NOT spent
		ORDER BY created_at DESC
	`, fmt.Sprintf(`["%s"]`, address))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var utxos []UTXO
	for rows.Next() {
		var u UTXO
		var addrs []byte
		rows.Scan(&u.UTXOID, &u.TxID, &u.OutputIndex, &u.AssetID, &u.Amount,
			&addrs, &u.Threshold, &u.Locktime, &u.CreatedAt)
		json.Unmarshal(addrs, &u.Addresses)
		utxos = append(utxos, u)
	}

	// If no local UTXOs, try RPC
	if len(utxos) == 0 {
		result, err := idx.RPCCall("xvm.getUTXOs", map[string]interface{}{
			"addresses": []string{address},
		})
		if err == nil {
			var response struct {
				UTXOs []string `json:"utxos"`
			}
			json.Unmarshal(result, &response)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"items":      response.UTXOs,
				"raw_format": true,
			})
			return
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items": utxos,
	})
}

func (idx *Indexer) handleAddressBalances(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	address := vars["address"]

	// First try from database
	rows, err := idx.db.Query(`
		SELECT asset_id, balance, utxo_count
		FROM xchain_address_balances
		WHERE address = $1
	`, address)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	balances := make(map[string]string)
	for rows.Next() {
		var assetID, balance string
		var utxoCount int
		rows.Scan(&assetID, &balance, &utxoCount)
		balances[assetID] = balance
	}

	// If no local balances, try RPC
	if len(balances) == 0 {
		result, err := idx.RPCCall("xvm.getAllBalances", map[string]interface{}{
			"address": address,
		})
		if err == nil {
			var response struct {
				Balances []struct {
					Asset   string `json:"asset"`
					Balance string `json:"balance"`
				} `json:"balances"`
			}
			json.Unmarshal(result, &response)
			for _, b := range response.Balances {
				balances[b.Asset] = b.Balance
			}
		}
	}

	json.NewEncoder(w).Encode(AddressBalance{
		Address:  address,
		Balances: balances,
	})
}

func (idx *Indexer) handleAddressTransactions(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	address := vars["address"]

	// Try RPC to get transaction IDs for address
	result, err := idx.RPCCall("xvm.getAddressTxs", map[string]interface{}{
		"address":  address,
		"pageSize": 50,
	})
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"items": []string{},
			"error": "Could not fetch transactions for address",
		})
		return
	}

	var response struct {
		TxIDs  []string `json:"txIDs"`
		Cursor uint64   `json:"cursor"`
	}
	json.Unmarshal(result, &response)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":  response.TxIDs,
		"cursor": response.Cursor,
	})
}

func (idx *Indexer) handleFees(w http.ResponseWriter, r *http.Request) {
	txFee, creationFee, err := idx.FetchTxFee(context.Background())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"tx_fee":       txFee,
		"creation_fee": creationFee,
	})
}

// Run starts the indexer
func (idx *Indexer) Run(ctx context.Context) error {
	// Initialize database
	if err := idx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}

	// Check if chain is linearized
	idx.CheckLinearization()
	log.Printf("X-Chain linearization status: %v", idx.isLinearized)

	// Fetch LUX asset info
	if err := idx.FetchLUXAsset(ctx); err != nil {
		log.Printf("Warning: Could not fetch LUX asset: %v", err)
	}

	// Start DAG WebSocket subscriber for live streaming
	go idx.dagSubscriber.Run(ctx)
	log.Printf("DAG WebSocket streaming enabled at /api/v2/dag/subscribe")

	// Start DAG poller for live updates
	go idx.dagPoller.Run(ctx)
	log.Printf("DAG poller started for live transaction streaming")

	// Start HTTP server in background
	go idx.StartHTTPServer(ctx)

	// Start stats update loop
	ticker := time.NewTicker(idx.config.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Check linearization status periodically
			idx.CheckLinearization()

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
		HTTPPort:     4200,
		PollInterval: 30 * time.Second,
	}

	// Parse flags
	flag.StringVar(&cfg.RPCEndpoint, "rpc", cfg.RPCEndpoint, "X-Chain RPC endpoint")
	flag.StringVar(&cfg.DatabaseURL, "db", cfg.DatabaseURL, "PostgreSQL connection string")
	flag.IntVar(&cfg.HTTPPort, "port", cfg.HTTPPort, "HTTP API port")
	flag.Parse()

	if cfg.RPCEndpoint == "" {
		cfg.RPCEndpoint = "http://localhost:9630/ext/bc/X"
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://blockscout:blockscout@localhost:5432/explorer_xchain?sslmode=disable"
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

	log.Printf("Starting X-Chain (Exchange) indexer...")
	log.Printf("RPC Endpoint: %s", cfg.RPCEndpoint)
	log.Printf("Chain Type: DAG (Directed Acyclic Graph)")

	if err := indexer.Run(ctx); err != nil {
		log.Fatalf("Indexer error: %v", err)
	}
}
