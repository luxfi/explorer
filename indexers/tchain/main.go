// T-Chain Explorer Indexer
// Lightweight indexer for LUX Teleport Chain (cross-chain messages, warp signatures, transfers)
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

// TeleportMessage represents a cross-chain teleport message
type TeleportMessage struct {
	ID            string    `json:"id"`
	Version       uint8     `json:"version"`
	Type          string    `json:"type"` // transfer, swap, lock, unlock, attest, governance, private
	SourceChain   string    `json:"sourceChain"`
	DestChain     string    `json:"destChain"`
	Nonce         uint64    `json:"nonce"`
	Encrypted     bool      `json:"encrypted"`
	Status        string    `json:"status"` // pending, signed, delivered, failed
	Signatures    int       `json:"signatures"`
	SignatureType string    `json:"signatureType"` // BLS, Ringtail, Hybrid
	CreatedAt     time.Time `json:"createdAt"`
	DeliveredAt   time.Time `json:"deliveredAt,omitempty"`
	PayloadSize   int       `json:"payloadSize"`
}

// Transfer represents a cross-chain transfer via Teleport
type Transfer struct {
	ID          string    `json:"id"`
	MessageID   string    `json:"messageId"`
	Asset       string    `json:"asset"`
	Amount      string    `json:"amount"`
	Sender      string    `json:"sender"`
	Recipient   string    `json:"recipient"`
	SourceChain string    `json:"sourceChain"`
	DestChain   string    `json:"destChain"`
	Fee         string    `json:"fee"`
	Status      string    `json:"status"`
	TxHash      string    `json:"txHash,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
}

// Attestation represents an oracle/attestation message
type Attestation struct {
	ID              string    `json:"id"`
	MessageID       string    `json:"messageId"`
	AttestationType string    `json:"attestationType"` // price, compute, oracle
	AttesterID      string    `json:"attesterId"`
	Data            string    `json:"data,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	Verified        bool      `json:"verified"`
}

// Block represents a T-Chain block
type Block struct {
	ID           string    `json:"id"`
	ParentID     string    `json:"parentId"`
	Height       uint64    `json:"height"`
	Timestamp    time.Time `json:"timestamp"`
	MessageCount int       `json:"messageCount"`
}

// ChainStats represents statistics for a specific chain
type ChainStats struct {
	ChainID       string `json:"chainId"`
	MessagesIn    int64  `json:"messagesIn"`
	MessagesOut   int64  `json:"messagesOut"`
	TotalVolume   string `json:"totalVolume"`
	LastMessageAt string `json:"lastMessageAt,omitempty"`
}

// Indexer handles T-Chain indexing
type Indexer struct {
	config     Config
	db         *sql.DB
	httpClient *http.Client
	mu         sync.RWMutex
	lastHeight uint64
}

// NewIndexer creates a new T-Chain indexer
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
		CREATE TABLE IF NOT EXISTS tchain_blocks (
			id TEXT PRIMARY KEY,
			parent_id TEXT,
			height BIGINT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL,
			message_count INT DEFAULT 0,
			raw_data JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_tchain_blocks_height ON tchain_blocks(height);

		CREATE TABLE IF NOT EXISTS tchain_messages (
			id TEXT PRIMARY KEY,
			version SMALLINT DEFAULT 1,
			type TEXT NOT NULL,
			source_chain TEXT NOT NULL,
			dest_chain TEXT NOT NULL,
			nonce BIGINT NOT NULL,
			encrypted BOOLEAN DEFAULT false,
			status TEXT DEFAULT 'pending',
			signatures INT DEFAULT 0,
			signature_type TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			delivered_at TIMESTAMPTZ,
			payload_size INT DEFAULT 0,
			payload_hash TEXT,
			raw_data JSONB
		);
		CREATE INDEX IF NOT EXISTS idx_tchain_messages_status ON tchain_messages(status);
		CREATE INDEX IF NOT EXISTS idx_tchain_messages_source ON tchain_messages(source_chain);
		CREATE INDEX IF NOT EXISTS idx_tchain_messages_dest ON tchain_messages(dest_chain);
		CREATE INDEX IF NOT EXISTS idx_tchain_messages_type ON tchain_messages(type);

		CREATE TABLE IF NOT EXISTS tchain_transfers (
			id TEXT PRIMARY KEY,
			message_id TEXT REFERENCES tchain_messages(id),
			asset TEXT NOT NULL,
			amount NUMERIC NOT NULL,
			sender TEXT NOT NULL,
			recipient TEXT NOT NULL,
			source_chain TEXT NOT NULL,
			dest_chain TEXT NOT NULL,
			fee NUMERIC,
			status TEXT DEFAULT 'pending',
			tx_hash TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_tchain_transfers_sender ON tchain_transfers(sender);
		CREATE INDEX IF NOT EXISTS idx_tchain_transfers_recipient ON tchain_transfers(recipient);
		CREATE INDEX IF NOT EXISTS idx_tchain_transfers_status ON tchain_transfers(status);

		CREATE TABLE IF NOT EXISTS tchain_attestations (
			id TEXT PRIMARY KEY,
			message_id TEXT REFERENCES tchain_messages(id),
			attestation_type TEXT NOT NULL,
			attester_id TEXT NOT NULL,
			data TEXT,
			timestamp TIMESTAMPTZ NOT NULL,
			verified BOOLEAN DEFAULT false,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_tchain_attestations_type ON tchain_attestations(attestation_type);
		CREATE INDEX IF NOT EXISTS idx_tchain_attestations_attester ON tchain_attestations(attester_id);

		CREATE TABLE IF NOT EXISTS tchain_chain_stats (
			chain_id TEXT PRIMARY KEY,
			messages_in BIGINT DEFAULT 0,
			messages_out BIGINT DEFAULT 0,
			total_volume NUMERIC DEFAULT 0,
			last_message_at TIMESTAMPTZ,
			updated_at TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS tchain_warp_signatures (
			id SERIAL PRIMARY KEY,
			message_id TEXT REFERENCES tchain_messages(id),
			signer_id TEXT NOT NULL,
			signature_type TEXT NOT NULL,
			signature TEXT NOT NULL,
			quantum_safe BOOLEAN DEFAULT false,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_tchain_sigs_message ON tchain_warp_signatures(message_id);
	`

	_, err := idx.db.Exec(schema)
	return err
}

// RPCCall makes a JSON-RPC call to the T-Chain
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
	return n, nil
}

// FetchPendingMessages fetches pending teleport messages
func (idx *Indexer) FetchPendingMessages(ctx context.Context) error {
	result, err := idx.RPCCall("tvm.getPendingMessages", map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to get pending messages: %w", err)
	}

	var response struct {
		Messages []struct {
			ID            string `json:"id"`
			Version       uint8  `json:"version"`
			Type          string `json:"messageType"`
			SourceChain   string `json:"sourceChainID"`
			DestChain     string `json:"destChainID"`
			Nonce         uint64 `json:"nonce"`
			Encrypted     bool   `json:"encrypted"`
			Status        string `json:"status"`
			Signatures    int    `json:"signatures"`
			SignatureType string `json:"signatureType"`
			CreatedAt     string `json:"createdAt"`
			PayloadSize   int    `json:"payloadSize"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(result, &response); err != nil {
		return fmt.Errorf("failed to parse messages: %w", err)
	}

	tx, err := idx.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, m := range response.Messages {
		createdAt, _ := time.Parse(time.RFC3339, m.CreatedAt)

		_, err := tx.ExecContext(ctx, `
			INSERT INTO tchain_messages
			(id, version, type, source_chain, dest_chain, nonce, encrypted, status, signatures, signature_type, created_at, payload_size)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (id) DO UPDATE SET
				status = EXCLUDED.status,
				signatures = EXCLUDED.signatures
		`, m.ID, m.Version, m.Type, m.SourceChain, m.DestChain, m.Nonce, m.Encrypted, m.Status, m.Signatures, m.SignatureType, createdAt, m.PayloadSize)
		if err != nil {
			return fmt.Errorf("failed to upsert message: %w", err)
		}

		// Update chain stats
		_, err = tx.ExecContext(ctx, `
			INSERT INTO tchain_chain_stats (chain_id, messages_out, last_message_at, updated_at)
			VALUES ($1, 1, $2, NOW())
			ON CONFLICT (chain_id) DO UPDATE SET
				messages_out = tchain_chain_stats.messages_out + 1,
				last_message_at = EXCLUDED.last_message_at,
				updated_at = NOW()
		`, m.SourceChain, createdAt)
		if err != nil {
			log.Printf("Failed to update source chain stats: %v", err)
		}

		_, err = tx.ExecContext(ctx, `
			INSERT INTO tchain_chain_stats (chain_id, messages_in, last_message_at, updated_at)
			VALUES ($1, 1, $2, NOW())
			ON CONFLICT (chain_id) DO UPDATE SET
				messages_in = tchain_chain_stats.messages_in + 1,
				last_message_at = EXCLUDED.last_message_at,
				updated_at = NOW()
		`, m.DestChain, createdAt)
		if err != nil {
			log.Printf("Failed to update dest chain stats: %v", err)
		}
	}

	return tx.Commit()
}

// StartHTTPServer starts the REST API server
func (idx *Indexer) StartHTTPServer(ctx context.Context) error {
	r := mux.NewRouter()

	api := r.PathPrefix("/api/v2").Subrouter()

	api.HandleFunc("/stats", idx.handleStats).Methods("GET")
	api.HandleFunc("/blocks", idx.handleBlocks).Methods("GET")
	api.HandleFunc("/blocks/{id}", idx.handleBlock).Methods("GET")
	api.HandleFunc("/messages", idx.handleMessages).Methods("GET")
	api.HandleFunc("/messages/{id}", idx.handleMessage).Methods("GET")
	api.HandleFunc("/messages/pending", idx.handlePendingMessages).Methods("GET")
	api.HandleFunc("/transfers", idx.handleTransfers).Methods("GET")
	api.HandleFunc("/transfers/{id}", idx.handleTransfer).Methods("GET")
	api.HandleFunc("/attestations", idx.handleAttestations).Methods("GET")
	api.HandleFunc("/chains", idx.handleChainStats).Methods("GET")
	api.HandleFunc("/chains/{chainId}", idx.handleChainStat).Methods("GET")

	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "chain": "T-Chain"})
	}).Methods("GET")

	handler := corsMiddleware(r)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", idx.config.HTTPPort),
		Handler: handler,
	}

	go func() {
		<-ctx.Done()
		server.Shutdown(context.Background())
	}()

	log.Printf("T-Chain indexer API listening on port %d", idx.config.HTTPPort)
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
		TotalBlocks       int64  `json:"total_blocks"`
		TotalMessages     int64  `json:"total_messages"`
		PendingMessages   int64  `json:"pending_messages"`
		DeliveredMessages int64  `json:"delivered_messages"`
		TotalTransfers    int64  `json:"total_transfers"`
		TotalAttestations int64  `json:"total_attestations"`
		EncryptedMessages int64  `json:"encrypted_messages"`
		QuantumSafeCount  int64  `json:"quantum_safe_count"`
		ConnectedChains   int64  `json:"connected_chains"`
		LastHeight        uint64 `json:"last_height"`
	}

	idx.db.QueryRow("SELECT COUNT(*) FROM tchain_blocks").Scan(&stats.TotalBlocks)
	idx.db.QueryRow("SELECT COUNT(*) FROM tchain_messages").Scan(&stats.TotalMessages)
	idx.db.QueryRow("SELECT COUNT(*) FROM tchain_messages WHERE status = 'pending'").Scan(&stats.PendingMessages)
	idx.db.QueryRow("SELECT COUNT(*) FROM tchain_messages WHERE status = 'delivered'").Scan(&stats.DeliveredMessages)
	idx.db.QueryRow("SELECT COUNT(*) FROM tchain_transfers").Scan(&stats.TotalTransfers)
	idx.db.QueryRow("SELECT COUNT(*) FROM tchain_attestations").Scan(&stats.TotalAttestations)
	idx.db.QueryRow("SELECT COUNT(*) FROM tchain_messages WHERE encrypted = true").Scan(&stats.EncryptedMessages)
	idx.db.QueryRow("SELECT COUNT(*) FROM tchain_warp_signatures WHERE quantum_safe = true").Scan(&stats.QuantumSafeCount)
	idx.db.QueryRow("SELECT COUNT(*) FROM tchain_chain_stats").Scan(&stats.ConnectedChains)

	idx.mu.RLock()
	stats.LastHeight = idx.lastHeight
	idx.mu.RUnlock()

	json.NewEncoder(w).Encode(stats)
}

func (idx *Indexer) handleBlocks(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, parent_id, height, timestamp, message_count
		FROM tchain_blocks ORDER BY height DESC LIMIT 50
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var blocks []Block
	for rows.Next() {
		var b Block
		rows.Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.MessageCount)
		blocks = append(blocks, b)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": blocks})
}

func (idx *Indexer) handleBlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var b Block
	err := idx.db.QueryRow(`
		SELECT id, parent_id, height, timestamp, message_count
		FROM tchain_blocks WHERE id = $1
	`, vars["id"]).Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.MessageCount)
	if err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(b)
}

func (idx *Indexer) handleMessages(w http.ResponseWriter, r *http.Request) {
	msgType := r.URL.Query().Get("type")
	status := r.URL.Query().Get("status")
	chain := r.URL.Query().Get("chain")

	query := `SELECT id, version, type, source_chain, dest_chain, nonce, encrypted, status,
		signatures, signature_type, created_at, delivered_at, payload_size
		FROM tchain_messages WHERE 1=1`
	args := []interface{}{}
	argNum := 1

	if msgType != "" {
		query += fmt.Sprintf(" AND type = $%d", argNum)
		args = append(args, msgType)
		argNum++
	}
	if status != "" {
		query += fmt.Sprintf(" AND status = $%d", argNum)
		args = append(args, status)
		argNum++
	}
	if chain != "" {
		query += fmt.Sprintf(" AND (source_chain = $%d OR dest_chain = $%d)", argNum, argNum)
		args = append(args, chain)
	}
	query += " ORDER BY created_at DESC LIMIT 50"

	rows, err := idx.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []TeleportMessage
	for rows.Next() {
		var m TeleportMessage
		var deliveredAt sql.NullTime
		rows.Scan(&m.ID, &m.Version, &m.Type, &m.SourceChain, &m.DestChain, &m.Nonce, &m.Encrypted,
			&m.Status, &m.Signatures, &m.SignatureType, &m.CreatedAt, &deliveredAt, &m.PayloadSize)
		if deliveredAt.Valid {
			m.DeliveredAt = deliveredAt.Time
		}
		messages = append(messages, m)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": messages})
}

func (idx *Indexer) handleMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var m TeleportMessage
	var deliveredAt sql.NullTime

	err := idx.db.QueryRow(`
		SELECT id, version, type, source_chain, dest_chain, nonce, encrypted, status,
			signatures, signature_type, created_at, delivered_at, payload_size
		FROM tchain_messages WHERE id = $1
	`, vars["id"]).Scan(&m.ID, &m.Version, &m.Type, &m.SourceChain, &m.DestChain, &m.Nonce, &m.Encrypted,
		&m.Status, &m.Signatures, &m.SignatureType, &m.CreatedAt, &deliveredAt, &m.PayloadSize)
	if err != nil {
		http.Error(w, "Message not found", http.StatusNotFound)
		return
	}
	if deliveredAt.Valid {
		m.DeliveredAt = deliveredAt.Time
	}

	json.NewEncoder(w).Encode(m)
}

func (idx *Indexer) handlePendingMessages(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, version, type, source_chain, dest_chain, nonce, encrypted, status,
			signatures, signature_type, created_at, payload_size
		FROM tchain_messages WHERE status = 'pending' ORDER BY created_at ASC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var messages []TeleportMessage
	for rows.Next() {
		var m TeleportMessage
		rows.Scan(&m.ID, &m.Version, &m.Type, &m.SourceChain, &m.DestChain, &m.Nonce, &m.Encrypted,
			&m.Status, &m.Signatures, &m.SignatureType, &m.CreatedAt, &m.PayloadSize)
		messages = append(messages, m)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": messages})
}

func (idx *Indexer) handleTransfers(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, message_id, asset, amount, sender, recipient, source_chain, dest_chain, fee, status, tx_hash, created_at
		FROM tchain_transfers ORDER BY created_at DESC LIMIT 50
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var transfers []Transfer
	for rows.Next() {
		var t Transfer
		var txHash sql.NullString
		rows.Scan(&t.ID, &t.MessageID, &t.Asset, &t.Amount, &t.Sender, &t.Recipient,
			&t.SourceChain, &t.DestChain, &t.Fee, &t.Status, &txHash, &t.CreatedAt)
		if txHash.Valid {
			t.TxHash = txHash.String
		}
		transfers = append(transfers, t)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": transfers})
}

func (idx *Indexer) handleTransfer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var t Transfer
	var txHash sql.NullString

	err := idx.db.QueryRow(`
		SELECT id, message_id, asset, amount, sender, recipient, source_chain, dest_chain, fee, status, tx_hash, created_at
		FROM tchain_transfers WHERE id = $1
	`, vars["id"]).Scan(&t.ID, &t.MessageID, &t.Asset, &t.Amount, &t.Sender, &t.Recipient,
		&t.SourceChain, &t.DestChain, &t.Fee, &t.Status, &txHash, &t.CreatedAt)
	if err != nil {
		http.Error(w, "Transfer not found", http.StatusNotFound)
		return
	}
	if txHash.Valid {
		t.TxHash = txHash.String
	}

	json.NewEncoder(w).Encode(t)
}

func (idx *Indexer) handleAttestations(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, message_id, attestation_type, attester_id, timestamp, verified
		FROM tchain_attestations ORDER BY timestamp DESC LIMIT 50
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var attestations []Attestation
	for rows.Next() {
		var a Attestation
		rows.Scan(&a.ID, &a.MessageID, &a.AttestationType, &a.AttesterID, &a.Timestamp, &a.Verified)
		attestations = append(attestations, a)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": attestations})
}

func (idx *Indexer) handleChainStats(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT chain_id, messages_in, messages_out, total_volume, last_message_at
		FROM tchain_chain_stats ORDER BY (messages_in + messages_out) DESC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var stats []ChainStats
	for rows.Next() {
		var s ChainStats
		var lastMessage sql.NullTime
		rows.Scan(&s.ChainID, &s.MessagesIn, &s.MessagesOut, &s.TotalVolume, &lastMessage)
		if lastMessage.Valid {
			s.LastMessageAt = lastMessage.Time.Format(time.RFC3339)
		}
		stats = append(stats, s)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": stats})
}

func (idx *Indexer) handleChainStat(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var s ChainStats
	var lastMessage sql.NullTime

	err := idx.db.QueryRow(`
		SELECT chain_id, messages_in, messages_out, total_volume, last_message_at
		FROM tchain_chain_stats WHERE chain_id = $1
	`, vars["chainId"]).Scan(&s.ChainID, &s.MessagesIn, &s.MessagesOut, &s.TotalVolume, &lastMessage)
	if err != nil {
		http.Error(w, "Chain not found", http.StatusNotFound)
		return
	}
	if lastMessage.Valid {
		s.LastMessageAt = lastMessage.Time.Format(time.RFC3339)
	}

	json.NewEncoder(w).Encode(s)
}

// Run starts the indexer
func (idx *Indexer) Run(ctx context.Context) error {
	if err := idx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}

	var lastHeight sql.NullInt64
	idx.db.QueryRow("SELECT MAX(height) FROM tchain_blocks").Scan(&lastHeight)
	if lastHeight.Valid {
		idx.lastHeight = uint64(lastHeight.Int64)
	}

	go idx.StartHTTPServer(ctx)

	ticker := time.NewTicker(idx.config.PollInterval)
	defer ticker.Stop()

	// Initial fetch
	idx.FetchPendingMessages(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := idx.FetchPendingMessages(ctx); err != nil {
				log.Printf("Error fetching messages: %v", err)
			}
		}
	}
}

func main() {
	cfg := Config{
		RPCEndpoint:  os.Getenv("RPC_ENDPOINT"),
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		HTTPPort:     4700,
		PollInterval: 10 * time.Second,
	}

	flag.StringVar(&cfg.RPCEndpoint, "rpc", cfg.RPCEndpoint, "T-Chain RPC endpoint")
	flag.StringVar(&cfg.DatabaseURL, "db", cfg.DatabaseURL, "PostgreSQL connection string")
	flag.IntVar(&cfg.HTTPPort, "port", cfg.HTTPPort, "HTTP API port")
	flag.Parse()

	if cfg.RPCEndpoint == "" {
		cfg.RPCEndpoint = "http://localhost:9630/ext/bc/T"
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://blockscout:blockscout@localhost:5432/explorer_tchain?sslmode=disable"
	}

	indexer, err := NewIndexer(cfg)
	if err != nil {
		log.Fatalf("Failed to create indexer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	log.Printf("Starting T-Chain (Teleport) indexer...")
	log.Printf("RPC Endpoint: %s", cfg.RPCEndpoint)
	log.Printf("Database: %s", cfg.DatabaseURL)

	if err := indexer.Run(ctx); err != nil {
		log.Fatalf("Indexer error: %v", err)
	}
}
