// B-Chain Explorer Indexer
// Lightweight indexer for LUX Bridge Chain (cross-chain bridges, MPC signers, transfers)
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

// BridgeRequest represents a cross-chain bridge request
type BridgeRequest struct {
	ID          string    `json:"id"`
	SourceChain string    `json:"sourceChain"`
	DestChain   string    `json:"destChain"`
	Asset       string    `json:"asset"`
	Amount      string    `json:"amount"`
	Sender      string    `json:"sender"`
	Recipient   string    `json:"recipient"`
	Status      string    `json:"status"` // pending, signed, completed, failed
	Fee         string    `json:"fee"`
	CreatedAt   time.Time `json:"createdAt"`
	CompletedAt time.Time `json:"completedAt,omitempty"`
	TxHash      string    `json:"txHash,omitempty"`
	Signatures  int       `json:"signatures"`
}

// Signer represents an MPC signer in the bridge
type Signer struct {
	NodeID     string    `json:"nodeId"`
	PartyID    string    `json:"partyId"`
	SlotIndex  int       `json:"slotIndex"`
	BondAmount string    `json:"bondAmount"` // 100M LUX bond (slashable)
	Active     bool      `json:"active"`
	Slashed    bool      `json:"slashed"`
	SlashCount int       `json:"slashCount"`
	MPCPubKey  string    `json:"mpcPubKey,omitempty"`
	JoinedAt   time.Time `json:"joinedAt"`
	LastSeen   time.Time `json:"lastSeen"`
}

// SignerSet represents the current MPC signer set
type SignerSet struct {
	TotalSigners   int    `json:"totalSigners"`
	Threshold      int    `json:"threshold"`
	MaxSigners     int    `json:"maxSigners"`
	CurrentEpoch   uint64 `json:"currentEpoch"`
	SetFrozen      bool   `json:"setFrozen"`
	RemainingSlots int    `json:"remainingSlots"`
	WaitlistSize   int    `json:"waitlistSize"`
	PublicKey      string `json:"publicKey,omitempty"`
}

// Block represents a B-Chain block
type Block struct {
	ID             string    `json:"id"`
	ParentID       string    `json:"parentId"`
	Height         uint64    `json:"height"`
	Timestamp      time.Time `json:"timestamp"`
	BridgeRequests int       `json:"bridgeRequests"`
}

// ChainVolume represents daily volume for a chain
type ChainVolume struct {
	Chain       string `json:"chain"`
	DailyVolume string `json:"dailyVolume"`
	TotalVolume string `json:"totalVolume"`
	TxCount     int64  `json:"txCount"`
}

// Indexer handles B-Chain indexing
type Indexer struct {
	config     Config
	db         *sql.DB
	httpClient *http.Client
	mu         sync.RWMutex
	lastHeight uint64
}

// NewIndexer creates a new B-Chain indexer
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
		CREATE TABLE IF NOT EXISTS bchain_blocks (
			id TEXT PRIMARY KEY,
			parent_id TEXT,
			height BIGINT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL,
			bridge_requests INT DEFAULT 0,
			raw_data JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_bchain_blocks_height ON bchain_blocks(height);

		CREATE TABLE IF NOT EXISTS bchain_signers (
			node_id TEXT PRIMARY KEY,
			party_id TEXT,
			slot_index INT,
			bond_amount NUMERIC NOT NULL DEFAULT 0,
			active BOOLEAN DEFAULT true,
			slashed BOOLEAN DEFAULT false,
			slash_count INT DEFAULT 0,
			mpc_pub_key TEXT,
			joined_at TIMESTAMPTZ DEFAULT NOW(),
			last_seen TIMESTAMPTZ DEFAULT NOW(),
			raw_data JSONB
		);
		CREATE INDEX IF NOT EXISTS idx_bchain_signers_active ON bchain_signers(active);
		CREATE INDEX IF NOT EXISTS idx_bchain_signers_slot ON bchain_signers(slot_index);

		CREATE TABLE IF NOT EXISTS bchain_waitlist (
			node_id TEXT PRIMARY KEY,
			position INT,
			bond_amount NUMERIC,
			added_at TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS bchain_bridge_requests (
			id TEXT PRIMARY KEY,
			source_chain TEXT NOT NULL,
			dest_chain TEXT NOT NULL,
			asset TEXT NOT NULL,
			amount NUMERIC NOT NULL,
			sender TEXT NOT NULL,
			recipient TEXT NOT NULL,
			status TEXT DEFAULT 'pending',
			fee NUMERIC,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			completed_at TIMESTAMPTZ,
			tx_hash TEXT,
			signatures INT DEFAULT 0,
			raw_data JSONB
		);
		CREATE INDEX IF NOT EXISTS idx_bchain_requests_status ON bchain_bridge_requests(status);
		CREATE INDEX IF NOT EXISTS idx_bchain_requests_source ON bchain_bridge_requests(source_chain);
		CREATE INDEX IF NOT EXISTS idx_bchain_requests_dest ON bchain_bridge_requests(dest_chain);
		CREATE INDEX IF NOT EXISTS idx_bchain_requests_sender ON bchain_bridge_requests(sender);

		CREATE TABLE IF NOT EXISTS bchain_chain_volumes (
			chain TEXT PRIMARY KEY,
			daily_volume NUMERIC DEFAULT 0,
			total_volume NUMERIC DEFAULT 0,
			tx_count BIGINT DEFAULT 0,
			last_updated TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS bchain_epochs (
			epoch BIGINT PRIMARY KEY,
			threshold INT,
			total_signers INT,
			public_key TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS bchain_slash_events (
			id SERIAL PRIMARY KEY,
			node_id TEXT REFERENCES bchain_signers(node_id),
			reason TEXT,
			amount NUMERIC,
			epoch BIGINT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
	`

	_, err := idx.db.Exec(schema)
	return err
}

// RPCCall makes a JSON-RPC call to the B-Chain
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

// FetchSignerSet fetches current signer set
func (idx *Indexer) FetchSignerSet(ctx context.Context) error {
	result, err := idx.RPCCall("bvm.getSignerSet", map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to get signer set: %w", err)
	}

	var response struct {
		TotalSigners   int    `json:"totalSigners"`
		Threshold      int    `json:"threshold"`
		MaxSigners     int    `json:"maxSigners"`
		CurrentEpoch   uint64 `json:"currentEpoch"`
		SetFrozen      bool   `json:"setFrozen"`
		RemainingSlots int    `json:"remainingSlots"`
		WaitlistSize   int    `json:"waitlistSize"`
		PublicKey      string `json:"publicKey"`
		Signers        []struct {
			NodeID     string `json:"nodeId"`
			PartyID    string `json:"partyId"`
			SlotIndex  int    `json:"slotIndex"`
			BondAmount string `json:"bondAmount"`
			Active     bool   `json:"active"`
			Slashed    bool   `json:"slashed"`
			SlashCount int    `json:"slashCount"`
			MPCPubKey  string `json:"mpcPubKey"`
			JoinedAt   string `json:"joinedAt"`
		} `json:"signers"`
	}

	if err := json.Unmarshal(result, &response); err != nil {
		return fmt.Errorf("failed to parse signer set: %w", err)
	}

	tx, err := idx.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, s := range response.Signers {
		joinedAt, _ := time.Parse(time.RFC3339, s.JoinedAt)

		_, err := tx.ExecContext(ctx, `
			INSERT INTO bchain_signers
			(node_id, party_id, slot_index, bond_amount, active, slashed, slash_count, mpc_pub_key, joined_at, last_seen)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
			ON CONFLICT (node_id) DO UPDATE SET
				party_id = EXCLUDED.party_id,
				slot_index = EXCLUDED.slot_index,
				bond_amount = EXCLUDED.bond_amount,
				active = EXCLUDED.active,
				slashed = EXCLUDED.slashed,
				slash_count = EXCLUDED.slash_count,
				mpc_pub_key = EXCLUDED.mpc_pub_key,
				last_seen = NOW()
		`, s.NodeID, s.PartyID, s.SlotIndex, s.BondAmount, s.Active, s.Slashed, s.SlashCount, s.MPCPubKey, joinedAt)
		if err != nil {
			return fmt.Errorf("failed to upsert signer: %w", err)
		}
	}

	// Store epoch info
	_, err = tx.ExecContext(ctx, `
		INSERT INTO bchain_epochs (epoch, threshold, total_signers, public_key)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (epoch) DO UPDATE SET
			threshold = EXCLUDED.threshold,
			total_signers = EXCLUDED.total_signers,
			public_key = EXCLUDED.public_key
	`, response.CurrentEpoch, response.Threshold, response.TotalSigners, response.PublicKey)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// FetchPendingBridges fetches pending bridge requests
func (idx *Indexer) FetchPendingBridges(ctx context.Context) error {
	result, err := idx.RPCCall("bvm.getPendingBridges", map[string]interface{}{})
	if err != nil {
		return fmt.Errorf("failed to get pending bridges: %w", err)
	}

	var response struct {
		Bridges []struct {
			ID          string `json:"id"`
			SourceChain string `json:"sourceChain"`
			DestChain   string `json:"destChain"`
			Asset       string `json:"asset"`
			Amount      string `json:"amount"`
			Sender      string `json:"sender"`
			Recipient   string `json:"recipient"`
			Status      string `json:"status"`
			Fee         string `json:"fee"`
			CreatedAt   string `json:"createdAt"`
			Signatures  int    `json:"signatures"`
		} `json:"bridges"`
	}

	if err := json.Unmarshal(result, &response); err != nil {
		return fmt.Errorf("failed to parse bridges: %w", err)
	}

	tx, err := idx.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, b := range response.Bridges {
		createdAt, _ := time.Parse(time.RFC3339, b.CreatedAt)

		_, err := tx.ExecContext(ctx, `
			INSERT INTO bchain_bridge_requests
			(id, source_chain, dest_chain, asset, amount, sender, recipient, status, fee, created_at, signatures)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (id) DO UPDATE SET
				status = EXCLUDED.status,
				signatures = EXCLUDED.signatures
		`, b.ID, b.SourceChain, b.DestChain, b.Asset, b.Amount, b.Sender, b.Recipient, b.Status, b.Fee, createdAt, b.Signatures)
		if err != nil {
			return fmt.Errorf("failed to upsert bridge: %w", err)
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
	api.HandleFunc("/signers", idx.handleSigners).Methods("GET")
	api.HandleFunc("/signers/{nodeId}", idx.handleSigner).Methods("GET")
	api.HandleFunc("/signer-set", idx.handleSignerSet).Methods("GET")
	api.HandleFunc("/bridges", idx.handleBridges).Methods("GET")
	api.HandleFunc("/bridges/{id}", idx.handleBridge).Methods("GET")
	api.HandleFunc("/bridges/pending", idx.handlePendingBridges).Methods("GET")
	api.HandleFunc("/volumes", idx.handleVolumes).Methods("GET")
	api.HandleFunc("/epochs", idx.handleEpochs).Methods("GET")

	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "chain": "B-Chain"})
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

	log.Printf("B-Chain indexer API listening on port %d", idx.config.HTTPPort)
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
		TotalBlocks      int64  `json:"total_blocks"`
		TotalSigners     int64  `json:"total_signers"`
		ActiveSigners    int64  `json:"active_signers"`
		TotalBridges     int64  `json:"total_bridges"`
		PendingBridges   int64  `json:"pending_bridges"`
		CompletedBridges int64  `json:"completed_bridges"`
		TotalVolume      string `json:"total_volume"`
		CurrentThreshold int    `json:"current_threshold"`
		CurrentEpoch     uint64 `json:"current_epoch"`
		LastHeight       uint64 `json:"last_height"`
	}

	idx.db.QueryRow("SELECT COUNT(*) FROM bchain_blocks").Scan(&stats.TotalBlocks)
	idx.db.QueryRow("SELECT COUNT(*) FROM bchain_signers").Scan(&stats.TotalSigners)
	idx.db.QueryRow("SELECT COUNT(*) FROM bchain_signers WHERE active = true").Scan(&stats.ActiveSigners)
	idx.db.QueryRow("SELECT COUNT(*) FROM bchain_bridge_requests").Scan(&stats.TotalBridges)
	idx.db.QueryRow("SELECT COUNT(*) FROM bchain_bridge_requests WHERE status = 'pending'").Scan(&stats.PendingBridges)
	idx.db.QueryRow("SELECT COUNT(*) FROM bchain_bridge_requests WHERE status = 'completed'").Scan(&stats.CompletedBridges)
	idx.db.QueryRow("SELECT COALESCE(SUM(total_volume), 0) FROM bchain_chain_volumes").Scan(&stats.TotalVolume)
	idx.db.QueryRow("SELECT threshold, epoch FROM bchain_epochs ORDER BY epoch DESC LIMIT 1").Scan(&stats.CurrentThreshold, &stats.CurrentEpoch)

	idx.mu.RLock()
	stats.LastHeight = idx.lastHeight
	idx.mu.RUnlock()

	json.NewEncoder(w).Encode(stats)
}

func (idx *Indexer) handleBlocks(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, parent_id, height, timestamp, bridge_requests
		FROM bchain_blocks ORDER BY height DESC LIMIT 50
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var blocks []Block
	for rows.Next() {
		var b Block
		rows.Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.BridgeRequests)
		blocks = append(blocks, b)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": blocks})
}

func (idx *Indexer) handleBlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var b Block
	err := idx.db.QueryRow(`
		SELECT id, parent_id, height, timestamp, bridge_requests
		FROM bchain_blocks WHERE id = $1
	`, vars["id"]).Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.BridgeRequests)
	if err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(b)
}

func (idx *Indexer) handleSigners(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT node_id, party_id, slot_index, bond_amount, active, slashed, slash_count, joined_at, last_seen
		FROM bchain_signers ORDER BY slot_index
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var signers []Signer
	for rows.Next() {
		var s Signer
		rows.Scan(&s.NodeID, &s.PartyID, &s.SlotIndex, &s.BondAmount, &s.Active, &s.Slashed, &s.SlashCount, &s.JoinedAt, &s.LastSeen)
		signers = append(signers, s)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": signers})
}

func (idx *Indexer) handleSigner(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var s Signer
	err := idx.db.QueryRow(`
		SELECT node_id, party_id, slot_index, bond_amount, active, slashed, slash_count, mpc_pub_key, joined_at, last_seen
		FROM bchain_signers WHERE node_id = $1
	`, vars["nodeId"]).Scan(&s.NodeID, &s.PartyID, &s.SlotIndex, &s.BondAmount, &s.Active, &s.Slashed, &s.SlashCount, &s.MPCPubKey, &s.JoinedAt, &s.LastSeen)
	if err != nil {
		http.Error(w, "Signer not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(s)
}

func (idx *Indexer) handleSignerSet(w http.ResponseWriter, r *http.Request) {
	var set SignerSet
	idx.db.QueryRow(`
		SELECT epoch, threshold, total_signers, public_key FROM bchain_epochs ORDER BY epoch DESC LIMIT 1
	`).Scan(&set.CurrentEpoch, &set.Threshold, &set.TotalSigners, &set.PublicKey)

	idx.db.QueryRow("SELECT COUNT(*) FROM bchain_signers WHERE active = true").Scan(&set.TotalSigners)
	idx.db.QueryRow("SELECT COUNT(*) FROM bchain_waitlist").Scan(&set.WaitlistSize)
	set.MaxSigners = 100
	set.RemainingSlots = set.MaxSigners - set.TotalSigners
	set.SetFrozen = set.TotalSigners >= set.MaxSigners

	json.NewEncoder(w).Encode(set)
}

func (idx *Indexer) handleBridges(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	chain := r.URL.Query().Get("chain")

	query := "SELECT id, source_chain, dest_chain, asset, amount, sender, recipient, status, fee, created_at, completed_at, tx_hash, signatures FROM bchain_bridge_requests WHERE 1=1"
	args := []interface{}{}
	argNum := 1

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

	var bridges []BridgeRequest
	for rows.Next() {
		var b BridgeRequest
		var completedAt sql.NullTime
		var txHash sql.NullString
		rows.Scan(&b.ID, &b.SourceChain, &b.DestChain, &b.Asset, &b.Amount, &b.Sender, &b.Recipient,
			&b.Status, &b.Fee, &b.CreatedAt, &completedAt, &txHash, &b.Signatures)
		if completedAt.Valid {
			b.CompletedAt = completedAt.Time
		}
		if txHash.Valid {
			b.TxHash = txHash.String
		}
		bridges = append(bridges, b)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": bridges})
}

func (idx *Indexer) handleBridge(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var b BridgeRequest
	var completedAt sql.NullTime
	var txHash sql.NullString

	err := idx.db.QueryRow(`
		SELECT id, source_chain, dest_chain, asset, amount, sender, recipient, status, fee, created_at, completed_at, tx_hash, signatures
		FROM bchain_bridge_requests WHERE id = $1
	`, vars["id"]).Scan(&b.ID, &b.SourceChain, &b.DestChain, &b.Asset, &b.Amount, &b.Sender, &b.Recipient,
		&b.Status, &b.Fee, &b.CreatedAt, &completedAt, &txHash, &b.Signatures)
	if err != nil {
		http.Error(w, "Bridge not found", http.StatusNotFound)
		return
	}
	if completedAt.Valid {
		b.CompletedAt = completedAt.Time
	}
	if txHash.Valid {
		b.TxHash = txHash.String
	}

	json.NewEncoder(w).Encode(b)
}

func (idx *Indexer) handlePendingBridges(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, source_chain, dest_chain, asset, amount, sender, recipient, status, fee, created_at, signatures
		FROM bchain_bridge_requests WHERE status = 'pending' ORDER BY created_at ASC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var bridges []BridgeRequest
	for rows.Next() {
		var b BridgeRequest
		rows.Scan(&b.ID, &b.SourceChain, &b.DestChain, &b.Asset, &b.Amount, &b.Sender, &b.Recipient,
			&b.Status, &b.Fee, &b.CreatedAt, &b.Signatures)
		bridges = append(bridges, b)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": bridges})
}

func (idx *Indexer) handleVolumes(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT chain, daily_volume, total_volume, tx_count FROM bchain_chain_volumes ORDER BY total_volume DESC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var volumes []ChainVolume
	for rows.Next() {
		var v ChainVolume
		rows.Scan(&v.Chain, &v.DailyVolume, &v.TotalVolume, &v.TxCount)
		volumes = append(volumes, v)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": volumes})
}

func (idx *Indexer) handleEpochs(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT epoch, threshold, total_signers, public_key, created_at FROM bchain_epochs ORDER BY epoch DESC LIMIT 50
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var epochs []map[string]interface{}
	for rows.Next() {
		var epoch uint64
		var threshold, totalSigners int
		var publicKey string
		var createdAt time.Time
		rows.Scan(&epoch, &threshold, &totalSigners, &publicKey, &createdAt)
		epochs = append(epochs, map[string]interface{}{
			"epoch":        epoch,
			"threshold":    threshold,
			"totalSigners": totalSigners,
			"publicKey":    publicKey,
			"createdAt":    createdAt,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": epochs})
}

// Run starts the indexer
func (idx *Indexer) Run(ctx context.Context) error {
	if err := idx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}

	var lastHeight sql.NullInt64
	idx.db.QueryRow("SELECT MAX(height) FROM bchain_blocks").Scan(&lastHeight)
	if lastHeight.Valid {
		idx.lastHeight = uint64(lastHeight.Int64)
	}

	go idx.StartHTTPServer(ctx)

	ticker := time.NewTicker(idx.config.PollInterval)
	defer ticker.Stop()

	// Initial fetch
	idx.FetchSignerSet(ctx)
	idx.FetchPendingBridges(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := idx.FetchSignerSet(ctx); err != nil {
				log.Printf("Error fetching signer set: %v", err)
			}
			if err := idx.FetchPendingBridges(ctx); err != nil {
				log.Printf("Error fetching bridges: %v", err)
			}
		}
	}
}

func main() {
	cfg := Config{
		RPCEndpoint:  os.Getenv("RPC_ENDPOINT"),
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		HTTPPort:     4600,
		PollInterval: 10 * time.Second,
	}

	flag.StringVar(&cfg.RPCEndpoint, "rpc", cfg.RPCEndpoint, "B-Chain RPC endpoint")
	flag.StringVar(&cfg.DatabaseURL, "db", cfg.DatabaseURL, "PostgreSQL connection string")
	flag.IntVar(&cfg.HTTPPort, "port", cfg.HTTPPort, "HTTP API port")
	flag.Parse()

	if cfg.RPCEndpoint == "" {
		cfg.RPCEndpoint = "http://localhost:9630/ext/bc/B"
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://blockscout:blockscout@localhost:5432/explorer_bchain?sslmode=disable"
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

	log.Printf("Starting B-Chain (Bridge) indexer...")
	log.Printf("RPC Endpoint: %s", cfg.RPCEndpoint)
	log.Printf("Database: %s", cfg.DatabaseURL)

	if err := indexer.Run(ctx); err != nil {
		log.Fatalf("Indexer error: %v", err)
	}
}
