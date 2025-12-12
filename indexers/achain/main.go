// A-Chain Explorer Indexer
// Lightweight indexer for LUX AI Chain (providers, tasks, attestations, rewards)
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

// Provider represents an AI compute provider
type Provider struct {
	ID             string    `json:"id"`
	WalletAddress  string    `json:"walletAddress"`
	Endpoint       string    `json:"endpoint"`
	Status         string    `json:"status"`
	TrustScore     uint8     `json:"trustScore"`
	GPUCount       int       `json:"gpuCount"`
	GPUModels      []string  `json:"gpuModels,omitempty"`
	TotalTasks     int64     `json:"totalTasks"`
	TotalRewards   string    `json:"totalRewards"`
	RegisteredAt   time.Time `json:"registeredAt"`
	LastSeen       time.Time `json:"lastSeen"`
	HasAttestation bool      `json:"hasAttestation"`
}

// Task represents an AI compute task
type Task struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Model       string    `json:"model"`
	Status      string    `json:"status"`
	Requester   string    `json:"requester"`
	ProviderID  string    `json:"providerId,omitempty"`
	Fee         string    `json:"fee"`
	CreatedAt   time.Time `json:"createdAt"`
	CompletedAt time.Time `json:"completedAt,omitempty"`
	ResultHash  string    `json:"resultHash,omitempty"`
}

// Attestation represents a TEE/GPU attestation
type Attestation struct {
	ID           string    `json:"id"`
	ProviderID   string    `json:"providerId"`
	Type         string    `json:"type"` // TEE, GPU, Hybrid
	TrustScore   uint8     `json:"trustScore"`
	Platform     string    `json:"platform"` // SGX, SEV-SNP, TDX, nvtrust
	Quote        string    `json:"quote,omitempty"`
	Verified     bool      `json:"verified"`
	VerifiedAt   time.Time `json:"verifiedAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

// Block represents an A-Chain block
type Block struct {
	ID         string    `json:"id"`
	ParentID   string    `json:"parentId"`
	Height     uint64    `json:"height"`
	Timestamp  time.Time `json:"timestamp"`
	TaskCount  int       `json:"taskCount"`
	MerkleRoot string    `json:"merkleRoot"`
}

// RewardStats represents provider reward statistics
type RewardStats struct {
	ProviderID     string `json:"providerId"`
	TotalRewards   string `json:"totalRewards"`
	PendingRewards string `json:"pendingRewards"`
	ClaimedRewards string `json:"claimedRewards"`
	TasksCompleted int64  `json:"tasksCompleted"`
	EpochRewards   string `json:"epochRewards"`
}

// Indexer handles A-Chain indexing
type Indexer struct {
	config     Config
	db         *sql.DB
	httpClient *http.Client
	mu         sync.RWMutex
	lastHeight uint64
}

// NewIndexer creates a new A-Chain indexer
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
		CREATE TABLE IF NOT EXISTS achain_blocks (
			id TEXT PRIMARY KEY,
			parent_id TEXT,
			height BIGINT NOT NULL,
			timestamp TIMESTAMPTZ NOT NULL,
			task_count INT DEFAULT 0,
			merkle_root TEXT,
			raw_data JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_achain_blocks_height ON achain_blocks(height);

		CREATE TABLE IF NOT EXISTS achain_providers (
			id TEXT PRIMARY KEY,
			wallet_address TEXT NOT NULL,
			endpoint TEXT,
			status TEXT DEFAULT 'active',
			trust_score SMALLINT DEFAULT 0,
			gpu_count INT DEFAULT 0,
			gpu_models JSONB,
			total_tasks BIGINT DEFAULT 0,
			total_rewards NUMERIC DEFAULT 0,
			registered_at TIMESTAMPTZ DEFAULT NOW(),
			last_seen TIMESTAMPTZ DEFAULT NOW(),
			has_attestation BOOLEAN DEFAULT false,
			raw_data JSONB
		);
		CREATE INDEX IF NOT EXISTS idx_achain_providers_status ON achain_providers(status);
		CREATE INDEX IF NOT EXISTS idx_achain_providers_trust ON achain_providers(trust_score DESC);

		CREATE TABLE IF NOT EXISTS achain_tasks (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			model TEXT,
			status TEXT DEFAULT 'pending',
			requester TEXT NOT NULL,
			provider_id TEXT REFERENCES achain_providers(id),
			fee NUMERIC,
			created_at TIMESTAMPTZ DEFAULT NOW(),
			completed_at TIMESTAMPTZ,
			result_hash TEXT,
			input_hash TEXT,
			raw_data JSONB
		);
		CREATE INDEX IF NOT EXISTS idx_achain_tasks_status ON achain_tasks(status);
		CREATE INDEX IF NOT EXISTS idx_achain_tasks_provider ON achain_tasks(provider_id);
		CREATE INDEX IF NOT EXISTS idx_achain_tasks_requester ON achain_tasks(requester);

		CREATE TABLE IF NOT EXISTS achain_attestations (
			id TEXT PRIMARY KEY,
			provider_id TEXT REFERENCES achain_providers(id),
			type TEXT NOT NULL,
			trust_score SMALLINT DEFAULT 0,
			platform TEXT,
			quote TEXT,
			verified BOOLEAN DEFAULT false,
			verified_at TIMESTAMPTZ,
			expires_at TIMESTAMPTZ,
			raw_data JSONB,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_achain_attestations_provider ON achain_attestations(provider_id);

		CREATE TABLE IF NOT EXISTS achain_rewards (
			id SERIAL PRIMARY KEY,
			provider_id TEXT REFERENCES achain_providers(id),
			amount NUMERIC NOT NULL,
			epoch BIGINT,
			task_id TEXT,
			claimed BOOLEAN DEFAULT false,
			claimed_at TIMESTAMPTZ,
			tx_hash TEXT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
		CREATE INDEX IF NOT EXISTS idx_achain_rewards_provider ON achain_rewards(provider_id);
		CREATE INDEX IF NOT EXISTS idx_achain_rewards_claimed ON achain_rewards(claimed);

		CREATE TABLE IF NOT EXISTS achain_models (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			type TEXT,
			provider_count INT DEFAULT 0,
			total_tasks BIGINT DEFAULT 0,
			avg_latency_ms INT,
			created_at TIMESTAMPTZ DEFAULT NOW()
		);
	`

	_, err := idx.db.Exec(schema)
	return err
}

// HTTPCall makes an HTTP call to A-Chain service endpoints
func (idx *Indexer) HTTPCall(path string) (json.RawMessage, error) {
	resp, err := idx.httpClient.Get(idx.config.RPCEndpoint + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// FetchProviders fetches and stores providers
func (idx *Indexer) FetchProviders(ctx context.Context) error {
	result, err := idx.HTTPCall("/providers")
	if err != nil {
		return fmt.Errorf("failed to get providers: %w", err)
	}

	var response struct {
		Providers []struct {
			ID             string   `json:"id"`
			WalletAddress  string   `json:"wallet_address"`
			Endpoint       string   `json:"endpoint"`
			GPUs           []struct {
				Model string `json:"model"`
			} `json:"gpus"`
			GPUAttestation interface{} `json:"gpu_attestation"`
		} `json:"providers"`
	}

	if err := json.Unmarshal(result, &response); err != nil {
		return fmt.Errorf("failed to parse providers: %w", err)
	}

	tx, err := idx.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, p := range response.Providers {
		gpuModels := make([]string, 0)
		for _, gpu := range p.GPUs {
			gpuModels = append(gpuModels, gpu.Model)
		}
		gpuJSON, _ := json.Marshal(gpuModels)
		hasAttestation := p.GPUAttestation != nil

		_, err := tx.ExecContext(ctx, `
			INSERT INTO achain_providers
			(id, wallet_address, endpoint, gpu_count, gpu_models, has_attestation, last_seen)
			VALUES ($1, $2, $3, $4, $5, $6, NOW())
			ON CONFLICT (id) DO UPDATE SET
				wallet_address = EXCLUDED.wallet_address,
				endpoint = EXCLUDED.endpoint,
				gpu_count = EXCLUDED.gpu_count,
				gpu_models = EXCLUDED.gpu_models,
				has_attestation = EXCLUDED.has_attestation,
				last_seen = NOW()
		`, p.ID, p.WalletAddress, p.Endpoint, len(p.GPUs), gpuJSON, hasAttestation)
		if err != nil {
			return fmt.Errorf("failed to upsert provider: %w", err)
		}
	}

	return tx.Commit()
}

// FetchStats fetches chain statistics
func (idx *Indexer) FetchStats(ctx context.Context) (map[string]interface{}, error) {
	result, err := idx.HTTPCall("/stats")
	if err != nil {
		return nil, err
	}

	var stats map[string]interface{}
	if err := json.Unmarshal(result, &stats); err != nil {
		return nil, err
	}
	return stats, nil
}

// StartHTTPServer starts the REST API server
func (idx *Indexer) StartHTTPServer(ctx context.Context) error {
	r := mux.NewRouter()

	// API v2 compatible endpoints
	api := r.PathPrefix("/api/v2").Subrouter()

	api.HandleFunc("/stats", idx.handleStats).Methods("GET")
	api.HandleFunc("/blocks", idx.handleBlocks).Methods("GET")
	api.HandleFunc("/blocks/{id}", idx.handleBlock).Methods("GET")
	api.HandleFunc("/providers", idx.handleProviders).Methods("GET")
	api.HandleFunc("/providers/{id}", idx.handleProvider).Methods("GET")
	api.HandleFunc("/providers/{id}/attestations", idx.handleProviderAttestations).Methods("GET")
	api.HandleFunc("/providers/{id}/rewards", idx.handleProviderRewards).Methods("GET")
	api.HandleFunc("/tasks", idx.handleTasks).Methods("GET")
	api.HandleFunc("/tasks/{id}", idx.handleTask).Methods("GET")
	api.HandleFunc("/attestations", idx.handleAttestations).Methods("GET")
	api.HandleFunc("/models", idx.handleModels).Methods("GET")

	// Health check
	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "chain": "A-Chain"})
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

	log.Printf("A-Chain indexer API listening on port %d", idx.config.HTTPPort)
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
		TotalProviders   int64  `json:"total_providers"`
		ActiveProviders  int64  `json:"active_providers"`
		TotalTasks       int64  `json:"total_tasks"`
		CompletedTasks   int64  `json:"completed_tasks"`
		TotalRewards     string `json:"total_rewards"`
		TotalModels      int64  `json:"total_models"`
		LastHeight       uint64 `json:"last_height"`
	}

	idx.db.QueryRow("SELECT COUNT(*) FROM achain_blocks").Scan(&stats.TotalBlocks)
	idx.db.QueryRow("SELECT COUNT(*) FROM achain_providers").Scan(&stats.TotalProviders)
	idx.db.QueryRow("SELECT COUNT(*) FROM achain_providers WHERE status = 'active'").Scan(&stats.ActiveProviders)
	idx.db.QueryRow("SELECT COUNT(*) FROM achain_tasks").Scan(&stats.TotalTasks)
	idx.db.QueryRow("SELECT COUNT(*) FROM achain_tasks WHERE status = 'completed'").Scan(&stats.CompletedTasks)
	idx.db.QueryRow("SELECT COALESCE(SUM(amount), 0) FROM achain_rewards").Scan(&stats.TotalRewards)
	idx.db.QueryRow("SELECT COUNT(*) FROM achain_models").Scan(&stats.TotalModels)

	idx.mu.RLock()
	stats.LastHeight = idx.lastHeight
	idx.mu.RUnlock()

	json.NewEncoder(w).Encode(stats)
}

func (idx *Indexer) handleBlocks(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, parent_id, height, timestamp, task_count, merkle_root
		FROM achain_blocks ORDER BY height DESC LIMIT 50
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var blocks []Block
	for rows.Next() {
		var b Block
		rows.Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.TaskCount, &b.MerkleRoot)
		blocks = append(blocks, b)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": blocks})
}

func (idx *Indexer) handleBlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var b Block
	err := idx.db.QueryRow(`
		SELECT id, parent_id, height, timestamp, task_count, merkle_root
		FROM achain_blocks WHERE id = $1
	`, vars["id"]).Scan(&b.ID, &b.ParentID, &b.Height, &b.Timestamp, &b.TaskCount, &b.MerkleRoot)
	if err != nil {
		http.Error(w, "Block not found", http.StatusNotFound)
		return
	}
	json.NewEncoder(w).Encode(b)
}

func (idx *Indexer) handleProviders(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, wallet_address, endpoint, status, trust_score, gpu_count,
		       total_tasks, total_rewards, registered_at, last_seen, has_attestation
		FROM achain_providers ORDER BY trust_score DESC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var providers []Provider
	for rows.Next() {
		var p Provider
		rows.Scan(&p.ID, &p.WalletAddress, &p.Endpoint, &p.Status, &p.TrustScore,
			&p.GPUCount, &p.TotalTasks, &p.TotalRewards, &p.RegisteredAt, &p.LastSeen, &p.HasAttestation)
		providers = append(providers, p)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": providers})
}

func (idx *Indexer) handleProvider(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var p Provider
	var gpuModelsJSON []byte
	err := idx.db.QueryRow(`
		SELECT id, wallet_address, endpoint, status, trust_score, gpu_count, gpu_models,
		       total_tasks, total_rewards, registered_at, last_seen, has_attestation
		FROM achain_providers WHERE id = $1
	`, vars["id"]).Scan(&p.ID, &p.WalletAddress, &p.Endpoint, &p.Status, &p.TrustScore,
		&p.GPUCount, &gpuModelsJSON, &p.TotalTasks, &p.TotalRewards, &p.RegisteredAt, &p.LastSeen, &p.HasAttestation)
	if err != nil {
		http.Error(w, "Provider not found", http.StatusNotFound)
		return
	}
	json.Unmarshal(gpuModelsJSON, &p.GPUModels)
	json.NewEncoder(w).Encode(p)
}

func (idx *Indexer) handleProviderAttestations(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	rows, err := idx.db.Query(`
		SELECT id, provider_id, type, trust_score, platform, verified, verified_at, expires_at
		FROM achain_attestations WHERE provider_id = $1 ORDER BY verified_at DESC
	`, vars["id"])
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var attestations []Attestation
	for rows.Next() {
		var a Attestation
		rows.Scan(&a.ID, &a.ProviderID, &a.Type, &a.TrustScore, &a.Platform, &a.Verified, &a.VerifiedAt, &a.ExpiresAt)
		attestations = append(attestations, a)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": attestations})
}

func (idx *Indexer) handleProviderRewards(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var stats RewardStats
	stats.ProviderID = vars["id"]

	idx.db.QueryRow(`
		SELECT COALESCE(SUM(amount), 0), COALESCE(SUM(CASE WHEN claimed THEN amount ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN NOT claimed THEN amount ELSE 0 END), 0), COUNT(DISTINCT task_id)
		FROM achain_rewards WHERE provider_id = $1
	`, vars["id"]).Scan(&stats.TotalRewards, &stats.ClaimedRewards, &stats.PendingRewards, &stats.TasksCompleted)

	json.NewEncoder(w).Encode(stats)
}

func (idx *Indexer) handleTasks(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	query := `SELECT id, type, model, status, requester, provider_id, fee, created_at, completed_at, result_hash
		FROM achain_tasks`
	args := []interface{}{}

	if status != "" {
		query += " WHERE status = $1"
		args = append(args, status)
	}
	query += " ORDER BY created_at DESC LIMIT 50"

	rows, err := idx.db.Query(query, args...)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var tasks []Task
	for rows.Next() {
		var t Task
		var completedAt sql.NullTime
		var providerID, resultHash sql.NullString
		rows.Scan(&t.ID, &t.Type, &t.Model, &t.Status, &t.Requester, &providerID, &t.Fee, &t.CreatedAt, &completedAt, &resultHash)
		if completedAt.Valid {
			t.CompletedAt = completedAt.Time
		}
		if providerID.Valid {
			t.ProviderID = providerID.String
		}
		if resultHash.Valid {
			t.ResultHash = resultHash.String
		}
		tasks = append(tasks, t)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": tasks})
}

func (idx *Indexer) handleTask(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	var t Task
	var completedAt sql.NullTime
	var providerID, resultHash sql.NullString

	err := idx.db.QueryRow(`
		SELECT id, type, model, status, requester, provider_id, fee, created_at, completed_at, result_hash
		FROM achain_tasks WHERE id = $1
	`, vars["id"]).Scan(&t.ID, &t.Type, &t.Model, &t.Status, &t.Requester, &providerID, &t.Fee, &t.CreatedAt, &completedAt, &resultHash)
	if err != nil {
		http.Error(w, "Task not found", http.StatusNotFound)
		return
	}
	if completedAt.Valid {
		t.CompletedAt = completedAt.Time
	}
	if providerID.Valid {
		t.ProviderID = providerID.String
	}
	if resultHash.Valid {
		t.ResultHash = resultHash.String
	}

	json.NewEncoder(w).Encode(t)
}

func (idx *Indexer) handleAttestations(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, provider_id, type, trust_score, platform, verified, verified_at, expires_at
		FROM achain_attestations ORDER BY verified_at DESC LIMIT 50
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var attestations []Attestation
	for rows.Next() {
		var a Attestation
		rows.Scan(&a.ID, &a.ProviderID, &a.Type, &a.TrustScore, &a.Platform, &a.Verified, &a.VerifiedAt, &a.ExpiresAt)
		attestations = append(attestations, a)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": attestations})
}

func (idx *Indexer) handleModels(w http.ResponseWriter, r *http.Request) {
	rows, err := idx.db.Query(`
		SELECT id, name, type, provider_count, total_tasks, avg_latency_ms
		FROM achain_models ORDER BY total_tasks DESC
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var models []map[string]interface{}
	for rows.Next() {
		var id, name, mtype string
		var providerCount, totalTasks int64
		var avgLatency sql.NullInt64
		rows.Scan(&id, &name, &mtype, &providerCount, &totalTasks, &avgLatency)
		models = append(models, map[string]interface{}{
			"id":            id,
			"name":          name,
			"type":          mtype,
			"providerCount": providerCount,
			"totalTasks":    totalTasks,
			"avgLatencyMs":  avgLatency.Int64,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"items": models})
}

// Run starts the indexer
func (idx *Indexer) Run(ctx context.Context) error {
	if err := idx.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize: %w", err)
	}

	var lastHeight sql.NullInt64
	idx.db.QueryRow("SELECT MAX(height) FROM achain_blocks").Scan(&lastHeight)
	if lastHeight.Valid {
		idx.lastHeight = uint64(lastHeight.Int64)
	}

	go idx.StartHTTPServer(ctx)

	ticker := time.NewTicker(idx.config.PollInterval)
	defer ticker.Stop()

	// Initial fetch
	idx.FetchProviders(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := idx.FetchProviders(ctx); err != nil {
				log.Printf("Error fetching providers: %v", err)
			}
		}
	}
}

func main() {
	cfg := Config{
		RPCEndpoint:  os.Getenv("RPC_ENDPOINT"),
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		HTTPPort:     4500,
		PollInterval: 10 * time.Second,
	}

	flag.StringVar(&cfg.RPCEndpoint, "rpc", cfg.RPCEndpoint, "A-Chain RPC endpoint")
	flag.StringVar(&cfg.DatabaseURL, "db", cfg.DatabaseURL, "PostgreSQL connection string")
	flag.IntVar(&cfg.HTTPPort, "port", cfg.HTTPPort, "HTTP API port")
	flag.Parse()

	if cfg.RPCEndpoint == "" {
		cfg.RPCEndpoint = "http://localhost:9630/ext/bc/A"
	}
	if cfg.DatabaseURL == "" {
		cfg.DatabaseURL = "postgres://blockscout:blockscout@localhost:5432/explorer_achain?sslmode=disable"
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

	log.Printf("Starting A-Chain (AI) indexer...")
	log.Printf("RPC Endpoint: %s", cfg.RPCEndpoint)
	log.Printf("Database: %s", cfg.DatabaseURL)

	if err := indexer.Run(ctx); err != nil {
		log.Fatalf("Indexer error: %v", err)
	}
}
