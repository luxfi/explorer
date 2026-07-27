package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// StatsService serves the Blockscout stats-microservice API surface
// (/v1/counters, /v1/lines, /v1/lines/{id}, /v1/pages/*) for the default chain,
// backed directly by the live indexer SQLite DB.
//
// The Next.js explorer turns on config.features.stats when
// NEXT_PUBLIC_STATS_API_HOST is set (it points at this backend). Its /stats page
// then requests /v1/counters and /v1/lines; without them it shows two error
// banners ("Something went wrong" + "Some of the charts did not load because the
// server didn't respond"). The indexer's own /v1/indexer/{slug}/stats endpoint
// is a different shape and its chart endpoints are empty stubs, so we serve real
// aggregates here, computed from evm_blocks / evm_transactions / evm_addresses.
type StatsService struct {
	dbPath string
	mu     sync.Mutex
	db     *sql.DB
}

// NewStatsService targets the default chain's indexer DB
// ({dataDir}/{slug}/query/indexer.db).
func NewStatsService(dbPath string) *StatsService {
	return &StatsService{dbPath: dbPath}
}

// conn lazily opens a read-only handle. The indexer writes in WAL mode, so a
// read-only reader never blocks ingestion. The DB may not exist until the
// indexer has created it, so open is retried per-request until it succeeds.
func (s *StatsService) conn() (*sql.DB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db != nil {
		return s.db, nil
	}
	db, err := sql.Open("sqlite3", "file:"+s.dbPath+"?mode=ro&_busy_timeout=3000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	s.db = db
	return db, nil
}

// Mount registers the stats-service routes on mux.
func (s *StatsService) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/counters", s.handleCounters)
	mux.HandleFunc("GET /v1/lines", s.handleLines)
	mux.HandleFunc("GET /v1/lines/{id}", s.handleLine)
	mux.HandleFunc("GET /v1/pages/main", s.handlePagesMain)
	mux.HandleFunc("GET /v1/pages/transactions", s.handlePagesTransactions)
	mux.HandleFunc("GET /v1/pages/contracts", s.handlePagesContracts)
}

// ---- Wire shapes (match @luxfi/stats-types) ----

type statsCounter struct {
	ID          string `json:"id"`
	Value       string `json:"value"`
	Title       string `json:"title"`
	Units       string `json:"units,omitempty"`
	Description string `json:"description"`
}

type statsPoint struct {
	Date          string `json:"date"`
	DateTo        string `json:"date_to"`
	Value         string `json:"value"`
	IsApproximate bool   `json:"is_approximate"`
}

type statsLineInfo struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Units       string   `json:"units,omitempty"`
	Resolutions []string `json:"resolutions"`
}

type statsLineChart struct {
	Chart []statsPoint  `json:"chart"`
	Info  statsLineInfo `json:"info"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ---- Aggregate helpers ----

func (s *StatsService) count(db *sql.DB, table string) int64 {
	var n int64
	// #nosec G201 — table is a fixed internal identifier, never user input.
	db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
	return n
}

// avgBlockTimeSec returns the lifetime average block interval in seconds,
// derived from the full timestamp span so it stays meaningful on a sparse,
// demand-driven chain (per-window deltas collapse to zero when idle).
func (s *StatsService) avgBlockTimeSec(db *sql.DB) float64 {
	var count, minTS, maxTS int64
	db.QueryRow("SELECT COUNT(*), COALESCE(MIN(timestamp),0), COALESCE(MAX(timestamp),0) FROM evm_blocks").
		Scan(&count, &minTS, &maxTS)
	if count < 2 || maxTS <= minTS {
		return 0
	}
	return float64(maxTS-minTS) / float64(count-1)
}

// dailySeries buckets a COUNT by UTC day over the trailing `days` window.
// timestamp is a unix-epoch integer, so strftime needs the 'unixepoch' modifier.
func (s *StatsService) dailySeries(db *sql.DB, query string, days int) ([]statsPoint, error) {
	since := time.Now().AddDate(0, 0, -days).Unix()
	rows, err := db.Query(query, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	points := make([]statsPoint, 0, days)
	for rows.Next() {
		var day string
		var value int64
		if err := rows.Scan(&day, &value); err != nil {
			return nil, err
		}
		points = append(points, statsPoint{Date: day, DateTo: day, Value: fmt.Sprintf("%d", value)})
	}
	return points, rows.Err()
}

// ---- Handlers ----

func (s *StatsService) handleCounters(w http.ResponseWriter, r *http.Request) {
	db, err := s.conn()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"counters": []statsCounter{}})
		return
	}
	blocks := s.count(db, "evm_blocks")
	txns := s.count(db, "evm_transactions")
	addrs := s.count(db, "evm_addresses")
	avgSec := s.avgBlockTimeSec(db)

	counters := []statsCounter{
		{ID: "total_blocks", Value: fmt.Sprintf("%d", blocks), Title: "Total blocks", Description: "All blocks indexed on the chain"},
		{ID: "total_txns", Value: fmt.Sprintf("%d", txns), Title: "Total transactions", Description: "All transactions indexed on the chain"},
		{ID: "completed_txns", Value: fmt.Sprintf("%d", txns), Title: "Completed transactions", Description: "Transactions included in a block"},
		{ID: "total_addresses", Value: fmt.Sprintf("%d", addrs), Title: "Total addresses", Description: "Distinct addresses seen on the chain"},
		{ID: "average_block_time", Value: fmt.Sprintf("%.1f", avgSec), Title: "Average block time", Units: "s", Description: "Average interval between blocks"},
	}
	writeJSON(w, http.StatusOK, map[string]any{"counters": counters})
}

// lineInfos is the catalogue of charts this backend can serve, each backed by a
// real SQLite aggregation.
var lineInfos = map[string]statsLineInfo{
	"newBlocksPerDay": {
		ID: "newBlocksPerDay", Title: "New blocks per day",
		Description: "Number of blocks produced each day", Resolutions: []string{"DAY"},
	},
	"newTxnsPerDay": {
		ID: "newTxnsPerDay", Title: "New transactions per day",
		Description: "Number of transactions each day", Resolutions: []string{"DAY"},
	},
}

func (s *StatsService) handleLines(w http.ResponseWriter, r *http.Request) {
	sections := []map[string]any{
		{
			"id": "blocks", "title": "Blocks",
			"charts": []statsLineInfo{lineInfos["newBlocksPerDay"]},
		},
		{
			"id": "transactions", "title": "Transactions",
			"charts": []statsLineInfo{lineInfos["newTxnsPerDay"]},
		},
	}
	writeJSON(w, http.StatusOK, map[string]any{"sections": sections})
}

func (s *StatsService) handleLine(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	info, ok := lineInfos[id]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "unknown chart"})
		return
	}
	db, err := s.conn()
	if err != nil {
		writeJSON(w, http.StatusOK, statsLineChart{Chart: []statsPoint{}, Info: info})
		return
	}

	var query string
	switch id {
	case "newBlocksPerDay":
		query = `SELECT strftime('%Y-%m-%d', timestamp, 'unixepoch') d, COUNT(*)
			FROM evm_blocks WHERE timestamp > ? GROUP BY d ORDER BY d`
	case "newTxnsPerDay":
		query = `SELECT strftime('%Y-%m-%d', b.timestamp, 'unixepoch') d, COUNT(*)
			FROM evm_transactions t JOIN evm_blocks b ON t.block_number = b.number
			WHERE b.timestamp > ? GROUP BY d ORDER BY d`
	}
	points, err := s.dailySeries(db, query, 365)
	if err != nil {
		writeJSON(w, http.StatusOK, statsLineChart{Chart: []statsPoint{}, Info: info})
		return
	}
	writeJSON(w, http.StatusOK, statsLineChart{Chart: points, Info: info})
}

func (s *StatsService) handlePagesMain(w http.ResponseWriter, r *http.Request) {
	db, err := s.conn()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	blocks := s.count(db, "evm_blocks")
	txns := s.count(db, "evm_transactions")
	addrs := s.count(db, "evm_addresses")
	avgSec := s.avgBlockTimeSec(db)
	daily, _ := s.dailySeries(db, `SELECT strftime('%Y-%m-%d', b.timestamp, 'unixepoch') d, COUNT(*)
		FROM evm_transactions t JOIN evm_blocks b ON t.block_number = b.number
		WHERE b.timestamp > ? GROUP BY d ORDER BY d`, 30)

	writeJSON(w, http.StatusOK, map[string]any{
		"total_blocks":           statsCounter{ID: "total_blocks", Value: fmt.Sprintf("%d", blocks), Title: "Total blocks", Description: "All blocks"},
		"total_transactions":     statsCounter{ID: "total_txns", Value: fmt.Sprintf("%d", txns), Title: "Total transactions", Description: "All transactions"},
		"total_addresses":        statsCounter{ID: "total_addresses", Value: fmt.Sprintf("%d", addrs), Title: "Total addresses", Description: "Distinct addresses"},
		"average_block_time":     statsCounter{ID: "average_block_time", Value: fmt.Sprintf("%.1f", avgSec), Title: "Average block time", Units: "s", Description: "Average interval between blocks"},
		"daily_new_transactions": statsLineChart{Chart: daily, Info: lineInfos["newTxnsPerDay"]},
	})
}

func (s *StatsService) handlePagesTransactions(w http.ResponseWriter, r *http.Request) {
	db, err := s.conn()
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	var txns24h int64
	db.QueryRow(`SELECT COUNT(*) FROM evm_transactions t JOIN evm_blocks b ON t.block_number = b.number
		WHERE b.timestamp > ?`, time.Now().AddDate(0, 0, -1).Unix()).Scan(&txns24h)
	writeJSON(w, http.StatusOK, map[string]any{
		"transactions_24h": statsCounter{ID: "new_txns_24h", Value: fmt.Sprintf("%d", txns24h), Title: "Transactions (24h)", Description: "Transactions in the last 24 hours"},
	})
}

func (s *StatsService) handlePagesContracts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{})
}
