package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// StatsService serves the Blockscout stats-microservice API surface
// (/v1/counters, /v1/lines, /v1/lines/{id}, /v1/pages/*), backed directly by
// the live indexer SQLite DB of whichever chain the request host names.
//
// The Next.js explorer turns on config.features.stats when
// NEXT_PUBLIC_STATS_API_HOST is set (it points at this backend). Its /stats page
// then requests /v1/counters and /v1/lines; without them it shows two error
// banners ("Something went wrong" + "Some of the charts did not load because the
// server didn't respond"). The indexer's own /v1/indexer/{slug}/stats endpoint
// is a different shape and its chart endpoints are empty stubs, so we serve real
// aggregates here, computed from evm_blocks / evm_transactions / evm_addresses.
type StatsService struct {
	dataDir string
	cfg     Config
	mu      sync.Mutex
	dbs     map[string]*sql.DB
	aggs    map[string]*memo
}

// NewStatsService reads each chain's indexer DB at {dataDir}/{slug}/query/indexer.db.
func NewStatsService(dataDir string, cfg Config) *StatsService {
	return &StatsService{
		dataDir: dataDir, cfg: cfg,
		dbs:  make(map[string]*sql.DB),
		aggs: make(map[string]*memo),
	}
}

// chain names the chain a request is served from.
func (s *StatsService) chain(r *http.Request) string { return s.cfg.Serves(r.Host).Slug }

// conn lazily opens a read-only handle to a chain's DB, one handle per chain.
// The indexer writes in WAL mode, so a read-only reader never blocks ingestion.
// The DB may not exist until the indexer has created it, so open is retried
// per-request until it succeeds.
func (s *StatsService) conn(slug string) (*sql.DB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if db, ok := s.dbs[slug]; ok {
		return db, nil
	}
	path := filepath.Join(s.dataDir, slug, "query", "indexer.db")
	db, err := sql.Open("sqlite3", "file:"+path+"?mode=ro&_busy_timeout=3000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	s.dbs[slug] = db
	return db, nil
}

// ---- One chain's arithmetic, computed once ----

// aggregate is every whole-table number the stats surfaces report. Each field
// costs a full scan: SQLite keeps no row count, and both the day bucket and the
// epoch bound are expressions over a TEXT datetime column, so no index answers
// them. On a chain of a million blocks the whole set costs seconds, and the
// same handful of connections serves every reader, so a request that computes
// its own copy makes every other request wait for it.
//
// A chain is append-only: within a few seconds every caller wants the same
// numbers. So they are computed once per chain per interval and read from
// memory, and the cost stops scaling with traffic. An indexed lookup like
// /v1/blocks is three orders of magnitude cheaper and is left alone.
type aggregate struct {
	blocks, txns, addrs, head, txns24h int64
	avgSec                             float64
	blocksPerDay, txsPerDay            []statsPoint // trailing year, oldest first
	at                                 time.Time
}

// memo holds one chain's aggregate and admits a single computation at a time.
type memo struct {
	compute sync.Mutex
	val     atomic.Pointer[aggregate]
}

// freshFor is how long an aggregate is served before a refresh is started. The
// numbers it holds are lifetime totals over an append-only chain, so a caller
// reading one a few seconds old sees the same chain everyone else does.
const freshFor = 30 * time.Second

// memoFor returns the memo for a chain, creating it on first use.
func (s *StatsService) memoFor(slug string) *memo {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.aggs[slug]
	if !ok {
		m = &memo{}
		s.aggs[slug] = m
	}
	return m
}

// numbers returns a chain's aggregate, and whether there is one to report.
//
// Once a value exists it is returned immediately and refreshed in the
// background when it ages past freshFor, so no request ever waits on a scan.
// Before then — a fresh chain, or an indexer that has not written its DB yet —
// the first caller computes it and any caller arriving meanwhile waits for that
// same computation rather than starting a second one.
func (s *StatsService) numbers(slug string) (*aggregate, bool) {
	m := s.memoFor(slug)
	if v := m.val.Load(); v != nil {
		if time.Since(v.at) > freshFor && m.compute.TryLock() {
			go func() {
				defer m.compute.Unlock()
				if fresh := s.scan(slug); fresh != nil {
					m.val.Store(fresh)
				}
			}()
		}
		return v, true
	}
	m.compute.Lock()
	defer m.compute.Unlock()
	if v := m.val.Load(); v != nil {
		return v, true
	}
	v := s.scan(slug)
	if v == nil {
		return nil, false
	}
	m.val.Store(v)
	return v, true
}

// scan computes a chain's aggregate. It is the only place these tables are
// counted, so every stats surface reports the same numbers as every other.
func (s *StatsService) scan(slug string) *aggregate {
	db, err := s.conn(slug)
	if err != nil {
		return nil
	}
	a := &aggregate{at: time.Now()}
	a.blocks = s.count(db, "evm_blocks")
	a.txns = s.count(db, "evm_transactions")
	a.addrs = s.count(db, "evm_addresses")
	a.avgSec = s.avgBlockTimeSec(db)
	if err := db.QueryRow("SELECT COALESCE(MAX(number),0) FROM evm_blocks").Scan(&a.head); err != nil {
		log.Printf("stats[%s]: head block unavailable: %v", slug, err)
	}
	// Bound on blockEpoch: SQLite orders every INTEGER below every TEXT, so a
	// datetime string compared against an epoch bound is always "greater than"
	// it, which reports the lifetime transaction count as the last 24 hours.
	if err := db.QueryRow(`SELECT COUNT(*)
		FROM evm_transactions t JOIN evm_blocks b ON t.block_number = b.number
		WHERE `+blockEpoch+` > ?`, time.Now().AddDate(0, 0, -1).Unix()).Scan(&a.txns24h); err != nil {
		log.Printf("stats[%s]: 24h transactions failed: %v", slug, err)
	}
	// A year covers every window asked for, so the shorter ones are cut from it
	// rather than scanned again.
	var err2 error
	if a.blocksPerDay, err2 = s.dailySeries(db, blocksPerDay, 365); err2 != nil {
		log.Printf("stats[%s]: daily blocks failed: %v", slug, err2)
		a.blocksPerDay = []statsPoint{}
	}
	if a.txsPerDay, err2 = s.dailySeries(db, txsPerDay, 365); err2 != nil {
		log.Printf("stats[%s]: daily transactions failed: %v", slug, err2)
		a.txsPerDay = []statsPoint{}
	}
	return a
}

// trailing cuts the last `days` UTC days from a series. Dates are ISO, so they
// compare chronologically as strings. A day on which nothing happened has no
// row, which is why this selects by date rather than by count.
func trailing(points []statsPoint, days int) []statsPoint {
	cut := time.Now().AddDate(0, 0, -days).Format("2006-01-02")
	out := make([]statsPoint, 0, days)
	for _, p := range points {
		if p.Date >= cut {
			out = append(out, p)
		}
	}
	return out
}

// Warm computes every configured chain's aggregate so the first caller after a
// start reads it from memory instead of waiting for the scan.
func (s *StatsService) Warm() {
	for _, ch := range s.cfg.Chains {
		if ch.Slug == "" {
			continue
		}
		go s.numbers(ch.Slug)
	}
}

// Mount registers the stats-service routes on mux.
//
// /v1/stats and /v1/blocks are the CANONICAL names. Everything under /v1 and
// nothing under /api — there is no /api/v2 here and never will be; see the
// house rule (api.* hosts carry /v1/ paths, and v1 is never bumped).
// /v1/counters and /v1/pages/* remain as the chart/page-shaped views the SPA
// already consumes; /v1/stats is the flat summary and is what external callers
// and health checks should use.
func (s *StatsService) Mount(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/stats", s.handleStats)
	mux.HandleFunc("GET /v1/blocks", s.handleBlocks)
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

// evm_blocks.timestamp is a column declared TIMESTAMP that the indexer fills by
// binding a Go time.Time, so SQLite stores a datetime STRING — never an
// integer. Reading it as an epoch is what silently emptied every chart on
// /stats: CAST('2026-08-08 12:55:22+00:00' AS INTEGER) is 2026 (SQLite takes
// the leading numeric prefix), and strftime with the 'unixepoch' modifier
// returns NULL because that modifier wants a number. strftime parses the
// string, applies its timezone, and answers in UTC. These are the only two
// spellings allowed to touch that column.
//
// Both name the column as `b.timestamp`, so every query below aliases
// evm_blocks to b — evm_transactions carries a timestamp too, and an
// unqualified reference is ambiguous the moment the two are joined.
const (
	blockEpoch = `CAST(strftime('%s', b.timestamp) AS INTEGER)`
	blockDay   = `strftime('%Y-%m-%d', b.timestamp)`
)

func (s *StatsService) count(db *sql.DB, table string) int64 {
	var n int64
	// #nosec G201 — table is a fixed internal identifier, never user input.
	db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
	return n
}

// avgBlockTimeSec returns the lifetime average block interval in seconds,
// derived from the full timestamp span so it stays meaningful on a sparse,
// demand-driven chain (per-window deltas collapse to zero when idle).
//
// The span is measured between the FIRST and LAST block by number, not by
// MIN and MAX of the timestamp column. Timestamps are monotonic in block order
// by consensus rule, so the two agree on a sound index — and disagree loudly
// on a damaged one, where MIN/MAX hands a single stray row the whole history.
// Hanzo carries a block that parses to epoch 0: MIN/MAX anchored the span at
// 1970 and reported 58,370 seconds per block on a chain that builds one every
// ten. Zoo carries one dated 1.76 years before its own first block, and read
// 2,387. Both are one row out of tens of thousands, and neither is the
// interval between blocks.
//
// Blocks with no time at all are skipped: a block that does not say when it
// happened cannot bound how far apart blocks are.
func (s *StatsService) avgBlockTimeSec(db *sql.DB) float64 {
	var count, minTS, maxTS int64
	err := db.QueryRow(`SELECT
		(SELECT COUNT(*) FROM evm_blocks b WHERE `+blockEpoch+` > 0),
		COALESCE((SELECT `+blockEpoch+` FROM evm_blocks b WHERE `+blockEpoch+` > 0 ORDER BY number ASC LIMIT 1), 0),
		COALESCE((SELECT `+blockEpoch+` FROM evm_blocks b WHERE `+blockEpoch+` > 0 ORDER BY number DESC LIMIT 1), 0)`).
		Scan(&count, &minTS, &maxTS)
	if err != nil {
		// Say WHY. Swallowing this is how the tile read "0.0 s" on a chain with
		// 1.1M blocks: the scan failed on every request and the zero value went
		// out as if it were the answer.
		log.Printf("stats: average block time unavailable: %v", err)
		return 0
	}
	if count < 2 || maxTS <= minTS {
		return 0
	}
	return float64(maxTS-minTS) / float64(count-1)
}

// dailySeries buckets a COUNT by UTC day over the trailing `days` window.
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

// blocksPerDay and txsPerDay are the two daily aggregates this service serves.
// Both bound the window on the epoch expression: comparing the datetime string
// against an integer bound is not just imprecise, SQLite orders every INTEGER
// below every TEXT, so `timestamp > 1754…` matched all 1.1M rows.
const (
	blocksPerDay = `SELECT ` + blockDay + ` d, COUNT(*) FROM evm_blocks b
		WHERE ` + blockEpoch + ` > ? GROUP BY d ORDER BY d`
	txsPerDay = `SELECT ` + blockDay + ` d, COUNT(*)
		FROM evm_transactions t JOIN evm_blocks b ON t.block_number = b.number
		WHERE ` + blockEpoch + ` > ? GROUP BY d ORDER BY d`
)

// ---- Handlers ----

func (s *StatsService) handleCounters(w http.ResponseWriter, r *http.Request) {
	a, ok := s.numbers(s.chain(r))
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"counters": []statsCounter{}})
		return
	}
	blocks, txns, addrs, avgSec := a.blocks, a.txns, a.addrs, a.avgSec

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
	a, ok := s.numbers(s.chain(r))
	if !ok {
		writeJSON(w, http.StatusOK, statsLineChart{Chart: []statsPoint{}, Info: info})
		return
	}
	points := a.blocksPerDay
	if id == "newTxnsPerDay" {
		points = a.txsPerDay
	}
	writeJSON(w, http.StatusOK, statsLineChart{Chart: points, Info: info})
}

// handleStats is the canonical flat summary: GET /v1/stats. Values are plain
// JSON numbers, not the counter envelopes /v1/counters uses, so a caller can
// compare total_blocks against eth_blockNumber without unwrapping anything.
// That comparison is the only honest way to tell whether the index is current —
// an HTTP 200 from the explorer proves nothing about whether it has the chain.
func (s *StatsService) handleStats(w http.ResponseWriter, r *http.Request) {
	a, ok := s.numbers(s.chain(r))
	if !ok {
		// No DB yet is a real state (fresh chain, indexer still starting), not
		// an error. Report zeroes and say so, rather than 500ing a health check.
		writeJSON(w, http.StatusOK, map[string]any{
			"total_blocks": 0, "total_transactions": 0, "total_addresses": 0,
			"average_block_time": 0, "indexed": false,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total_blocks":       a.blocks,
		"total_transactions": a.txns,
		"total_addresses":    a.addrs,
		"average_block_time": a.avgSec,
		"head_block":         a.head,
		"indexed":            true,
	})
}

// handleBlocks is the canonical block list: GET /v1/blocks?limit=&before=.
// Newest first. `before` pages backwards by block number so a caller never has
// to guess an offset while the head advances underneath it.
func (s *StatsService) handleBlocks(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 200 {
		limit = 200 // bound the page; an unbounded LIMIT is a DoS on a big index
	}
	db, err := s.conn(s.chain(r))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"blocks": []any{}, "indexed": false})
		return
	}
	// blockEpoch, not a bare read: go-sqlite3 converts a column declared
	// TIMESTAMP to time.Time, which will not Scan into an int64 — every row
	// would be skipped and the endpoint would answer an empty list on a fully
	// populated index. It parses the stored datetime rather than casting it,
	// which is what made this field read 2026 for every block on mainnet.
	query := `SELECT number, hash, parent_hash, miner, gas_limit, gas_used, base_fee,
		` + blockEpoch + `, tx_count FROM evm_blocks b`
	args := []any{}
	if before := r.URL.Query().Get("before"); before != "" {
		if n, err := strconv.ParseInt(before, 10, 64); err == nil {
			query += " WHERE number < ?"
			args = append(args, n)
		}
	}
	query += " ORDER BY number DESC LIMIT ?"
	args = append(args, limit)

	rows, err := db.Query(query, args...)
	if err != nil {
		// Say WHY. An empty list that silently means "the query broke" is
		// indistinguishable from "this chain has no blocks", and that ambiguity
		// is exactly how a scan-type bug hides behind a 200.
		log.Printf("v1/blocks: query failed: %v", err)
		writeJSON(w, http.StatusOK, map[string]any{"blocks": []any{}, "indexed": true, "error": err.Error()})
		return
	}
	defer rows.Close()

	blocks := []map[string]any{}
	for rows.Next() {
		var (
			number, gasLimit, gasUsed, ts, txCount int64
			hash, parent, miner, baseFee           sql.NullString
		)
		if err := rows.Scan(&number, &hash, &parent, &miner, &gasLimit, &gasUsed, &baseFee, &ts, &txCount); err != nil {
			log.Printf("v1/blocks: skipping row: %v", err)
			continue
		}
		blocks = append(blocks, map[string]any{
			"number": number, "hash": hash.String, "parent_hash": parent.String,
			"miner": miner.String, "gas_limit": gasLimit, "gas_used": gasUsed,
			"base_fee": baseFee.String, "timestamp": ts, "tx_count": txCount,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"blocks": blocks, "indexed": true})
}

func (s *StatsService) handlePagesMain(w http.ResponseWriter, r *http.Request) {
	a, ok := s.numbers(s.chain(r))
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	// A nil slice marshals to `null`, which the SPA renders as "No data" —
	// identical on the wire to a chain that genuinely has no transactions.
	// trailing always returns a slice, so the two stay distinguishable.
	daily := trailing(a.txsPerDay, 30)

	writeJSON(w, http.StatusOK, map[string]any{
		"total_blocks":           statsCounter{ID: "total_blocks", Value: fmt.Sprintf("%d", a.blocks), Title: "Total blocks", Description: "All blocks"},
		"total_transactions":     statsCounter{ID: "total_txns", Value: fmt.Sprintf("%d", a.txns), Title: "Total transactions", Description: "All transactions"},
		"total_addresses":        statsCounter{ID: "total_addresses", Value: fmt.Sprintf("%d", a.addrs), Title: "Total addresses", Description: "Distinct addresses"},
		"average_block_time":     statsCounter{ID: "average_block_time", Value: fmt.Sprintf("%.1f", a.avgSec), Title: "Average block time", Units: "s", Description: "Average interval between blocks"},
		"daily_new_transactions": statsLineChart{Chart: daily, Info: lineInfos["newTxnsPerDay"]},
	})
}

func (s *StatsService) handlePagesTransactions(w http.ResponseWriter, r *http.Request) {
	a, ok := s.numbers(s.chain(r))
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"transactions_24h": statsCounter{ID: "new_txns_24h", Value: fmt.Sprintf("%d", a.txns24h), Title: "Transactions (24h)", Description: "Transactions in the last 24 hours"},
	})
}

func (s *StatsService) handlePagesContracts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{})
}
