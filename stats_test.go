package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	// ONE sqlite C library in this binary, under a name nothing else claims.
	// This process links graph and indexer as well as its own store, and
	// csqlite is the house build of the amalgamation all three now open —
	// registered as "sqlite3". Upstream mattn compiles a second copy of the
	// same C, and defining every sqlite3_* symbol twice fails at link on
	// darwin. Not its hanzoai/sqlite wrapper either: that registers
	// "sqlite", and so does modernc.org/sqlite, which arrives with
	// hanzoai/replicate — two packages under one name is a panic in init.
	_ "github.com/hanzoai/csqlite"
)

// statsChains is the two-chain registry the stats tests resolve hosts against:
// cchain is the configured default (so an unnamed host lands there) and hanzo
// is reachable only by naming it in the hostname.
var statsChains = Config{Chains: []ChainConfig{
	{Slug: "cchain", Name: "Lux C-Chain", Default: true},
	{Slug: "hanzo", Name: "Hanzo"},
}}

// writeIndexerDB builds one chain's indexer DB under the layout the service
// reads, {dataDir}/{slug}/query/indexer.db, and fills it with `blocks` blocks
// one minute apart ending now, one transaction in every block, two addresses.
//
// timestamp is written the way the indexer writes it: a Go time.Time bound
// into a column declared TIMESTAMP, which go-sqlite3 stores as a datetime
// STRING. A fixture that puts a unix integer in that column compiles, passes,
// and proves nothing — it is exactly what let every /stats chart ship empty
// and the average-block-time tile ship "0.0" under a green suite.
func writeIndexerDB(t *testing.T, dataDir, slug string, blocks int) {
	t.Helper()
	dir := filepath.Join(dataDir, slug, "query")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", filepath.Join(dir, "indexer.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`
		CREATE TABLE evm_blocks (id TEXT PRIMARY KEY, number INTEGER, hash TEXT, parent_hash TEXT,
			nonce TEXT, miner TEXT, difficulty TEXT, total_difficulty TEXT, gas_limit INTEGER,
			gas_used INTEGER, timestamp TIMESTAMP NOT NULL, tx_count INTEGER, base_fee TEXT, size INTEGER);
		CREATE TABLE evm_transactions (hash TEXT PRIMARY KEY, block_number INTEGER, timestamp TIMESTAMP);
		CREATE TABLE evm_addresses (hash TEXT PRIMARY KEY);
	`); err != nil {
		t.Fatal(err)
	}
	start := time.Now().Add(-time.Duration(blocks) * time.Minute)
	for i := 1; i <= blocks; i++ {
		ts := start.Add(time.Duration(i) * time.Minute)
		if _, err := db.Exec(`INSERT INTO evm_blocks
			(id,number,hash,parent_hash,miner,gas_limit,gas_used,timestamp,tx_count,base_fee)
			VALUES(?,?,?,?,?,?,?,?,?,?)`,
			fmt.Sprintf("0x%064d", i), i, fmt.Sprintf("0x%064d", i), fmt.Sprintf("0x%064d", i-1),
			"0x0000000000000000000000000000000000000001", 12000000, 21000, ts, 1, "0x5"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO evm_transactions(hash,block_number,timestamp) VALUES(?,?,?)`,
			fmt.Sprintf("0xaa%062d", i), i, ts); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO evm_addresses(hash) VALUES('0x01'),('0x02')`); err != nil {
		t.Fatal(err)
	}
}

// newStats returns a service over a fresh data dir holding one cchain DB.
func newStats(t *testing.T, blocks int) *StatsService {
	t.Helper()
	dir := t.TempDir()
	writeIndexerDB(t, dir, "cchain", blocks)
	return NewStatsService(dir, statsChains)
}

// get calls a handler for `host` and decodes the JSON body.
func get(t *testing.T, h http.HandlerFunc, host, path string, pathValues ...string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	for i := 0; i+1 < len(pathValues); i += 2 {
		req.SetPathValue(pathValues[i], pathValues[i+1])
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s: status %d", host, path, rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s %s: bad json: %v -- %s", host, path, err, rec.Body.String())
	}
	return body
}

func TestStatsCounters(t *testing.T) {
	s := newStats(t, 5)
	var out struct {
		Counters []statsCounter `json:"counters"`
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/counters", nil)
	rec := httptest.NewRecorder()
	s.handleCounters(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, c := range out.Counters {
		got[c.ID] = c.Value
		if c.Title == "" {
			t.Errorf("counter %s has empty title", c.ID)
		}
	}
	if got["total_blocks"] != "5" {
		t.Errorf("total_blocks = %q, want 5", got["total_blocks"])
	}
	if got["total_txns"] != "5" {
		t.Errorf("total_txns = %q, want 5", got["total_txns"])
	}
	if got["total_addresses"] != "2" {
		t.Errorf("total_addresses = %q, want 2", got["total_addresses"])
	}
	// Blocks are one minute apart, so the lifetime average is 60s. Asserting the
	// VALUE, not merely that a counter exists: "0.0" is what this reported on a
	// 1.1M-block chain for as long as the timestamp was read as an epoch.
	if got["average_block_time"] != "60.0" {
		t.Errorf("average_block_time = %q, want 60.0", got["average_block_time"])
	}
}

func TestStatsLines(t *testing.T) {
	s := newStats(t, 5)
	rec := httptest.NewRecorder()
	s.handleLines(rec, httptest.NewRequest(http.MethodGet, "/v1/lines", nil))
	var out struct {
		Sections []struct {
			ID     string          `json:"id"`
			Charts []statsLineInfo `json:"charts"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sections) == 0 {
		t.Fatal("no sections advertised")
	}
	found := false
	for _, sec := range out.Sections {
		for _, c := range sec.Charts {
			if c.ID == "newBlocksPerDay" || c.ID == "newTxnsPerDay" {
				found = true
			}
		}
	}
	if !found {
		t.Error("expected block/txn charts advertised")
	}
}

// The /stats page charts. Both series must carry today's bucket with the full
// block/transaction count in it — an empty Chart is what the page renders as
// "No data", and it answered 200 the whole time it was empty.
func TestStatsLineData(t *testing.T) {
	s := newStats(t, 5)
	today := time.Now().UTC().Format("2006-01-02")
	for _, id := range []string{"newBlocksPerDay", "newTxnsPerDay"} {
		req := httptest.NewRequest(http.MethodGet, "/v1/lines/"+id, nil)
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.handleLine(rec, req)
		var out statsLineChart
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Chart) == 0 {
			t.Fatalf("%s returned no data points", id)
		}
		var total int
		var sawToday bool
		for _, p := range out.Chart {
			if p.Date == today {
				sawToday = true
			}
			var v int
			fmt.Sscanf(p.Value, "%d", &v)
			total += v
		}
		if !sawToday {
			t.Errorf("%s has no bucket for today (%s): %+v", id, today, out.Chart)
		}
		if total != 5 {
			t.Errorf("%s buckets sum to %d, want 5", id, total)
		}
		if out.Info.ID != id {
			t.Errorf("%s info.id = %q", id, out.Info.ID)
		}
	}
}

func TestStatsLineUnknown(t *testing.T) {
	s := newStats(t, 5)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/lines/nope", nil)
	req.SetPathValue("id", "nope")
	s.handleLine(rec, req)
	if rec.Code != 404 {
		t.Errorf("unknown chart status = %d, want 404", rec.Code)
	}
}

// One binary answers every brand host, so every aggregate must come from the
// chain that host is served. Hanzo's home page printing Lux's 1,107,085 blocks
// above Hanzo's own height 29,451 is this test, failing.
func TestStatsAreScopedToTheHostsChain(t *testing.T) {
	dir := t.TempDir()
	writeIndexerDB(t, dir, "cchain", 9)
	writeIndexerDB(t, dir, "hanzo", 4)
	s := NewStatsService(dir, statsChains)

	for _, tc := range []struct {
		host   string
		blocks float64
	}{
		{"api-explore.lux.network", 9},   // names no chain -> the default, cchain
		{"api-explore.hanzo.network", 4}, // names hanzo
		{"explore.hanzo.ai", 4},
		{"explorer.hanzo-test.network", 4},
	} {
		body := get(t, s.handleStats, tc.host, "/v1/stats")
		if got := body["total_blocks"].(float64); got != tc.blocks {
			t.Errorf("%s: /v1/stats total_blocks = %v, want %v", tc.host, got, tc.blocks)
		}

		main := get(t, s.handlePagesMain, tc.host, "/v1/pages/main")
		total := main["total_blocks"].(map[string]any)["value"].(string)
		if want := fmt.Sprintf("%d", int(tc.blocks)); total != want {
			t.Errorf("%s: /v1/pages/main total_blocks = %q, want %q", tc.host, total, want)
		}
	}
}

// /v1/pages/main feeds the home page tiles and its own chart. The chart is the
// field that shipped as `null` on all three brands.
func TestPagesMainCarriesItsChart(t *testing.T) {
	s := newStats(t, 6)
	body := get(t, s.handlePagesMain, "api-explore.lux.network", "/v1/pages/main")

	chart, ok := body["daily_new_transactions"].(map[string]any)["chart"].([]any)
	if !ok {
		t.Fatalf("daily_new_transactions.chart is not a series: %#v", body["daily_new_transactions"])
	}
	if len(chart) == 0 {
		t.Fatal("daily_new_transactions.chart is empty")
	}
	if got := body["average_block_time"].(map[string]any)["value"].(string); got != "60.0" {
		t.Errorf("average_block_time = %q, want 60.0", got)
	}
}

// The 24h counter bounds on the same epoch expression. Comparing the stored
// datetime string against an integer bound made every transaction ever indexed
// "in the last 24 hours", because SQLite orders every INTEGER below every TEXT.
func TestPagesTransactions24h(t *testing.T) {
	dir := t.TempDir()
	writeIndexerDB(t, dir, "cchain", 3)
	db, err := sql.Open("sqlite3", filepath.Join(dir, "cchain", "query", "indexer.db"))
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().AddDate(0, 0, -9)
	if _, err := db.Exec(`INSERT INTO evm_blocks(id,number,timestamp,tx_count) VALUES('0xold',999,?,1);
		INSERT INTO evm_transactions(hash,block_number,timestamp) VALUES('0xold',999,?)`, old, old); err != nil {
		t.Fatal(err)
	}
	db.Close()

	body := get(t, NewStatsService(dir, statsChains).handlePagesTransactions,
		"api-explore.lux.network", "/v1/pages/transactions")
	if got := body["transactions_24h"].(map[string]any)["value"].(string); got != "3" {
		t.Errorf("transactions_24h = %q, want 3 (the 9-day-old transaction is outside the window)", got)
	}
}

// One stray row must not become the whole chain's history. Both of these are
// real: Hanzo carries a block that parses to epoch 0 and reported 58,370
// seconds per block; Zoo carries one dated well before its own first block and
// reported 2,387. The chain builds one every ten seconds in both cases.
func TestAverageBlockTimeSurvivesAStrayRow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stray time.Time
	}{
		{"a block with no time at all", time.Unix(0, 0).UTC()},
		{"a block dated years before the first", time.Now().AddDate(-2, 0, 0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeIndexerDB(t, dir, "cchain", 5) // five blocks, one minute apart
			db, err := sql.Open("sqlite3", filepath.Join(dir, "cchain", "query", "indexer.db"))
			if err != nil {
				t.Fatal(err)
			}
			// Numbered in the middle of the run, the way a damaged row sits in a
			// real index — not at either end, where it would be the boundary.
			if _, err := db.Exec(`INSERT INTO evm_blocks(id,number,timestamp,tx_count) VALUES('0xz',3,?,0)`,
				tc.stray); err != nil {
				t.Fatal(err)
			}
			db.Close()

			body := get(t, NewStatsService(dir, statsChains).handleStats, "api-explore.lux.network", "/v1/stats")
			got := body["average_block_time"].(float64)
			// Five blocks a minute apart span four minutes; the stray row adds one
			// more block to the count without extending the span.
			if got < 40 || got > 60 {
				t.Errorf("average_block_time = %v, want the real ~48-60s cadence", got)
			}
		})
	}
}
