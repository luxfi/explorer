package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

// Full evm_blocks schema, matching what the indexer actually writes — the
// shared stats harness only creates the columns /v1/counters needs.
func newBlocksDB(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "indexer.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`
		CREATE TABLE evm_blocks (number INTEGER PRIMARY KEY, hash TEXT, parent_hash TEXT, nonce TEXT,
			miner TEXT, difficulty TEXT, total_difficulty TEXT, size INTEGER, gas_limit INTEGER,
			gas_used INTEGER, base_fee TEXT, timestamp TIMESTAMP, tx_count INTEGER);
		CREATE TABLE evm_transactions (hash TEXT PRIMARY KEY, block_number INTEGER);
		CREATE TABLE evm_addresses (hash TEXT PRIMARY KEY);
	`); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		if _, err := db.Exec(`INSERT INTO evm_blocks
			(number,hash,parent_hash,miner,gas_limit,gas_used,base_fee,timestamp,tx_count)
			VALUES(?,?,?,?,?,?,?,?,?)`,
			i, fmt.Sprintf("0x%064d", i), fmt.Sprintf("0x%064d", i-1),
			"0x0000000000000000000000000000000000000001", 12000000, 21000, "0x5", 1700000000+i, 1); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("bad json: %v -- %s", err, rec.Body.String())
	}
	return body
}

// /v1/stats is the canonical flat summary. Values must be plain numbers so a
// caller can compare total_blocks to eth_blockNumber without unwrapping an
// envelope — that comparison is the only real check that the index is current.
func TestV1Stats(t *testing.T) {
	s := NewStatsService(newBlocksDB(t, 7))
	rec := httptest.NewRecorder()
	s.handleStats(rec, httptest.NewRequest(http.MethodGet, "/v1/stats", nil))
	body := decode(t, rec)

	if got := body["total_blocks"].(float64); got != 7 {
		t.Errorf("total_blocks = %v, want 7", got)
	}
	if got := body["head_block"].(float64); got != 7 {
		t.Errorf("head_block = %v, want 7", got)
	}
	if body["indexed"] != true {
		t.Errorf("indexed = %v, want true", body["indexed"])
	}
}

// A missing DB is a real state (fresh chain, indexer starting), not an error:
// it must answer 200 with indexed=false so a health check can tell the two
// apart, rather than 500ing.
func TestV1StatsNoDB(t *testing.T) {
	s := NewStatsService(filepath.Join(t.TempDir(), "absent.db"))
	rec := httptest.NewRecorder()
	s.handleStats(rec, httptest.NewRequest(http.MethodGet, "/v1/stats", nil))
	body := decode(t, rec)
	if body["indexed"] != false {
		t.Errorf("indexed = %v, want false", body["indexed"])
	}
}

func TestV1Blocks(t *testing.T) {
	s := NewStatsService(newBlocksDB(t, 10))

	t.Run("newest first, default page", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.handleBlocks(rec, httptest.NewRequest(http.MethodGet, "/v1/blocks", nil))
		blocks := decode(t, rec)["blocks"].([]any)
		if len(blocks) != 10 {
			t.Fatalf("got %d blocks, want 10", len(blocks))
		}
		if n := blocks[0].(map[string]any)["number"].(float64); n != 10 {
			t.Errorf("first block = %v, want 10 (newest first)", n)
		}
		if h := blocks[0].(map[string]any)["hash"].(string); h == "" {
			t.Error("hash must be populated")
		}
	})

	t.Run("limit is honoured", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.handleBlocks(rec, httptest.NewRequest(http.MethodGet, "/v1/blocks?limit=3", nil))
		if got := len(decode(t, rec)["blocks"].([]any)); got != 3 {
			t.Fatalf("got %d blocks, want 3", got)
		}
	})

	t.Run("limit is bounded so a huge index cannot be dumped", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.handleBlocks(rec, httptest.NewRequest(http.MethodGet, "/v1/blocks?limit=99999", nil))
		got := len(decode(t, rec)["blocks"].([]any))
		// Assert the cap AND that rows actually came back — `got > 200` alone
		// passes trivially when the handler returns nothing, which is how the
		// scan-type bug slipped through the first run of this suite.
		if got != 10 {
			t.Fatalf("returned %d blocks, want all 10 (capped at 200)", got)
		}
	})

	t.Run("before pages backwards", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.handleBlocks(rec, httptest.NewRequest(http.MethodGet, "/v1/blocks?before=5&limit=2", nil))
		blocks := decode(t, rec)["blocks"].([]any)
		if len(blocks) != 2 {
			t.Fatalf("got %d blocks, want 2", len(blocks))
		}
		if n := blocks[0].(map[string]any)["number"].(float64); n != 4 {
			t.Errorf("first block = %v, want 4 (strictly before 5)", n)
		}
	})
}

// Every route this service mounts lives under /v1 and none under /api.
func TestStatsRoutesAreV1Only(t *testing.T) {
	mux := http.NewServeMux()
	NewStatsService("/nonexistent.db").Mount(mux)
	for _, p := range []string{"/v1/stats", "/v1/blocks", "/v1/counters", "/v1/pages/main"} {
		if _, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, p, nil)); pattern == "" {
			t.Errorf("%s is not mounted", p)
		}
	}
	// /api/v2 is Blockscout's shape and must not exist here.
	if _, pattern := mux.Handler(httptest.NewRequest(http.MethodGet, "/api/v2/stats", nil)); pattern != "" {
		t.Errorf("/api/v2/stats must NOT be mounted, got pattern %q", pattern)
	}
}
