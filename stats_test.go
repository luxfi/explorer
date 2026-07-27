package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// newTestStatsDB builds a minimal indexer DB mirroring the evm_* schema columns
// the stats service reads: evm_blocks(number, timestamp[unix]), evm_transactions
// (block_number), evm_addresses(hash).
func newTestStatsDB(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "indexer.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`
		CREATE TABLE evm_blocks (number INTEGER PRIMARY KEY, timestamp INTEGER, gas_used INTEGER, gas_limit INTEGER, base_fee TEXT);
		CREATE TABLE evm_transactions (hash TEXT PRIMARY KEY, block_number INTEGER, gas_price TEXT);
		CREATE TABLE evm_addresses (hash TEXT PRIMARY KEY);
	`)
	if err != nil {
		t.Fatal(err)
	}
	// 5 blocks over the last 3 days (30s apart within a day), 3 txns, 2 addrs.
	now := time.Now()
	for i := 0; i < 5; i++ {
		ts := now.AddDate(0, 0, -(i % 3)).Unix() + int64(i)*30
		if _, err := db.Exec(`INSERT INTO evm_blocks(number,timestamp,gas_used,gas_limit,base_fee) VALUES(?,?,?,?,?)`,
			i+1, ts, 21000, 12000000, "0x5"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		if _, err := db.Exec(`INSERT INTO evm_transactions(hash,block_number,gas_price) VALUES(?,?,?)`,
			fmt.Sprintf("0x%064d", i), i+1, "25000000000"); err != nil {
			t.Fatal(err)
		}
	}
	db.Exec(`INSERT INTO evm_addresses(hash) VALUES('0x01'),('0x02')`)
	return path
}

func TestStatsCounters(t *testing.T) {
	s := NewStatsService(newTestStatsDB(t))
	rec := httptest.NewRecorder()
	s.handleCounters(rec, httptest.NewRequest(http.MethodGet, "/v1/counters", nil))
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	var out struct {
		Counters []statsCounter `json:"counters"`
	}
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
	if got["total_txns"] != "3" {
		t.Errorf("total_txns = %q, want 3", got["total_txns"])
	}
	if got["total_addresses"] != "2" {
		t.Errorf("total_addresses = %q, want 2", got["total_addresses"])
	}
}

func TestStatsLines(t *testing.T) {
	s := NewStatsService(newTestStatsDB(t))
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

func TestStatsLineData(t *testing.T) {
	s := NewStatsService(newTestStatsDB(t))
	for _, id := range []string{"newBlocksPerDay", "newTxnsPerDay"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/lines/"+id, nil)
		req.SetPathValue("id", id)
		s.handleLine(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s status %d", id, rec.Code)
		}
		var out statsLineChart
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if len(out.Chart) == 0 {
			t.Errorf("%s returned no data points", id)
		}
		if out.Info.ID != id {
			t.Errorf("%s info.id = %q", id, out.Info.ID)
		}
	}
}

func TestStatsLineUnknown(t *testing.T) {
	s := NewStatsService(newTestStatsDB(t))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/lines/nope", nil)
	req.SetPathValue("id", "nope")
	s.handleLine(rec, req)
	if rec.Code != 404 {
		t.Errorf("unknown chart status = %d, want 404", rec.Code)
	}
}
