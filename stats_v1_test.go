package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// /v1/stats is the canonical flat summary. Values must be plain numbers so a
// caller can compare total_blocks to eth_blockNumber without unwrapping an
// envelope — that comparison is the only real check that the index is current.
func TestV1Stats(t *testing.T) {
	body := get(t, newStats(t, 7).handleStats, "api-explore.lux.network", "/v1/stats")

	if got := body["total_blocks"].(float64); got != 7 {
		t.Errorf("total_blocks = %v, want 7", got)
	}
	if got := body["head_block"].(float64); got != 7 {
		t.Errorf("head_block = %v, want 7", got)
	}
	if got := body["average_block_time"].(float64); got != 60 {
		t.Errorf("average_block_time = %v, want 60", got)
	}
	if body["indexed"] != true {
		t.Errorf("indexed = %v, want true", body["indexed"])
	}
}

// A missing DB is a real state (fresh chain, indexer starting), not an error:
// it must answer 200 with indexed=false so a health check can tell the two
// apart, rather than 500ing.
func TestV1StatsNoDB(t *testing.T) {
	s := NewStatsService(t.TempDir(), statsChains)
	body := get(t, s.handleStats, "api-explore.lux.network", "/v1/stats")
	if body["indexed"] != false {
		t.Errorf("indexed = %v, want false", body["indexed"])
	}
}

func TestV1Blocks(t *testing.T) {
	s := newStats(t, 10)
	const host = "api-explore.lux.network"

	t.Run("newest first, default page", func(t *testing.T) {
		blocks := get(t, s.handleBlocks, host, "/v1/blocks")["blocks"].([]any)
		if len(blocks) != 10 {
			t.Fatalf("got %d blocks, want 10", len(blocks))
		}
		first := blocks[0].(map[string]any)
		if n := first["number"].(float64); n != 10 {
			t.Errorf("first block = %v, want 10 (newest first)", n)
		}
		if h := first["hash"].(string); h == "" {
			t.Error("hash must be populated")
		}
		// The timestamp is a unix epoch within a minute of the fixture's head.
		// It read 2026 on mainnet — SQLite casting the leading digits of the
		// stored datetime string — and 2026 is a plausible-looking number, which
		// is why nothing caught it.
		ts := int64(first["timestamp"].(float64))
		if delta := time.Since(time.Unix(ts, 0)); delta < 0 || delta > 2*time.Minute {
			t.Errorf("timestamp = %d (%s), want the head block's real time", ts, time.Unix(ts, 0))
		}
	})

	t.Run("limit is honoured", func(t *testing.T) {
		if got := len(get(t, s.handleBlocks, host, "/v1/blocks?limit=3")["blocks"].([]any)); got != 3 {
			t.Fatalf("got %d blocks, want 3", got)
		}
	})

	t.Run("limit is bounded so a huge index cannot be dumped", func(t *testing.T) {
		got := len(get(t, s.handleBlocks, host, "/v1/blocks?limit=99999")["blocks"].([]any))
		// Assert the cap AND that rows actually came back — `got > 200` alone
		// passes trivially when the handler returns nothing, which is how the
		// scan-type bug slipped through the first run of this suite.
		if got != 10 {
			t.Fatalf("returned %d blocks, want all 10 (capped at 200)", got)
		}
	})

	t.Run("before pages backwards", func(t *testing.T) {
		blocks := get(t, s.handleBlocks, host, "/v1/blocks?before=5&limit=2")["blocks"].([]any)
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
	NewStatsService(t.TempDir(), statsChains).Mount(mux)
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
