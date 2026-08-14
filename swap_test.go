package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luxfi/graph/engine"
)

// The swap form calls /v1/quote, not /v1/graph/cchain/amm/quote. These tests
// drive the unprefixed routes the way it does and assert the answer came from
// the chain the request named — through the real dispatcher into the real
// handler, because a dispatcher that finds the wrong chain and a handler that
// builds the wrong bytes fail identically from the outside.

const (
	luxChain = 96369
	zooChain = 200200
	router   = "0x939bC0Bca6F9B9c52E6e3AD8A3C590b5d9B9D10E"
	wlux     = "0x4888E4a2Ee0F03051c72D2BD3ACf755eD3498B3E"
	lusd     = "0x848Cff46eb323f323b6Bbe1Df274E40793d7f2c2"
	trader   = "0x9011E888251AB053B7bD1cdB598Db4f9DEd94714"
)

// mountChain registers one chain's swap routes exactly as runSubgraph does:
// the handlers go on a mux under the prefixed path, and that same mux is what
// the unprefixed routes reach. Building it the same way is the point — a test
// that registered its own handlers would prove nothing about the wiring.
func mountChain(s *ChainSupervisor, slug string, chainID int64, rtr string) {
	prefix := "/v1/graph/" + slug + "/amm"
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+prefix+"/swap", engine.HandleSwap(chainID, rtr, wlux))
	mux.HandleFunc("POST "+prefix+"/quote", func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(map[string]any{"servedBy": chainID})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	mux.HandleFunc("GET "+prefix+"/swappable_tokens", func(w http.ResponseWriter, r *http.Request) {
		body, _ := json.Marshal(map[string]any{"servedBy": chainID})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	s.swapRoutes.Store(chainID, &swapMount{prefix: prefix, h: mux})
}

func swapServer(t *testing.T, defaultChain int64) *http.ServeMux {
	t.Helper()
	s := NewChainSupervisor(Config{DataDir: t.TempDir()})
	mountChain(s, "cchain", luxChain, router)
	mountChain(s, "zoo", zooChain, router)
	s.defaultChainID = defaultChain

	mux := http.NewServeMux()
	s.MountSwap(mux)
	return mux
}

func call(t *testing.T, mux *http.ServeMux, method, path, body string) (int, map[string]any) {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)

	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: response is not JSON: %v\n%s", method, path, err, rec.Body.String())
	}
	return rec.Code, out
}

// The whole reason the chain need not be in the path: the swap carries it.
func TestSwapDispatchesOnTheChainTheQuoteNames(t *testing.T) {
	mux := swapServer(t, luxChain)

	code, out := call(t, mux, http.MethodPost, "/v1/swap", `{"quote":{
		"chainId":96369,
		"swapper":"`+trader+`",
		"input":{"token":"0x0000000000000000000000000000000000000000","amount":"1000000000000000000"},
		"output":{"token":"`+lusd+`","amount":"611022579164403","recipient":"`+trader+`"},
		"tradeType":"EXACT_INPUT","slippage":0.5,"gasUseEstimate":"79990",
		"route":[[{"type":"v3-pool","address":"0x37011bB281676f85962fb35C674f7E9EB7584452",
			"tokenIn":{"address":"0x0000000000000000000000000000000000000000","chainId":96369,"symbol":"LUX","decimals":"18"},
			"tokenOut":{"address":"`+lusd+`","chainId":96369,"symbol":"LUSD","decimals":"18"},
			"fee":"3000","amountIn":"1000000000000000000","amountOut":"611022579164403"}]]}}`)

	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %v", code, out)
	}
	swap, ok := out["swap"].(map[string]any)
	if !ok {
		t.Fatalf("no swap in response: %v", out)
	}
	// The same bytes exchange-api returned, now reached without a chain in the path.
	want := "0x04e45aaf" +
		"0000000000000000000000004888e4a2ee0f03051c72d2bd3acf755ed3498b3e" +
		"000000000000000000000000848cff46eb323f323b6bbe1df274e40793d7f2c2" +
		"0000000000000000000000000000000000000000000000000000000000000bb8" +
		"0000000000000000000000009011e888251ab053b7bd1cdb598db4f9ded94714" +
		"0000000000000000000000000000000000000000000000000de0b6b3a7640000" +
		"000000000000000000000000000000000000000000000000000228f174dca7a4" +
		"0000000000000000000000000000000000000000000000000000000000000000"
	if swap["data"] != want {
		t.Errorf("data:\n got  %v\n want %v", swap["data"], want)
	}
	if swap["chainId"] != float64(luxChain) {
		t.Errorf("chainId = %v, want %d", swap["chainId"], luxChain)
	}
}

// Two chains are indexed here, so naming one must not reach the other.
func TestSwapDispatchesToEachChain(t *testing.T) {
	mux := swapServer(t, luxChain)
	for _, c := range []struct {
		name, method, path, body string
		want                     int64
	}{
		{"quote names lux", http.MethodPost, "/v1/quote",
			`{"tokenInChainId":96369,"tokenOutChainId":96369}`, luxChain},
		{"quote names zoo", http.MethodPost, "/v1/quote",
			`{"tokenInChainId":200200,"tokenOutChainId":200200}`, zooChain},
		{"tokens name zoo in the query", http.MethodGet,
			"/v1/swappable_tokens?chainId=200200", "", zooChain},
		{"tokens name lux as tokenInChainId", http.MethodGet,
			"/v1/swappable_tokens?tokenInChainId=96369", "", luxChain},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out := call(t, mux, c.method, c.path, c.body)
			if code != http.StatusOK {
				t.Fatalf("status = %d, want 200: %v", code, out)
			}
			if out["servedBy"] != float64(c.want) {
				t.Errorf("served by chain %v, want %d", out["servedBy"], c.want)
			}
		})
	}
}

// A form that has not settled its network yet sends no chain. Answering with
// the chain marked default is better than an error on the first render.
func TestSwapFallsBackToTheDefaultChain(t *testing.T) {
	for _, def := range []int64{luxChain, zooChain} {
		mux := swapServer(t, def)
		code, out := call(t, mux, http.MethodPost, "/v1/quote", `{"tokenIn":"0x0"}`)
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200: %v", code, out)
		}
		if out["servedBy"] != float64(def) {
			t.Errorf("default %d: served by %v", def, out["servedBy"])
		}
	}
}

// A chain this process does not index is a question it cannot answer, and
// answering from another chain's book would be worse than saying so.
func TestSwapRefusesAChainItDoesNotIndex(t *testing.T) {
	mux := swapServer(t, luxChain)
	code, out := call(t, mux, http.MethodPost, "/v1/quote", `{"tokenInChainId":1}`)
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: %v", code, out)
	}
	if out["errorCode"] != "UNKNOWN_CHAIN" {
		t.Errorf("errorCode = %v, want UNKNOWN_CHAIN", out["errorCode"])
	}
}

// The body is read once to find the chain and must arrive at the handler
// whole. A dispatcher that consumed it would leave every handler reading an
// empty request, which looks exactly like a client sending nothing.
func TestSwapBodySurvivesDispatch(t *testing.T) {
	mux := swapServer(t, luxChain)
	code, out := call(t, mux, http.MethodPost, "/v1/swap",
		`{"quote":{"chainId":96369,"swapper":"`+trader+`","route":[]}}`)
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %v", code, out)
	}
	// This detail can only come from a handler that read the route out of the body.
	if out["detail"] != "quote.route must contain at least one hop" {
		t.Errorf("detail = %v — the handler did not see the body", out["detail"])
	}
}

// A chain with no router configured serves no swap route, and the dispatcher
// must not invent one.
func TestSwapAbsentWhenChainHasNoRouter(t *testing.T) {
	s := NewChainSupervisor(Config{DataDir: t.TempDir()})
	prefix := "/v1/graph/bare/amm"
	m := http.NewServeMux()
	m.HandleFunc("POST "+prefix+"/quote", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"servedBy":1}`))
	})
	s.swapRoutes.Store(int64(1), &swapMount{prefix: prefix, h: m})
	s.defaultChainID = 1

	mux := http.NewServeMux()
	s.MountSwap(mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/swap",
		strings.NewReader(`{"quote":{"chainId":1}}`)))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when the chain serves no swap route", rec.Code)
	}
}

// servesAMM decides which subgraph's book backs a chain's swap routes. A
// non-AMM schema has no pools to price against.
func TestServesAMM(t *testing.T) {
	for _, s := range []string{"amm", "amm-v2", "uniswap-v3", "v4", "all"} {
		if !servesAMM(s) {
			t.Errorf("servesAMM(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"dex", "clob", "securities", "erc20", ""} {
		if servesAMM(s) {
			t.Errorf("servesAMM(%q) = true, want false", s)
		}
	}
}
