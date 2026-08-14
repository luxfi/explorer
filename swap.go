package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/luxfi/graph/engine"
)

// The swap form's routes, without a chain in the path.
//
// A swap request already says which chain it is for — the quote body names the
// chain of each token, an approval names its chain, a swap carries the quote it
// came from. Putting the chain in the path as well gives the same fact two
// homes, and the one the client fills in from its network selector is the one
// that is right. So these routes read the chain out of the request and hand it
// to the same handlers /v1/graph/{chain}/{subgraph}/ already publishes.
//
// Nothing is re-implemented here. The mount holds the very mux those routes are
// registered on; this only works out which chain's mux, and asks it the
// question under the path it knows.

// swapMount is one chain's swap routes: the mux they are registered on and the
// prefix they are registered under.
type swapMount struct {
	prefix string
	h      http.Handler
}

// swapPaths are the routes served both ways. The unprefixed form is what the
// swap form calls; the prefixed form is where the handler is registered.
//
// /v1/graphql reaches the engine's own schema, which resolves subgraph fields —
// pools, pairs, tokens, swaps, bundles, factories. Uniswap's data-api names
// (topTokens, topV2Pairs, tokenProjects and their siblings) are a different
// vocabulary and are not resolved here; a client that asks for one gets
// "unknown field". Point a caller at this route once it speaks the schema.
var swapPaths = []struct {
	method, path string
}{
	{http.MethodPost, "/v1/quote"},
	{http.MethodGet, "/v1/swappable_tokens"},
	{http.MethodPost, "/v1/swap"},
	{http.MethodPost, "/v1/check_approval"},
	{http.MethodPost, "/v1/graphql"},
}

// MountSwap installs the unprefixed swap routes.
func (s *ChainSupervisor) MountSwap(mux *http.ServeMux) {
	for _, r := range swapPaths {
		mux.HandleFunc(r.method+" "+r.path, s.dispatchSwap)
	}
}

// canSwap reports whether a chain can build a swap at all. Both addresses are
// rendered into a twenty-byte argument — the router the transaction is
// addressed to, and the wrapped native a route substitutes for the coin — so
// anything else produces a call whose arguments have slid.
func canSwap(cfg ChainConfig) bool {
	return cfg.ChainID != 0 && engine.IsAddress(cfg.Router) && engine.IsAddress(cfg.Native)
}

// firstAMM names the subgraph whose book backs a chain's swap routes: the
// earliest enabled one in the config that loads AMM resolvers. Reading it off
// the config makes the choice the operator's and the same on every restart,
// where letting the goroutines race would make it the scheduler's.
func firstAMM(cfg ChainConfig) string {
	if !cfg.Graph.Enabled {
		return ""
	}
	for _, sg := range cfg.Graph.Subgraphs {
		if sg.Enabled && servesAMM(schemaOf(sg)) {
			return sg.Name
		}
	}
	return ""
}

// schemaOf is the schema a subgraph loads, defaulting the way runSubgraph does.
func schemaOf(sg Subgraph) string {
	if sg.Schema == "" {
		return "amm"
	}
	return sg.Schema
}

// servesAMM reports whether a schema name loads the AMM resolvers — the pools
// a quote is priced over. A chain's swap routes come from the subgraph that
// holds its book, not from whichever subgraph happened to start first.
func servesAMM(schema string) bool {
	switch schema {
	case "amm", "amm-v2", "uniswap-v2", "amm-v3", "uniswap-v3", "amm-v4", "uniswap-v4", "v4", "all":
		return true
	}
	return false
}

// dispatchSwap sends a request to the chain it names.
func (s *ChainSupervisor) dispatchSwap(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		// Say which failure it was. A body too long to read is not a body that
		// failed to parse, and telling someone their JSON is malformed when it
		// is merely large sends them looking in the wrong place.
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeSwapError(w, http.StatusRequestEntityTooLarge, "VALIDATION_ERROR",
				"body must be under "+strconv.Itoa(bodyLimit>>10)+"KB")
			return
		}
		writeSwapError(w, http.StatusBadRequest, "VALIDATION_ERROR", "body could not be read")
		return
	}

	id := chainOf(r, body)
	if id == 0 {
		s.mu.Lock()
		id = s.defaultChainID
		s.mu.Unlock()
	}
	mount, ok := s.swapRoutes.Load(id)
	if !ok {
		writeSwapError(w, http.StatusNotFound, "UNKNOWN_CHAIN",
			"no chain "+strconv.FormatInt(id, 10)+" is indexed here")
		return
	}
	m := mount.(*swapMount)

	// Ask the mux under the path the handler is registered at. The body was
	// consumed to find the chain, so it goes back as it arrived.
	r2 := r.Clone(r.Context())
	r2.URL.Path = m.prefix + strings.TrimPrefix(r.URL.Path, "/v1")
	r2.Body = io.NopCloser(bytes.NewReader(body))
	r2.ContentLength = int64(len(body))
	m.h.ServeHTTP(w, r2)
}

// readBody takes the whole body so it can be read twice: once to find the
// chain, once by the handler.
//
// The limit is the handlers' own. Buffering more than they will read means
// holding a request nobody can answer, and the reading happens here first.
const bodyLimit = 1 << 20

func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	return io.ReadAll(http.MaxBytesReader(nil, r.Body, bodyLimit))
}

// chainOf finds the chain a request names, or 0 when it names none.
//
// The field differs by route because each was designed around its own question
// — a quote names the chain of each token, an approval names one chain, a swap
// carries the quote it came from. They are all the same fact, so they are read
// in one place instead of once per handler.
//
// The order is narrowest first. A quote states the chain it was priced on, and
// that is the chain the swap must be built for — a sibling key alongside it, or
// a query parameter, would otherwise send someone's quote to another chain's
// router. The query is read last because a body says more than a URL does, and
// only a GET has nothing else to say.
func chainOf(r *http.Request, body []byte) int64 {
	var b struct {
		ChainID         *int64 `json:"chainId"`
		TokenInChainID  *int64 `json:"tokenInChainId"`
		TokenOutChainID *int64 `json:"tokenOutChainId"`
		Quote           *struct {
			ChainID *int64 `json:"chainId"`
		} `json:"quote"`
	}
	if len(body) > 0 && json.Unmarshal(body, &b) == nil {
		if b.Quote != nil && b.Quote.ChainID != nil && *b.Quote.ChainID != 0 {
			return *b.Quote.ChainID
		}
		for _, v := range []*int64{b.ChainID, b.TokenInChainID, b.TokenOutChainID} {
			if v != nil && *v != 0 {
				return *v
			}
		}
	}
	for _, k := range []string{"chainId", "tokenInChainId", "tokenOutChainId"} {
		if v := r.URL.Query().Get(k); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				return n
			}
		}
	}
	return 0
}

func writeSwapError(w http.ResponseWriter, code int, errorCode, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"errorCode": errorCode, "detail": detail})
}
