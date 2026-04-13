package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/luxfi/mdns"
)

// daemonService maps mDNS service types to their daemon info.
var daemonServices = []struct {
	Service string // mDNS service type
	Name    string // daemon name for logs
	Brand   string // brand prefix for chain slugs
}{
	{"_luxd._tcp", "luxd", "lux"},
	{"_zood._tcp", "zood", "zoo"},
	{"_lqd._tcp", "lqd", "liquid"},
	{"_hanzod._tcp", "hanzod", "hanzo"},
	{"_parsd._tcp", "parsd", "pars"},
}

// StartMDNSDiscovery browses for all known daemon types and auto-registers
// discovered chains. Blocks until the registry's hub context is cancelled.
func (r *ChainRegistry) StartMDNSDiscovery() {
	var discs []*mdns.Discovery

	for _, svc := range daemonServices {
		svc := svc // capture
		disc := mdns.New(svc.Service, "explorer", 0,
			mdns.WithBrowseInterval(10*time.Second),
			mdns.WithStaleTimeout(60*time.Second),
		)

		disc.OnPeer(func(peer *mdns.Peer, joined bool) {
			if !joined {
				return
			}
			log.Printf("[mdns] discovered %s at %s:%d", svc.Name, peer.Addr, peer.Port)
			r.probeNode(peer.Addr, peer.Port, svc.Brand)
		})

		if err := disc.Start(); err != nil {
			log.Printf("[mdns] %s: failed to start: %v", svc.Service, err)
			continue
		}
		discs = append(discs, disc)
	}

	log.Printf("[mdns] browsing for %d daemon types", len(discs))

	// Block forever - caller runs this in a goroutine
	select {}
}

// probeNode queries a node's info and blockchain endpoints,
// then registers any discovered chains. Brand prefixes slugs for non-lux daemons.
func (r *ChainRegistry) probeNode(host string, port int, brand string) {
	base := fmt.Sprintf("http://%s:%d", host, port)

	// Query node info
	info, err := rpcCall(base+"/ext/info", "info.getNodeID", nil)
	if err != nil {
		log.Printf("[mdns] probe %s failed: %v", base, err)
		return
	}

	nodeID, _ := info["nodeID"].(string)
	log.Printf("[mdns] %s node %s at %s", brand, nodeID, base)

	// Use info.getChains — returns ONLY chains this node is actively tracking.
	// One RPC call, no probing. Added in luxd v1.24.28+.
	chains, err := rpcCall(base+"/ext/info", "info.getChains", nil)
	if err != nil {
		// Fallback: older nodes without info.getChains — probe each chain
		log.Printf("[mdns] %s: info.getChains not available, falling back to platform probe", base)
		r.probeNodeLegacy(base, brand)
		return
	}

	chainList, ok := chains["chains"].([]any)
	if !ok {
		log.Printf("[mdns] %s: unexpected getChains response", base)
		return
	}

	for _, c := range chainList {
		cMap, ok := c.(map[string]any)
		if !ok {
			continue
		}
		name, _ := cMap["name"].(string)
		id, _ := cMap["id"].(string)
		vmID, _ := cMap["vmID"].(string)

		if id == "" {
			continue
		}
		if name == "" {
			name = id[:8]
		}

		slug := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
		if brand != "lux" {
			slug = brand + "-" + slug
		}

		chainType := inferChainType(vmID, name)
		isDefault := !r.HasDefault()

		r.Add(ChainConfig{
			Slug:    slug,
			Name:    name,
			RPC:     fmt.Sprintf("%s/ext/bc/%s/rpc", base, id),
			Type:    chainType,
			Source:  "mdns",
			Default: isDefault,
		})
		log.Printf("[mdns] %s: registered %s (%s)", brand, slug, chainType)
	}
}

// probeNodeLegacy uses platform.getBlockchains + per-chain RPC probe for older nodes
// that don't support info.getChains.
func (r *ChainRegistry) probeNodeLegacy(base, brand string) {
	chains, err := rpcCall(base+"/ext/bc/P", "platform.getBlockchains", nil)
	if err != nil {
		log.Printf("[mdns] %s: cannot query platform either, giving up", base)
		return
	}

	blockchains, ok := chains["blockchains"].([]any)
	if !ok {
		return
	}

	for _, bc := range blockchains {
		bcMap, ok := bc.(map[string]any)
		if !ok {
			continue
		}
		name, _ := bcMap["name"].(string)
		id, _ := bcMap["id"].(string)
		vmID, _ := bcMap["vmID"].(string)
		if name == "" || id == "" {
			continue
		}

		rpcURL := fmt.Sprintf("%s/ext/bc/%s/rpc", base, id)
		if !probeRPC(rpcURL) {
			continue
		}

		slug := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
		if brand != "lux" {
			slug = brand + "-" + slug
		}

		r.Add(ChainConfig{
			Slug:    slug,
			Name:    name,
			RPC:     rpcURL,
			Type:    inferChainType(vmID, name),
			Source:  "mdns",
			Default: !r.HasDefault(),
		})
		log.Printf("[mdns] %s: registered %s (legacy probe)", brand, slug)
	}
}

// probeRPC checks if a chain's RPC endpoint is actually available on this node.
// Returns true if the endpoint responds (even with an error result — that means the
// chain is tracked). Returns false if connection refused or timeout (not tracked).
func probeRPC(rpcURL string) bool {
	client := &http.Client{Timeout: 2 * time.Second}
	body := `{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}`
	resp, err := client.Post(rpcURL, "application/json", strings.NewReader(body))
	if err != nil {
		return false
	}
	resp.Body.Close()
	// Any HTTP response means the chain is tracked — even 400/500 means the
	// endpoint exists. Only connection failure means not tracked.
	return true
}

// inferChainType determines chain type from the VM ID and chain name reported by the node.
// No hardcoded chain lists — this only classifies what the node already told us.
func inferChainType(vmID, name string) string {
	lower := strings.ToLower(vmID + " " + name)
	switch {
	case strings.Contains(lower, "platform"):
		return "pchain"
	case strings.Contains(lower, "avm") || strings.Contains(lower, "x-chain"):
		return "dag"
	default:
		return "evm"
	}
}

// HasDefault returns true if any chain is marked as default.
func (r *ChainRegistry) HasDefault() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.chains {
		if e.Config.Default {
			return true
		}
	}
	return false
}

// rpcCall makes a JSON-RPC call and returns the result map.
func rpcCall(url, method string, params any) (map[string]any, error) {
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
	}
	if params != nil {
		body["params"] = params
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(url, "application/json", strings.NewReader(string(encoded)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Result map[string]any `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	if result.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", result.Error.Message)
	}
	return result.Result, nil
}
