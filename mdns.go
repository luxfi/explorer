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

// StartMDNSDiscovery browses for _luxd._tcp services and auto-registers
// discovered chains. Blocks until the registry's hub context is cancelled.
func (r *ChainRegistry) StartMDNSDiscovery() {
	disc := mdns.New("_luxd._tcp", "explorer", 0,
		mdns.WithBrowseInterval(10*time.Second),
		mdns.WithStaleTimeout(60*time.Second),
	)

	disc.OnPeer(func(peer *mdns.Peer, joined bool) {
		if !joined {
			return
		}
		log.Printf("[mdns] discovered luxd at %s:%d", peer.Addr, peer.Port)
		r.probeNode(peer.Addr, peer.Port)
	})

	if err := disc.Start(); err != nil {
		log.Printf("[mdns] failed to start: %v", err)
		return
	}
	defer disc.Stop()

	// Block forever - caller runs this in a goroutine
	select {}
}

// probeNode queries a luxd node's info and blockchain endpoints,
// then registers any discovered chains.
func (r *ChainRegistry) probeNode(host string, port int) {
	base := fmt.Sprintf("http://%s:%d", host, port)

	// Query node info
	info, err := rpcCall(base+"/ext/info", "info.getNodeID", nil)
	if err != nil {
		log.Printf("[mdns] probe %s failed: %v", base, err)
		return
	}

	nodeID, _ := info["nodeID"].(string)
	log.Printf("[mdns] node %s at %s", nodeID, base)

	// Query blockchains
	chains, err := rpcCall(base+"/ext/bc", "platform.getBlockchains", nil)
	if err != nil {
		// Fallback: try standard chains
		r.registerStandardChains(base)
		return
	}

	blockchains, ok := chains["blockchains"].([]any)
	if !ok {
		r.registerStandardChains(base)
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

		slug := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
		chainType := "evm"
		if strings.Contains(vmID, "avm") {
			chainType = "dag"
		} else if strings.Contains(vmID, "platform") {
			chainType = "pchain"
		}

		r.Add(ChainConfig{
			Slug:   slug,
			Name:   name,
			RPC:    fmt.Sprintf("%s/ext/bc/%s/rpc", base, id),
			Type:   chainType,
			Source: "mdns",
		})
	}
}

// registerStandardChains adds C/P/X chains from a standard luxd node.
func (r *ChainRegistry) registerStandardChains(base string) {
	standards := []ChainConfig{
		{Slug: "cchain", Name: "C-Chain", RPC: base + "/ext/bc/C/rpc", Type: "evm", Source: "mdns", Default: true},
		{Slug: "pchain", Name: "P-Chain", RPC: base + "/ext/bc/P", Type: "pchain", Source: "mdns"},
		{Slug: "xchain", Name: "X-Chain", RPC: base + "/ext/bc/X", Type: "dag", Source: "mdns"},
	}
	for _, c := range standards {
		if err := r.Add(c); err != nil {
			log.Printf("[mdns] skip %s: %v", c.Slug, err)
		}
	}
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
