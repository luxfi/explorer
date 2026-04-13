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

	// Query blockchains
	chains, err := rpcCall(base+"/ext/bc", "platform.getBlockchains", nil)
	if err != nil {
		r.registerStandardChains(base, brand)
		return
	}

	blockchains, ok := chains["blockchains"].([]any)
	if !ok {
		r.registerStandardChains(base, brand)
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
		if brand != "lux" {
			slug = brand + "-" + slug
		}

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

// knownChains maps daemon brands to their standard chain sets.
// Each daemon has different chains — not all have C/P/X.
var knownChains = map[string][]ChainConfig{
	"lux": {
		{Slug: "cchain", Name: "Lux C-Chain", Type: "evm", Default: true},
		{Slug: "pchain", Name: "Lux P-Chain", Type: "pchain"},
		{Slug: "xchain", Name: "Lux X-Chain", Type: "dag"},
	},
	"zoo": {
		{Slug: "zoo-evm", Name: "Zoo EVM", Type: "evm", Default: true},
		{Slug: "zoo-dex", Name: "Zoo DEX", Type: "evm"},
	},
	"liquid": {
		{Slug: "liquid-evm", Name: "Liquid EVM", Type: "evm", Default: true},
		{Slug: "liquid-dex", Name: "Liquid DEX", Type: "evm"},
		{Slug: "liquid-fhe", Name: "Liquid FHE", Type: "evm"},
	},
	"hanzo": {
		{Slug: "hanzo-evm", Name: "Hanzo EVM", Type: "evm", Default: true},
	},
	"pars": {
		{Slug: "pars-evm", Name: "Pars EVM", Type: "evm", Default: true},
	},
}

// registerStandardChains adds known chains for a daemon when blockchain query fails.
func (r *ChainRegistry) registerStandardChains(base, brand string) {
	chains, ok := knownChains[brand]
	if !ok {
		log.Printf("[mdns] no known chains for %s, skipping fallback", brand)
		return
	}

	for _, c := range chains {
		c.Source = "mdns"
		// Map slug to RPC path
		switch {
		case strings.HasSuffix(c.Slug, "-evm") || c.Slug == "cchain":
			c.RPC = base + "/ext/bc/C/rpc"
		case strings.HasSuffix(c.Slug, "-dex"):
			c.RPC = base + "/ext/bc/D/rpc"
		case strings.HasSuffix(c.Slug, "-fhe"):
			c.RPC = base + "/ext/bc/T/rpc"
		case c.Slug == "pchain":
			c.RPC = base + "/ext/bc/P"
		case c.Slug == "xchain":
			c.RPC = base + "/ext/bc/X"
		default:
			c.RPC = base + "/ext/bc/C/rpc"
		}
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
