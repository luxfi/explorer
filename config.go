package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level explorer configuration loaded from chains.yaml.
type Config struct {
	DataDir      string        `yaml:"data_dir"`
	HTTPAddr     string        `yaml:"http_addr"`
	StaticDir    string        `yaml:"static_dir"` // overlay dir for SPA; empty = embedded only
	BrandDefault Brand         `yaml:"brand_default"`
	Networks     []Network     `yaml:"networks"`
	Chains       []ChainConfig `yaml:"chains"`
}

// ChainConfig defines a single chain plus per-chain customization. The
// admin/registry/mdns layer also uses this shape; fields beyond Slug/Name/
// ChainID/RPC/Type/Default are optional and apply when the chain is loaded
// from a config file.
type ChainConfig struct {
	Slug    string `json:"slug"         yaml:"slug"`
	Name    string `json:"name"         yaml:"name"`
	ChainID int64  `json:"chain_id"     yaml:"chain_id"`
	Type    string `json:"type"         yaml:"type"` // evm, dag, linear, solana, bitcoin, cosmos
	// RPC is the address THIS PROCESS dials. In-cluster that is normally a
	// service-mesh name (luxd-headless.lux-mainnet.svc.cluster.local:9630),
	// which is correct for the indexer and USELESS to a browser.
	RPC string `json:"rpc"          yaml:"rpc"`
	// PublicRPC is what the browser is told to use. Split from RPC because the
	// two have opposite requirements and one field cannot satisfy both: the
	// SPA was being handed `http://luxd-headless…svc.cluster.local:9630/...`,
	// which no browser can resolve, so every wallet/network action against the
	// default chain failed. Leave empty when RPC is already public — see
	// browserReachable() in frontend.go, which falls back to RPC in that case.
	PublicRPC   string `json:"public_rpc,omitempty" yaml:"public_rpc,omitempty"`
	WS          string `json:"ws"           yaml:"ws"`
	CoinSymbol  string `json:"coin"         yaml:"coin"`
	PoolManager string `json:"pool_manager" yaml:"pool_manager"` // DEX settlement precompile (0x9999); empty => indexer default
	// FactoryV2 and FactoryV3 are this chain's canonical AMM factories, and
	// Native its wrapped native token. Each is an identity of THIS chain, so
	// each is declared per chain: one process indexes six chains, and a chain
	// that omitted them used to inherit Lux mainnet's — which served Lux's
	// pools, priced in Lux's coin, under a neighbouring chain's slug. Omit them
	// and the chain indexes no AMM, which is the honest answer.
	FactoryV2 string `json:"factory_v2" yaml:"factory_v2"`
	FactoryV3 string `json:"factory_v3" yaml:"factory_v3"`
	Native    string `json:"native"     yaml:"native"`
	// QuoterV2 is this chain's V3 periphery quoter. A quote off the indexed
	// book is exact for V2 (constant product, closed form) and only an estimate
	// for V3, where the answer depends on which ticks the trade crosses. With
	// this set, a V3 route is priced by the chain itself; without it, the
	// quote falls back to the closed form and says so. Per chain, like the
	// factories, because it is deployed per chain.
	QuoterV2 string `json:"quoter_v2" yaml:"quoter_v2"`
	// Router is this chain's V3 periphery SwapRouter02 — the contract a swap
	// is addressed to, and the contract an approval grants. One field, because
	// the two must name the same address or the grant is spent on nothing.
	Router string `json:"router" yaml:"router"`
	// GenesisSupply is every native unit minted at block 0, in whole tokens —
	// "2000000000000" for Lux and for Zoo. Fixed at genesis and not exposed
	// over RPC, so it is declared here beside the factory addresses.
	GenesisSupply string `json:"genesis_supply" yaml:"genesis_supply"`
	// Treasury holds what has not been distributed yet; its balance is read
	// live and subtracted from the mint to get circulating supply.
	Treasury string `json:"treasury" yaml:"treasury"`
	// Enabled gates the chain entirely: a disabled chain is never registered,
	// so it is not indexed, mounts no routes, and does not reach the SPA's
	// chain list. See ChainRegistry.Add, the single place it is honoured.
	//
	// A pointer, so absent and false are distinguishable. Absent means ON —
	// every config predating this field wrote `enabled: true` by convention
	// while the field was inert, and a plain bool would read a future config
	// that simply omits the key as "off" and make the chain vanish with no
	// error. Nil is no opinion; only an explicit `enabled: false` disables.
	Enabled *bool  `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Default bool   `json:"default"      yaml:"default"`
	Source  string `json:"source"       yaml:"-"` // config, env, mdns, admin

	Indexer IndexerSettings `json:"indexer,omitempty" yaml:"indexer,omitempty"`
	Graph   GraphSettings   `json:"graph,omitempty"   yaml:"graph,omitempty"`
	Brand   *Brand          `json:"brand,omitempty"   yaml:"brand,omitempty"`
	Tokens  TokensFeatures  `json:"tokens,omitempty"  yaml:"tokens,omitempty"`
}

// IndexerSettings overrides indexer behaviour for a single chain.
type IndexerSettings struct {
	PollInterval string `yaml:"poll_interval" json:"poll_interval,omitempty"` // e.g. "30s"
	StartBlock   uint64 `yaml:"start_block"   json:"start_block,omitempty"`
}

// GraphSettings configures per-chain GraphQL subgraphs.
type GraphSettings struct {
	Enabled   bool       `yaml:"enabled"   json:"enabled"`
	Subgraphs []Subgraph `yaml:"subgraphs" json:"subgraphs,omitempty"`
}

// Subgraph mounts a single named GraphQL schema under
// /v1/graph/{chain-slug}/{subgraph-name}/. Schema is either a built-in name
// understood by github.com/luxfi/graph/engine.LoadBuiltin (amm, uniswap-v2,
// uniswap-v3, uniswap-v4, securities, fhe, etc.) or a path to a .graphql file.
type Subgraph struct {
	Name    string `yaml:"name"    json:"name"`
	Schema  string `yaml:"schema"  json:"schema"`
	Enabled bool   `yaml:"enabled" json:"enabled"`
}

// Brand is the per-chain (or default) UI branding shown by the SPA. Icon/Logo
// files are read from disk on every request so a deploy can swap them without
// rebuilding the binary.
type Brand struct {
	Name        string `yaml:"name"         json:"name,omitempty"`
	Coin        string `yaml:"coin"         json:"coin,omitempty"`
	AccentColor string `yaml:"accent_color" json:"accentColor,omitempty"`
	IconFile    string `yaml:"icon_file"    json:"-"`
	LogoFile    string `yaml:"logo_file"    json:"-"`
	IconURL     string `yaml:"icon_url"     json:"iconUrl,omitempty"`
	LogoURL     string `yaml:"logo_url"     json:"logoUrl,omitempty"`
}

// TokensFeatures controls which tokens the SPA highlights or hides.
type TokensFeatures struct {
	Featured  []string `yaml:"featured"   json:"featured,omitempty"`
	AllowList []string `yaml:"allow_list" json:"allowList,omitempty"`
	BlockList []string `yaml:"block_list" json:"blockList,omitempty"`
}

// Network is a peer explorer the SPA can link to in its network switcher.
type Network struct {
	Label   string `yaml:"label"    json:"label"`
	Domain  string `yaml:"domain"   json:"domain"`
	ChainID int64  `yaml:"chain_id" json:"chainId"`
}

// On reports whether the chain should run. Absent means on; only an explicit
// `enabled: false` turns a chain off.
func (c ChainConfig) On() bool { return c.Enabled == nil || *c.Enabled }

// Chain reports the first configured chain whose slug the request host spells
// out. Matches these hostname shapes, in order of specificity:
//
//	"{slug}"                             — bare slug (curl localhost)
//	"{slug}.tld..."                      — zoo.lux.network, hanzo.ai
//	"explore-{slug}.tld..."              — explore-hanzo.lux.network
//	"explorer-{slug}.tld..."             — explorer-hanzo.lux.network
//	"api-explore-{slug}.tld..."          — api-explore-hanzo.lux.network
//	"explore.{slug}.tld..."              — explore.hanzo.ai, explore.zoo.ngo
//	"explorer.{slug}.tld..."             — explorer.hanzo.ai, explorer.zoo.network
//	"api-explore.{slug}.tld..."          — api-explore.hanzo.ai
//	"explore-{slug}-{env}.tld..."        — explore-hanzo-test.lux.network
//	"explorer-{slug}-{env}.tld..."       — explorer-hanzo-test.lux.network
//	"api-explore-{slug}-{env}.tld..."    — api-explore-hanzo-dev.lux.network
//	"explore.{slug}-{env}.tld..."        — explore.zoo-test.network
//	"explorer.{slug}-{env}.tld..."       — explorer.zoo-test.network
//	"api-explore.{slug}-{env}.tld..."    — api-explore.zoo-test.network
//
// First chain match wins on ambiguous hosts.
func (c Config) Chain(host string) (ChainConfig, bool) {
	host = strings.ToLower(strings.SplitN(host, ":", 2)[0])
	for _, ch := range c.Chains {
		if hostMatchesSlug(host, ch.Slug) {
			return ch, true
		}
	}
	return ChainConfig{}, false
}

// Serves returns the chain a request on host is answered from: the chain the
// host names, else the chain marked default, else the first configured chain.
//
// One binary answers every brand host, so this is the only thing that decides
// which chain a request is about. Any surface that reads chain data and does
// not ask — a stats aggregate pinned at startup, a realtime stream with no
// filter — reports the default chain's numbers to all five brands, which is
// how Hanzo's home page came to print Lux's block total above Hanzo's own
// block heights.
func (c Config) Serves(host string) ChainConfig {
	if ch, ok := c.Chain(host); ok {
		return ch
	}
	for _, ch := range c.Chains {
		if ch.Default {
			return ch
		}
	}
	if len(c.Chains) > 0 {
		return c.Chains[0]
	}
	return ChainConfig{}
}

// hostMatchesSlug is the pure string predicate for chain↔host matching.
// Kept separate from Chain so unit tests can cover it directly.
func hostMatchesSlug(host, slug string) bool {
	if slug == "" {
		return false
	}
	if host == slug {
		return true
	}
	// Direct slug-as-subdomain: zoo.lux.network, hanzo.ai.
	if strings.HasPrefix(host, slug+".") || strings.HasPrefix(host, slug+"-") {
		return true
	}
	// Brand-owned domains: explore.zoo.network, explorer.zoo-test.network,
	// api-explore.zoo.ngo, etc. Each "explore"/"explorer" prefix combines
	// with "." or "-" as the slug separator.
	prefixes := []string{
		"explore-", "explorer-",
		"api-explore-", "api-explorer-",
		"explore.", "explorer.",
		"api-explore.", "api-explorer.",
	}
	for _, p := range prefixes {
		// {prefix}{slug}.tld  — e.g. explore.zoo.network, explore-zoo.lux.network
		if strings.HasPrefix(host, p+slug+".") {
			return true
		}
		// {prefix}{slug}-{env}.tld — e.g. explore-zoo-test.lux.network,
		// explorer.zoo-test.network
		if strings.HasPrefix(host, p+slug+"-") {
			return true
		}
	}
	return false
}

// slugPattern restricts chain slugs to lowercase alphanumeric + hyphen so they
// remain safe in URL routes (/v1/indexer/{slug}/) and filesystem paths.
var slugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// LoadConfig reads chains.yaml, expands $ENV_VAR in RPC/WS, and validates slugs.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	for i := range cfg.Chains {
		cfg.Chains[i].RPC = os.Expand(cfg.Chains[i].RPC, os.Getenv)
		cfg.Chains[i].WS = os.Expand(cfg.Chains[i].WS, os.Getenv)
		if !slugPattern.MatchString(cfg.Chains[i].Slug) {
			return Config{}, fmt.Errorf("chain[%d]: invalid slug %q", i, cfg.Chains[i].Slug)
		}
	}
	return cfg, nil
}
