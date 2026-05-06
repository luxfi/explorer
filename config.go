package main

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// Config is the top-level explorer configuration loaded from chains.yaml.
type Config struct {
	DataDir      string        `yaml:"data_dir"`
	HTTPAddr     string        `yaml:"http_addr"`
	BrandDefault Brand         `yaml:"brand_default"`
	Networks     []Network     `yaml:"networks"`
	Chains       []ChainConfig `yaml:"chains"`
}

// ChainConfig defines a single chain plus per-chain customization. The
// admin/registry/mdns layer also uses this shape; fields beyond Slug/Name/
// ChainID/RPC/Type/Default are optional and apply when the chain is loaded
// from a config file.
type ChainConfig struct {
	Slug       string `json:"slug"     yaml:"slug"`
	Name       string `json:"name"     yaml:"name"`
	ChainID    int64  `json:"chain_id" yaml:"chain_id"`
	Type       string `json:"type"     yaml:"type"` // evm, dag, linear, solana, bitcoin, cosmos
	RPC        string `json:"rpc"      yaml:"rpc"`
	WS         string `json:"ws"       yaml:"ws"`
	CoinSymbol string `json:"coin"     yaml:"coin"`
	Enabled    bool   `json:"enabled"  yaml:"enabled"`
	Default    bool   `json:"default"  yaml:"default"`
	Source     string `json:"source"   yaml:"-"` // config, env, mdns, admin

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
