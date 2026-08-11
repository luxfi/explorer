package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Each chain carries its own AMM factories and native token, and a chain that
// names none gets none. The failure this guards is silent: the zoo subgraph
// answered with Lux's factory, so zoo.exchange served Lux's pools as Zoo's.
func TestChainsDeclareTheirOwnAMM(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chains.yaml")
	if err := os.WriteFile(path, []byte(`
chains:
  - slug: cchain
    chain_id: 96369
    factory_v2: "0xD173926A10A0C4eCd3A51B1422270b65Df0551c1"
    factory_v3: "0x80bBc7C4C7a59C899D1B37BC14539A22D5830a84"
    native: "0x4888E4a2Ee0F03051c72D2BD3ACf755eD3498B3E"
  - slug: zoo
    chain_id: 200200
    factory_v3: "0x9378b62fC172d2A4f715d7ecF49DE0362f1BB702"
    native: "0xc65ea8882020Af7CDa7854d590C6Fcd34BF364ec"
  - slug: pars
    chain_id: 494949
`), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	byslug := map[string]ChainConfig{}
	for _, c := range cfg.Chains {
		byslug[c.Slug] = c
	}

	if got := byslug["cchain"].FactoryV3; got != "0x80bBc7C4C7a59C899D1B37BC14539A22D5830a84" {
		t.Errorf("cchain factory_v3 = %q", got)
	}
	if got := byslug["zoo"].FactoryV3; got != "0x9378b62fC172d2A4f715d7ecF49DE0362f1BB702" {
		t.Errorf("zoo factory_v3 = %q", got)
	}
	if got := byslug["zoo"].Native; got != "0xc65ea8882020Af7CDa7854d590C6Fcd34BF364ec" {
		t.Errorf("zoo native = %q", got)
	}
	// Zoo has no V2 AMM, and pars declares nothing at all. Neither may end up
	// holding a neighbour's address.
	if got := byslug["zoo"].FactoryV2; got != "" {
		t.Errorf("zoo has no V2 AMM, got factory_v2 = %q", got)
	}
	if c := byslug["pars"]; c.FactoryV2 != "" || c.FactoryV3 != "" || c.Native != "" {
		t.Errorf("an undeclared chain must stay undeclared, got %+v", c)
	}
}
