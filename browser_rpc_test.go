package main

import "testing"

// The SPA was being handed the address the SERVER dials. In-cluster that is a
// service-mesh name, so every browser hitting explore.lux.network got
// http://luxd-headless.lux-mainnet.svc.cluster.local:9630/v1/bc/C/rpc — a host
// it cannot resolve. RPC (what we dial) and the browser's RPC are two different
// values; this pins them apart.
func TestBrowserRPC(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   ChainConfig
		want string
	}{{
		name: "cluster-internal RPC is never handed to a browser",
		in:   ChainConfig{RPC: "http://luxd-headless.lux-mainnet.svc.cluster.local:9630/v1/bc/C/rpc"},
		want: "",
	}, {
		name: "explicit public_rpc wins",
		in: ChainConfig{
			RPC:       "http://luxd-headless.lux-mainnet.svc.cluster.local:9630/v1/bc/C/rpc",
			PublicRPC: "https://api.lux.network/v1/bc/C/rpc",
		},
		want: "https://api.lux.network/v1/bc/C/rpc",
	}, {
		name: "already-public RPC passes through unchanged",
		in:   ChainConfig{RPC: "https://api.zoo.ngo/v1/bc/C/rpc"},
		want: "https://api.zoo.ngo/v1/bc/C/rpc",
	}, {
		name: "bare service name is not public",
		in:   ChainConfig{RPC: "http://luxd-headless:9630/v1/bc/C/rpc"},
		want: "",
	}, {
		name: "loopback is not public",
		in:   ChainConfig{RPC: "http://127.0.0.1:9630/v1/bc/C/rpc"},
		want: "",
	}, {
		name: "RFC1918 literal is not public",
		in:   ChainConfig{RPC: "http://10.150.2.1:9630/v1/bc/C/rpc"},
		want: "",
	}, {
		name: "empty stays empty",
		in:   ChainConfig{},
		want: "",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := browserRPC(tc.in); got != tc.want {
				t.Fatalf("browserRPC() = %q, want %q", got, tc.want)
			}
		})
	}
}
