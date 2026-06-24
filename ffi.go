// Package main — single all-in-one explorer binary.
//
// The explorer runs the Blockscout-rs explorer services (stats, and — as they
// are scaled out — sig-provider, smart-contract-verifier, multichain-aggregator,
// visualizer) IN-PROCESS via cgo. No subprocesses, no Go rewrites: each
// service's real Rust entrypoint runs on its own Tokio runtime thread inside
// this one binary, and the zip front router (front.go) reverse-proxies
// /v1/<prefix>/* to it.
//
// This is the ONE build path. `make` (and `go build`) compiles the Rust FFI
// staticlib (ffi/ -> liblux_explorer_ffi.a) first, then links it here via cgo.
// There is no build-tag variant: the single binary IS the explorer.
//
// ── The shared C SQLite (zero duplicate symbols) ──────────────────────────────
// Two halves each need a C SQLite: the Go side (mattn/go-sqlite3, pulled by
// luxfi/indexer + luxfi/graph for `sql.Open("sqlite3", …)`) and the Rust side
// (sqlx's libsqlite3-sys, used by stats' sea-orm). If BOTH bundle their own
// amalgamation, `ld` reports ~245 `duplicate symbol _sqlite3_*`.
// (luxfi/graph's optional DR path uses hanzoai/replicate's pure-Go modernc
// driver under the separate name "sqlite" — a different engine, different name,
// no collision; see supervisor.go.)
//
// They share ONE C SQLite instead:
//   - Rust: the migration crate enables libsqlite3-sys `bundled-sqlcipher` +
//     `unlock_notify`, so the staticlib carries a single, complete SQLCipher
//     amalgamation (all 283 `sqlite3_*` symbols, incl. unlock_notify +
//     load_extension that sqlx-sqlite 0.8 references and that Apple's libsqlite3
//     / Homebrew's libsqlcipher.dylib omit). libsqlite3-sys feature-unifies, so
//     every Rust consumer links these same symbols.
//   - Go: built with `-tags libsqlite3` (see Makefile), which sets
//     `-DUSE_LIBSQLITE3` so mattn compiles its bundled `sqlite3-binding.c` to
//     NOTHING and references `sqlite3_*` as external — resolved against the
//     staticlib below.
//
// Net: one definition of the SQLite C symbols (the staticlib's), shared by both
// halves -> zero duplicate symbols at the final cgo link. SQLCipher's at-rest
// codec is available to the Go driver; on Apple it uses CommonCrypto
// (SQLCIPHER_CRYPTO_CC), hence the Security/CoreFoundation frameworks below.
package main

/*
// Link the Rust staticlib that (a) exports the C-ABI service starters and
// (b) DEFINES the single C-SQLite (SQLCipher) the Go side resolves against.
#cgo LDFLAGS: -L${SRCDIR}/ffi/target/release -llux_explorer_ffi

// System libraries the Rust staticlib transitively needs:
//   * tokio + reqwest(rustls/ring) + the bundled SQLCipher amalgamation.
//   * macOS: Security + CoreFoundation back SQLCipher's CommonCrypto codec
//     (SQLCIPHER_CRYPTO_CC) AND reqwest's TLS reachability; SystemConfiguration
//     covers reachability; resolv + c++ cover DNS + the C++ runtime.
#cgo darwin LDFLAGS: -lresolv -lc++ -framework Security -framework CoreFoundation -framework SystemConfiguration
#cgo linux  LDFLAGS: -lresolv -lstdc++ -lm -ldl -lpthread

#include <stdint.h>
#include <stdlib.h>

// Mirrors the C ABI exported by ffi/src/lib.rs. Each starter spawns the named
// service on its own runtime thread and returns 0 (LUX_FFI_OK) once launched.
// EVERY service! entry is exported by the staticlib regardless of which cargo
// features were compiled in (disabled ones return LUX_FFI_ERR_DISABLED), so the
// Go binary links identically no matter the FFI_FEATURES — declare them all.
extern int lux_explorer_start_stats(const char* config_json);
extern int lux_explorer_start_sig_provider(const char* config_json);
extern int lux_explorer_start_multichain_aggregator(const char* config_json);
extern int lux_explorer_start_all(void);
*/
import "C"

import (
	"log"
	"unsafe"
)

// ffiResult maps the C return codes from ffi/src/lib.rs to human strings.
func ffiResult(code C.int) string {
	switch int(code) {
	case 0:
		return "ok"
	case 1:
		return "bad-config"
	case 2:
		return "parse-error"
	case 3:
		return "disabled"
	case 4:
		return "spawn-error"
	default:
		return "unknown"
	}
}

// ffiStarters maps an FFI service name to its C entrypoint. Adding a service is
// one line here plus its service!{…} block in ffi/src/lib.rs and its
// dep+feature in ffi/Cargo.toml (see ffi/README.md). Disabled services still
// export their symbol and return LUX_FFI_ERR_DISABLED, so this table can list
// every service unconditionally — the binary links identically regardless of
// which cargo features were compiled into the staticlib.
var ffiStarters = map[string]func(*C.char) C.int{
	"stats":                 func(c *C.char) C.int { return C.lux_explorer_start_stats(c) },
	"sig-provider":          func(c *C.char) C.int { return C.lux_explorer_start_sig_provider(c) },
	"multichain-aggregator": func(c *C.char) C.int { return C.lux_explorer_start_multichain_aggregator(c) },
	// Scale-out (uncomment as the matching service!{…} is enabled in ffi/):
	// "smart-contract-verifier": func(c *C.char) C.int { return C.lux_explorer_start_smart_contract_verifier(c) },
	// "visualizer":              func(c *C.char) C.int { return C.lux_explorer_start_visualizer(c) },
}

// startFFIServices launches each resolved in-process Rust service by calling its
// C entrypoint with the settings JSON resolveServices rendered (server
// addr/port + optional DB url). Called once from main() at startup.
//
// Each starter returns immediately after spawning the service's worker thread,
// so this does not block the zip HTTP listener.
func startFFIServices(svcs []resolvedService) {
	for _, s := range svcs {
		fn, ok := ffiStarters[s.Name]
		if !ok {
			log.Printf("[ffi] no entrypoint for service %q (rebuild ffi with its feature?)", s.Name)
			continue
		}
		var cstr *C.char
		if s.SettingsJSON != "" {
			cstr = C.CString(s.SettingsJSON)
		}
		code := fn(cstr)
		if cstr != nil {
			C.free(unsafe.Pointer(cstr))
		}
		log.Printf("[ffi] start %s on :%d -> %s (%d)", s.Name, s.HTTPPort, ffiResult(code), int(code))
	}
}
