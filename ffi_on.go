//go:build ffi

// Package main — FFI build variant.
//
// When built with `-tags ffi` the explorer links the Rust staticlib
// `liblux_explorer_ffi.a` (produced by `cargo build --release` in ./ffi) and
// runs the Blockscout-rs explorer services (sig-provider, and — as they are
// scaled out — smart-contract-verifier, stats, multichain-aggregator,
// visualizer) IN-PROCESS via cgo. No subprocesses, no Go rewrites: each
// service's real Rust entrypoint runs on its own Tokio runtime thread inside
// this single binary.
//
// Build:  make single        (cargo build --release in ffi/ then go build -tags ffi)
// The non-FFI fallback lives in ffi_off.go (//go:build !ffi) so a plain
// `go build ./...` compiles WITHOUT the staticlib present.
package main

/*
#cgo LDFLAGS: -L${SRCDIR}/ffi/target/release -llux_explorer_ffi
// System libraries the Rust staticlib (tokio + reqwest/curl + openssl + ring)
// transitively needs. macOS frameworks cover Security/TLS + reachability;
// resolv/c++ cover DNS + the C++ runtime pulled by curl/openssl. On Linux this
// preamble is replaced by ffi_on_linux.go's cgo line.
#cgo darwin LDFLAGS: -lresolv -lc++ -framework Security -framework CoreFoundation -framework SystemConfiguration
#cgo linux  LDFLAGS: -lresolv -lstdc++ -lm -ldl -lpthread -lssl -lcrypto

#include <stdint.h>
#include <stdlib.h>

// Mirrors the C ABI exported by ffi/src/lib.rs. Each starter spawns the named
// service on its own runtime thread and returns 0 (LUX_FFI_OK) once launched.
extern int lux_explorer_start_sig_provider(const char* config_json);
extern int lux_explorer_start_all(void);
*/
import "C"

import (
	"log"
	"unsafe"
)

// ffiEnabled is read by main.go to log which build variant is running.
const ffiEnabled = true

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

// startFFIServices launches the in-process Rust explorer services. configJSON
// keys the per-service settings (empty => upstream defaults). It is called once
// from main() at startup in the ffi build; the non-FFI build's stub is a no-op.
//
// Each starter returns immediately after spawning the service's worker thread,
// so this does not block the Go HTTP listener.
func startFFIServices(configJSON map[string]string) {
	start := func(name string, fn func(*C.char) C.int) {
		cfg := configJSON[name]
		var cstr *C.char
		if cfg != "" {
			cstr = C.CString(cfg)
			defer C.free(unsafe.Pointer(cstr))
		}
		code := fn(cstr)
		log.Printf("[ffi] start %s -> %s (%d)", name, ffiResult(code), int(code))
	}

	start("sig-provider", func(c *C.char) C.int { return C.lux_explorer_start_sig_provider(c) })
	// As services are scaled out in ffi/, add their starters here, e.g.:
	// start("stats", func(c *C.char) C.int { return C.lux_explorer_start_stats(c) })
}
