//go:build !ffi

// Package main — non-FFI build variant (the default).
//
// A plain `go build ./...` compiles this file and NOT ffi_on.go, so the
// explorer builds and runs WITHOUT the Rust staticlib present. The Blockscout-rs
// services are simply not started; everything else (Go-native indexer + graph +
// SPA + realtime) works exactly as before. Build the single all-in-one binary
// with `make single` (which adds -tags ffi and links liblux_explorer_ffi.a).
package main

// ffiEnabled is false in the default build; main.go logs this so it is obvious
// which variant is running.
const ffiEnabled = false

// startFFIServices is a no-op in the non-FFI build.
func startFFIServices(_ map[string]string) {}
