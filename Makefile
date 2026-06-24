# Lux explorer build.
#
# Two binaries from one source tree, selected by the `ffi` build tag:
#
#   make build    Default Go-native explorer (indexer + graph + SPA + realtime).
#                 No Rust, no cgo. This is what `go build ./...` produces.
#
#   make single   THE single all-in-one binary: builds the Rust FFI staticlib
#                 (ffi/ -> liblux_explorer_ffi.a) then links it into the Go
#                 binary with cgo (-tags ffi), so the Blockscout-rs services
#                 (sig-provider, …) run IN-PROCESS. One binary runs everything.
#
# Scale services out by enabling more cargo features (see ffi/README.md):
#   make single FFI_FEATURES=sig-provider,stats,visualizer

BIN        ?= explorer
FFI_DIR    := ffi
FFI_LIB    := $(FFI_DIR)/target/release/liblux_explorer_ffi.a
# Cargo features = which Rust services get compiled into the staticlib.
# `all` = every wired service. Override on the CLI to scope the build.
FFI_FEATURES ?= all

.PHONY: build single ffi-lib clean test fmt

build:
	go build -o $(BIN) .

# Step 1: build the Rust staticlib with the requested services.
ffi-lib:
	cd $(FFI_DIR) && cargo build --release --features $(FFI_FEATURES)

# Step 2: link it into the Go binary via cgo. The -tags ffi build compiles
# ffi_on.go (cgo preamble + extern decls) instead of the ffi_off.go stub.
single: ffi-lib
	go build -tags ffi -o $(BIN) .
	@echo "built single all-in-one binary: ./$(BIN) (features: $(FFI_FEATURES))"

test:
	go test ./...

fmt:
	go fmt ./...
	cd $(FFI_DIR) && cargo fmt

clean:
	rm -f $(BIN)
	cd $(FFI_DIR) && cargo clean
