# Lux explorer — ONE build path, ONE binary.
#
# The explorer is a single Go binary that embeds the SPA, indexes chains
# (luxfi/indexer), runs per-chain GraphQL (luxfi/graph), serves realtime/admin,
# AND runs the Blockscout-rs explorer services (stats, …) IN-PROCESS via cgo.
# The zip front router (front.go) reverse-proxies /v1/<prefix>/* to them.
#
# `make` does two coherent steps, in order:
#   1. ffi-lib : cargo-build the Rust FFI staticlib (ffi/ -> liblux_explorer_ffi.a)
#                with the requested services. It carries the SINGLE C-SQLite
#                (bundled SQLCipher) that BOTH halves share.
#   2. go build : link that staticlib into the Go binary with cgo, built
#                `-tags libsqlite3` so the Go side's mattn/go-sqlite3 does NOT
#                bundle a second C-SQLite (it resolves sqlite3_* against the
#                staticlib) -> zero duplicate symbols. See ffi.go for the why.
#
# Scale services out by enabling more cargo features (see ffi/README.md):
#   make FFI_FEATURES=stats,sig-provider

BIN          ?= explorer
FFI_DIR      := ffi
FFI_LIB      := $(FFI_DIR)/target/release/liblux_explorer_ffi.a
# Cargo features = which Rust services get compiled into the staticlib. stats is
# the DB-backed default (it exercises the shared-C-SQLite link). Override on the
# CLI to scope the build.
FFI_FEATURES ?= stats

# `-tags libsqlite3` => mattn/go-sqlite3 (luxfi/indexer + luxfi/graph +
# hanzoai/sqlite) compiles its bundled amalgamation to nothing (sqlite3-binding.c
# is `#ifndef USE_LIBSQLITE3`) and resolves sqlite3_* against the staticlib's
# bundled SQLCipher. This is what makes the Go + Rust halves share ONE C-SQLite.
GO_TAGS      ?= libsqlite3

# mattn's `-tags libsqlite3` path `#include <sqlite3.h>`; point it at the
# SQLCipher header so its function decls (incl. sqlite3_load_extension /
# sqlite3_unlock_notify / sqlite3_key) match the staticlib's bundled SQLCipher
# symbols. -DSQLITE_HAS_CODEC exposes the codec (sqlite3_key) decl. This is the
# header that matches the C-SQLite the binary actually links.
SQLCIPHER_INC ?= /opt/homebrew/Cellar/sqlcipher/4.16.0/include/sqlcipher
export CGO_CFLAGS := -I$(SQLCIPHER_INC) -DSQLITE_HAS_CODEC
export CGO_ENABLED := 1

.PHONY: all build ffi-lib clean test fmt vet

all: build

# Step 1: build the Rust FFI staticlib with the requested services.
ffi-lib:
	cd $(FFI_DIR) && cargo build --release --features $(FFI_FEATURES)

# Step 2: link it into the Go binary via cgo (`-tags libsqlite3`, see above).
build: ffi-lib
	go build -tags "$(GO_TAGS)" -o $(BIN) .
	@echo "built explorer: ./$(BIN) (in-process services: $(FFI_FEATURES))"

# Vet the Go sources against the same tag/staticlib the binary links with.
vet: ffi-lib
	go vet -tags "$(GO_TAGS)" ./...

test:
	go test -tags "$(GO_TAGS)" ./...

fmt:
	go fmt ./...
	cd $(FFI_DIR) && cargo fmt

clean:
	rm -f $(BIN)
	cd $(FFI_DIR) && cargo clean
