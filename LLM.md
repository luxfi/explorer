# explorer

**Org:** luxfi  ·  **Ecosystem:** lux  ·  **Path:** `/Users/a/work/lux/luxfi/explorer`
**Origin:** https://github.com/luxfi/explorer.git

## Discovery

This file (`CLAUDE.md`) is the canonical agent-facing readme; `LLM.md` is a symlink to it. Update either name and both stay in sync.

## Where to look first

- `README.md` — human-facing overview (if present)
- `package.json` / `Cargo.toml` / `pyproject.toml` / `go.mod` — language & deps
- `.github/workflows/` — CI surface
- `docs/` — extended docs (if present)

## Sibling repos

See the org-level `LLM.md` at `/Users/a/work/lux/luxfi/LLM.md` for the full inventory of sibling repos and inter-repo dependencies.

## Unified explorer bundle (2026-06-05)

luxfi/explorer + luxfi/graph + luxfi/explore are rolled into ONE Deployment
per env. Architecture:

- **luxfi/explorer (this repo)** — the Go binary `cmd: explorer`. Imports
  `github.com/luxfi/indexer` and `github.com/luxfi/graph` as libraries.
  Serves on `:8090`:
    /v1/indexer/{slug}/*          — Blockscout-compatible JSON API
    /v1/graph/{slug}/{subgraph}/  — GraphQL per-chain per-subgraph
    /v1/explorer/admin/*          — Runtime chain registry CRUD
    /v1/explorer/realtime         — WebSocket + SSE live feed
    /                             — Embedded SPA shim (fallback only)
  Image: `ghcr.io/luxfi/explorer:1.2.18`

- **luxfi/explore** — the Next.js SSR app (Blockscout fork). Serves the
  rich SPA at `:3000`. Runs as a **sidecar container in the same Pod**;
  shares the network namespace with the explorer Go binary so it can hit
  `http://localhost:8090` for data if needed (currently it uses the
  public `api-explore.<env>.network` host).
  Image: `ghcr.io/luxfi/explore@sha256:ddb15bc28ff38c7619bc08df9337e02b32ef886c33b9993a9b9cb3c475ad75de`

- **luxfi/graph (formerly graphd)** — NOT a separate Deployment. Linked
  into the explorer binary as a library. Per-chain GraphQL engines are
  spawned by the supervisor when `chains[].graph.enabled: true` in the
  chains.yaml ConfigMap.

The legacy `lux-indexer` Deployment (same Go `indexerd` binary, only
indexed EVM) has been **deleted**. Its routes are served by the unified
explorer Deployment.

Per env: 1 Pod, 2 containers, 1 Service exposing `:80 / :8090 / :3000`.

## Single-binary mode — zip front + Blockscout-rs in-process (cgo FFI)

The explorer can be built as ONE Go binary that runs the Blockscout-rs Rust
services IN-PROCESS (each a Tokio thread, no subprocess) and reverse-proxies to
them through `github.com/hanzoai/zip` (Fiber v3 / fasthttp) as the front router.
LEAST-WORK: the Rust services are NOT rewritten/ported — their real entrypoints
run via the `ffi/` staticlib (`lux_explorer_ffi`, crate-type staticlib) over
cgo, keeping their own HTTP servers on loopback.

- **Build:** `make single` (default `make build` / `go build ./...` is the
  Go-native binary, no cgo — `ffi_off.go` stub). Scope services with
  `make single FFI_FEATURES=sig-provider,visualizer`.
- **Front router (`front.go`):** zip owns the public listener. Routes, in order:
  `/v1/<prefix>/*` → `httputil.ReverseProxy` → `127.0.0.1:<svc_port>`
  (prefix stripped); `/*` → the existing net/http explorer mux via
  `zip.AdaptNetHTTP`. Security headers + CORS are zip middleware.
- **Config (`services:` in chains.yaml, `ServicesConfig`/`resolveServices`):**
  one source of truth for enabled services, loopback ports (base 8050,
  HTTP=base+2n/gRPC=+1), prefixes, and per-service settings JSON. The FFI
  launcher (`ffi_on.go startFFIServices`) and the proxy both read it.
- **Status:** sig-provider WIRED + PROVEN end-to-end (one process owns :8090
  and :8050; `curl /v1/sig/health → {"status":"SERVING"}`). visualizer +
  smart-contract-verifier are stateless and ready to wire (recipe in
  `ffi/README.md`). stats + multichain-aggregator stay DISABLED:
  `blockscout-service-launcher` DB layer is Postgres-only (no SQLite without a
  Rust rewrite), and stats also needs a populated Blockscout indexer Postgres.
  See `ffi/README.md` for the per-service table + exact code citations.

Manifests:
  ~/work/lux/universe/k8s/lux-mainnet/explorer.yaml
  ~/work/lux/universe/k8s/lux-mainnet/explore-ingress.yaml
  ~/work/lux/universe/k8s/lux-testnet/explorer.yaml
  ~/work/lux/universe/k8s/lux-testnet/explore-ingress.yaml
  ~/work/lux/universe/k8s/lux-devnet/explorer.yaml
  ~/work/lux/universe/k8s/lux-devnet/explore-ingress.yaml

Public URLs (all 200 OK, verified 2026-06-05):
  https://explore.lux.network              (Next.js SPA)
  https://api-explore.lux.network/v1/indexer/cchain/blocks
  https://api-explore.lux.network/v1/graph/cchain/amm/graphql
  https://explore.lux-test.network         (Next.js SPA)
  https://api-explore.lux-test.network/v1/indexer/cchain/blocks
  https://api-explore.lux-test.network/v1/graph/cchain/amm/graphql
  https://explore.lux-dev.network          (Next.js SPA)
  https://api-explore.lux-dev.network/v1/indexer/cchain/blocks
  https://api-explore.lux-dev.network/v1/graph/cchain/amm/graphql
