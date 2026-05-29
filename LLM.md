# LLM context — `luxfi/explorer`

Single-binary Lux explorer: chain indexer, per-chain GraphQL engine, and
embedded SPA served from one Go process on one HTTP listener. Imports
`luxfi/indexer` and `luxfi/graph` as libraries; embeds the
`luxfi/explore` Next.js build via `go:embed`.

## What lives here

The repo is a flat Go `package main` — no submodules, no `cmd/` tree.
Each file is one slice of the binary's behaviour:

- `main.go` — flag/env parsing, HTTP listener, route table, graceful
  shutdown. Routes are documented at the top of the file and match the
  `## Routes` section of `README.md` verbatim.
- `config.go` — `chains.yaml` loader (canonical schema).
- `registry.go` — `ChainRegistry`, the thread-safe, runtime-mutable
  chain store backing the `/v1/explorer/admin/chains` CRUD API.
- `supervisor.go` — `ChainSupervisor`, per-chain goroutine ownership
  (indexer + graph workers) plus the slug-aware route dispatcher.
- `frontend.go` — embedded SPA + runtime config (`/envs.js`) + on-disk
  brand assets (`/icon.svg`, `/logo.svg`).
- `realtime.go` — WebSocket realtime hub (`RealtimeHub`).
- `realtime_sse.go` — parallel SSE registry that shares the broadcast
  feed so EventSource clients in the bundled SPA can subscribe without
  speaking WebSocket.
- `mdns.go` — optional `_luxd._tcp` / `_zood._tcp` / `_hanzod._tcp` /
  `_parsd._tcp` discovery; mDNS-sourced chains never override
  config-sourced entries.
- `static/` — embed target; the Dockerfile populates this from a
  `luxfi/explore` build before `go build` runs. A placeholder
  `index.html` is committed so `go:embed all:static` always succeeds.
- `chains.example.yaml`, `compose.yml`, `Dockerfile` — deploy surface.

## Embedded-imports pattern

The binary is composed by library import, not by spawning subprocesses:

- `luxfi/indexer` (`evm` / `explorer` / `storage` packages) — runs the
  chain-indexer state machine in-process per chain.
- `luxfi/graph` (`engine` / `indexer` / `storage` packages) — runs the
  GraphQL engine in-process per chain, per subgraph.
- `luxfi/explore` — Next.js SPA; its static export is baked into
  `static/` at Docker-build time and served via `embed.FS`.

`go.mod` uses local `replace` directives pointing at sibling repos for
dev builds (`../indexer`, `../graph`); production CI clones all three
into the same layout inside the Docker build.

## Route strategy

One HTTP listener serves four surfaces (canonical table in `README.md`):

- `/` — SPA with SPA-routing fallback.
- `/v1/indexer/*`, `/v1/indexer/{slug}/*` — explorer REST API
  (`/v1/explorer/{slug}/*` is a legacy alias).
- `/v1/graph/{slug}/{subgraph}/graphql` — GraphQL endpoint, per-chain
  and per-subgraph.
- `/v1/explorer/admin/chains[/{slug}]` — runtime chain CRUD; mutates
  the `ChainRegistry` and triggers `ChainSupervisor` to spawn or cancel
  the per-chain workers.
- `/v1/explorer/realtime`, `/v1/explorer/realtime/stats` — the WS hub
  and its stats endpoint.

Brand assets (`/icon.svg`, `/logo.svg`) are read from disk on every
request so a deploy can swap them without rebuilding the binary; the
default SPA chunks come from the embedded filesystem.

## Realtime hub

`RealtimeHub` in `realtime.go` maintains a set of `wsClient`s, each with
its own subscription set keyed by channel string (e.g. `blocks`,
`transactions`, `blocks:cchain`). A parallel `sseRegistry`
(`realtime_sse.go`) shares the same broadcast feed so EventSource clients
in the SPA can subscribe without speaking WebSocket. The wire format is
`RealtimeMessage{Type, Chain, Data, Timestamp}`. Subscribe / unsubscribe
/ ping are handled inside the client read loop; payload schemas live in
the indexer source.

## GraphQL surface

GraphQL is per-chain and per-subgraph: `chains.yaml` lists each chain's
enabled subgraphs (e.g. `amm`), the supervisor spawns a `graph` worker
per (slug, subgraph) pair, and `engine` from `luxfi/graph` serves the
endpoint at `/v1/graph/{slug}/{subgraph}/graphql`. Subgraph schemas
themselves are owned by `luxfi/graph`, not this repo.

## Storage layout

Each chain (and each subgraph) owns an isolated SQLite-WAL plus a KV
store under `/data/{slug}/`. WAL is optionally streamed to S3 with PQ
encryption when `REPLICATE_S3_ENDPOINT` is set — replication is
implemented in `luxfi/indexer/daemon`, not here.

## Build / run quickstart

```bash
# Local dev build (expects sibling ../indexer and ../graph)
go build -o explorer .

# Production image
docker run -p 8090:8090 \
  -v $(pwd)/chains.example.yaml:/etc/explorer/chains.yaml:ro \
  -v explorer-data:/data \
  ghcr.io/luxfi/explorer:latest \
  --config /etc/explorer/chains.yaml

# Compose
docker compose up
```

Environment knobs (`HTTP_ADDR`, `DATA_DIR`, `EXPLORER_CONFIG`,
`EXPLORER_MDNS`, `REPLICATE_S3_ENDPOINT`) are parsed in `main.go`.

## Cross-refs

- `README.md` — canonical routes table, full `chains.yaml` example,
  per-network customization, mDNS, storage, curl examples.
- `luxfi/indexer` — indexer library + WAL replication daemon.
- `luxfi/graph` — per-chain GraphQL engine and subgraph schemas.
- `luxfi/explore` — Next.js SPA shipped as embedded static assets.
