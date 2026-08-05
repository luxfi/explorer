# Explorer

Single-binary Lux explorer: chain indexer, GraphQL engine, and SPA frontend
in one Go process. Imports [`luxfi/indexer`](https://github.com/luxfi/indexer)
and [`luxfi/graph`](https://github.com/luxfi/graph) as libraries; embeds the
[`luxfi/explore`](https://github.com/luxfi/explore) Next.js build via
`go:embed`.

```
ghcr.io/luxfi/explorer
  -> indexes one or more EVM chains  (luxfi/indexer)
  -> exposes per-chain GraphQL       (luxfi/graph)
  -> serves embedded SPA + REST API  (luxfi/explore)
```

## Routes

| Path                                              | Purpose                          |
|---------------------------------------------------|----------------------------------|
| `/`                                               | SPA (embedded; SPA-routing fallback) |
| `/envs.js`                                        | Runtime config `window.ENV = {...}` |
| `/icon.svg`, `/logo.svg`                          | Per-host brand assets (disk override) |
| `/health`                                         | Service health                   |
| `/v1/indexer/*`                                   | Default chain explorer API       |
| `/v1/indexer/{slug}/*`                            | Per-chain explorer API           |
| `/v1/explorer/{slug}/*`                           | Legacy alias for `/v1/indexer/{slug}` |
| `/v1/graph/{slug}/{subgraph}/graphql`             | Per-chain, per-subgraph GraphQL  |
| `/v1/explorer/admin/chains[/{slug}]`              | Runtime registry CRUD            |
| `/v1/explorer/realtime`                           | WebSocket realtime hub           |
| `/v1/explorer/realtime/stats`                     | Realtime stats                   |

## Quick Start

```bash
docker run -p 8090:8090 \
  -v $(pwd)/chains.example.yaml:/etc/explorer/chains.yaml:ro \
  -v explorer-data:/data \
  ghcr.io/luxfi/explorer:latest \
  --config /etc/explorer/chains.yaml
```

Or with compose:

```bash
docker compose up
```

## Configuration

`chains.yaml` is the single source of truth. Every aspect of the deploy --
chains, branding, GraphQL subgraphs, network switcher links -- is per-chain
customizable. See [`chains.example.yaml`](chains.example.yaml) for the full
schema.

```yaml
data_dir: /data
http_addr: :8090

brand_default:
  name: Lux Explorer
  coin: LUX
  accent_color: "#5cf"

networks:
  - { label: Mainnet, domain: explorer.lux.network, chain_id: 96369 }

chains:
  - slug: cchain
    name: Lux C-Chain
    chain_id: 96369
    type: evm
    rpc: https://api.lux.network/mainnet/ext/bc/C/rpc
    coin: LUX
    enabled: true
    default: true

    indexer:
      poll_interval: 30s

    graph:
      enabled: true
      subgraphs:
        - { name: amm, schema: amm, enabled: true }

    brand:
      name: Lux C-Chain
      accent_color: "#5cf"
```

`$ENV_VAR` substitution in `rpc:` / `ws:` lets one file template every
network -- mount it read-only and inject secrets via env vars.

## Per-Network Customization

The same image powers every deploy. To rebrand for a different network:

1. Mount a different `chains.yaml`.
2. Optionally mount `icon.svg` / `logo.svg` at the path referenced by
   `chains.yaml` -- they are read from disk per-request, not embedded.
3. Set environment variables to fill the `${VAR}` placeholders.

No image rebuild needed. The SPA reads chain list and brand at runtime from
`/envs.js`.

## Runtime Registry

Chains can be added, updated, and removed at runtime without restart:

```bash
# Add
curl -X POST http://localhost:8090/v1/explorer/admin/chains \
  -H 'Content-Type: application/json' \
  -d '{"slug":"new","name":"New","chain_id":123,"rpc":"http://node:8545","type":"evm"}'

# List
curl http://localhost:8090/v1/explorer/admin/chains

# Remove
curl -X DELETE http://localhost:8090/v1/explorer/admin/chains/new
```

Adding a chain spawns its indexer + (optional) graph workers; removing
cancels them and frees the routes.

## mDNS Discovery

Set `EXPLORER_MDNS=true` to auto-register chains advertised by local Lux
nodes (`_luxd._tcp`, `_zood._tcp`, `_hanzod._tcp`, `_parsd._tcp`). The
explorer queries `info.getChains` on the discovered node and registers each
tracked chain. mDNS-sourced chains never override config-sourced entries.

## Storage Layout

```
/data/
  cchain/
    query/indexer.db         (SQLite WAL, indexer)
    {zapdb}/                 (KV store)
    graph/
      amm/graph.db           (SQLite WAL, per-subgraph)
  zoo/
    ...
```

Each chain (and each subgraph) owns an isolated SQLite + KV store. WAL is
optionally streamed to S3 with PQ encryption when `REPLICATE_S3_ENDPOINT`
is set -- see `luxfi/indexer/daemon`.

## Local Build

```bash
# Sibling layout: ~/work/lux/{indexer,graph,explorer}
cd ~/work/lux/explorer
go build -o explorer .
```

`go.mod` uses local `replace` directives pointing at `../indexer` and
`../graph`. Production CI clones all three repos into the same layout
inside the Docker build.

## Endpoints (curl examples)

```bash
curl http://localhost:8090/health
curl http://localhost:8090/v1/indexer/cchain/blocks/latest
curl -X POST http://localhost:8090/v1/graph/cchain/amm/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ swaps(first:5) { id amount0 amount1 } }"}'
```

## Related

- [`luxfi/indexer`](https://github.com/luxfi/indexer) -- chain indexer library
- [`luxfi/graph`](https://github.com/luxfi/graph) -- per-chain GraphQL library
- [`luxfi/explore`](https://github.com/luxfi/explore) -- Next.js SPA
