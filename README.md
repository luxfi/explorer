# Explorer

Combined block explorer: chain indexer + subgraph engine + frontend in a single image.

```
ghcr.io/luxfi/indexer   ← chain data: blocks, txs, tokens, contracts (SQLite)
ghcr.io/luxfi/graph     ← subgraph events: swaps, pools, DeFi, GraphQL (SQLite)
ghcr.io/luxfi/explore   ← Next.js frontend
ghcr.io/luxfi/explorer  ← all three combined (this image)
```

Each component runs standalone for independent scaling, or together in one container.

## Run

```bash
# Combined (default) — indexes chain + subgraphs, serves API + frontend
docker run -p 8090:8090 \
  -e RPC_ENDPOINT=http://node:9650/ext/bc/C/rpc \
  -v data:/data \
  ghcr.io/luxfi/explorer

# Just the indexer (chain data API only)
docker run -p 8090:8090 \
  -v data:/data \
  ghcr.io/luxfi/explorer \
  indexer --chain cchain --rpc http://node:9650/ext/bc/C/rpc

# Just the graph engine (subgraph GraphQL only)
docker run -p 4000:4000 \
  -v data:/data \
  ghcr.io/luxfi/explorer \
  graph --rpc http://node:9650/ext/bc/C/rpc
```

## Architecture

```
explorer (1 image, 3 binaries)
├── indexer   /v1/explorer/*     Chain data REST API
├── graph     /graphql           Subgraph-compatible GraphQL
├── explore   /*                 Embedded Next.js frontend
│
├── SQLite per-chain             Zero-config, WAL mode
├── ZapDB KV                     Fast hash lookups
└── Replicate → S3               E2E PQ encrypted (ML-KEM-768)
```

## White-Label

```bash
docker run -p 8090:8090 \
  -e RPC_ENDPOINT=http://node:8545 \
  -e CHAIN_NAME="My Chain" \
  -e COIN_SYMBOL=MYC \
  ghcr.io/luxfi/explorer
```

## Related

- [`luxfi/indexer`](https://github.com/luxfi/indexer) — Go chain indexer, 1528 tests
- [`luxfi/graph`](https://github.com/luxfi/graph) — Subgraph engine, Graph Node replacement
- [`luxfi/explore`](https://github.com/luxfi/explore) — Next.js frontend
- [`luxfi/explorer-v1`](https://github.com/luxfi/explorer-v1) — Legacy Elixir stack (archived)
