# Explorer

Combined block explorer image: Go backend ([`luxfi/indexer`](https://github.com/luxfi/indexer)) + Next.js frontend ([`luxfi/explore`](https://github.com/luxfi/explore)) in a single container.

```
ghcr.io/luxfi/indexer   ← Go backend (API + chain indexing)
ghcr.io/luxfi/explore   ← Next.js frontend
ghcr.io/luxfi/explorer  ← This: combined single image
```

## Run

```bash
docker run -p 8090:8090 \
  -e RPC_ENDPOINT=http://node:9650/ext/bc/C/rpc \
  -e CHAIN_NAME="My Chain" \
  -e COIN_SYMBOL=ETH \
  -v explorer-data:/data \
  ghcr.io/luxfi/explorer
```

Single port, single image. Backend API at `/v1/explorer/*`, frontend at `/`.

## Build

```bash
docker build -t ghcr.io/luxfi/explorer .
```

Pulls `luxfi/indexer` and `luxfi/explore` from GitHub at build time. Override branches:

```bash
docker build \
  --build-arg INDEXER_REF=v1.2.0 \
  --build-arg EXPLORE_REF=v2.7.2 \
  -t ghcr.io/luxfi/explorer .
```

## White-Label

```bash
docker run -p 8090:8090 \
  -e RPC_ENDPOINT=http://node:8545 \
  -e CHAIN_NAME="Awesome Chain" \
  -e COIN_SYMBOL=AWE \
  -e CHAIN_ID=12345 \
  ghcr.io/luxfi/explorer
```

## Multi-Chain

Mount a `chains.yaml`:

```bash
docker run -p 8090:8090 \
  -v ./chains.yaml:/etc/explorer/chains.yaml \
  -v explorer-data:/data \
  ghcr.io/luxfi/explorer --config=/etc/explorer/chains.yaml
```

## Related

- [`luxfi/indexer`](https://github.com/luxfi/indexer) — Go backend, 1528 tests, SQLite, E2E PQ encrypted backups
- [`luxfi/explore`](https://github.com/luxfi/explore) — Next.js frontend, Geist font, white-label
- [`luxfi/explorer-v1`](https://github.com/luxfi/explorer-v1) — Legacy Elixir stack (archived)
