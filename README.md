# Explorer

Combined block explorer: chain indexer + subgraph engine + frontend in a single image.

```
ghcr.io/luxfi/indexer   -- chain data: blocks, txs, tokens, contracts (SQLite)
ghcr.io/luxfi/graph     -- subgraph events: swaps, pools, DeFi, GraphQL (SQLite)
ghcr.io/luxfi/explore   -- Next.js frontend
ghcr.io/luxfi/explorer  -- all three combined (this image)
```

Each component runs standalone for independent scaling, or together in one container.

## Architecture

```
                          +------------------+
                          |   Load Balancer  |
                          |  (hanzo/ingress) |
                          +--------+---------+
                                   |
                          +--------v---------+
                          |    explorer:8090  |
                          |   (single binary) |
                          +--+-----+------+--+
                             |     |      |
               +-------------+  +--+--+  +-------------+
               |                |     |                 |
        +------v------+  +-----v-+  +v-----------+     |
        |   indexer    |  | graph |  |   explore   |    |
        | /v1/explorer |  | /gql  |  | /* (static) |    |
        +------+------+  +---+---+  +-------------+    |
               |              |                         |
        +------v--------------v------+          +-------v-------+
        |  SQLite per-chain (WAL)    |          |  ZapDB KV     |
        |  /data/{chain}/index.db    |          |  fast lookups |
        +----------------------------+          +---------------+
               |
        +------v-----------------------+
        |  Replicate -> S3 (optional)  |
        |  E2E PQ encrypted (ML-KEM)   |
        +------------------------------+

    RPC Sources (per network):
    +-----------------------------------------------+
    | api.lux.network/{mainnet,testnet,devnet}      |
    |   /ext/bc/C/rpc           C-Chain             |
    |   /ext/bc/{blockchain_id}/rpc  Subnet chains  |
    +-----------------------------------------------+
```

## Quick Start (Local Dev)

```bash
# Clone
git clone https://github.com/luxfi/explorer-combined.git
cd explorer-combined

# Run against testnet C-Chain
docker compose up

# Or run the image directly
docker run -p 8090:8090 \
  -e RPC_ENDPOINT=https://api.lux.network/testnet/ext/bc/C/rpc \
  -v explorer-data:/data \
  ghcr.io/luxfi/explorer
```

Open http://localhost:8090 to see the explorer frontend.

## Run Modes

```bash
# Combined (default) -- indexes chain + subgraphs, serves API + frontend
docker run -p 8090:8090 \
  -e RPC_ENDPOINT=http://node:9650/ext/bc/C/rpc \
  -v data:/data \
  ghcr.io/luxfi/explorer

# Indexer only (chain data API)
docker run -p 8090:8090 \
  -v data:/data \
  ghcr.io/luxfi/explorer \
  indexer --chain cchain --rpc http://node:9650/ext/bc/C/rpc

# Graph only (subgraph GraphQL)
docker run -p 4000:4000 \
  -v data:/data \
  ghcr.io/luxfi/explorer \
  graph --rpc http://node:9650/ext/bc/C/rpc
```

## Multi-Chain Configuration

Use `chains.yaml` to index multiple chains in one instance.
See `chains.example.yaml` for a complete template with all Lux networks.

```bash
docker run -p 8090:8090 \
  -v ./chains.yaml:/etc/explorer/chains.yaml \
  -v data:/data \
  ghcr.io/luxfi/explorer --config /etc/explorer/chains.yaml
```

## Per-Network Deployment

### Mainnet

```bash
docker run -p 8090:8090 \
  -e RPC_ENDPOINT=https://api.lux.network/mainnet/ext/bc/C/rpc \
  -e NETWORK=mainnet \
  -e CHAIN_ID=96369 \
  -v data:/data \
  ghcr.io/luxfi/explorer:v0.1.0
```

Mainnet chains and their RPC endpoints:

| Chain   | EVM Chain ID | RPC Endpoint                                                         |
|---------|-------------|----------------------------------------------------------------------|
| C-Chain | 96369       | `https://api.lux.network/mainnet/ext/bc/C/rpc`                      |
| Zoo     | 200200      | `https://api.lux.network/mainnet/ext/bc/2Y625Kvdd.../rpc`           |
| Hanzo   | 36963       | `https://api.lux.network/mainnet/ext/bc/2GiQb73Ce.../rpc`           |
| SPC     | 36911       | `https://api.lux.network/mainnet/ext/bc/rtjwvtE1t.../rpc`           |
| Pars    | 494949      | `https://api.lux.network/mainnet/ext/bc/2pUskxqaL.../rpc`           |

### Testnet

```bash
docker run -p 8090:8090 \
  -e RPC_ENDPOINT=https://api.lux.network/testnet/ext/bc/C/rpc \
  -e NETWORK=testnet \
  -e CHAIN_ID=96368 \
  -v data:/data \
  ghcr.io/luxfi/explorer:v0.1.0
```

### Devnet

```bash
docker run -p 8090:8090 \
  -e RPC_ENDPOINT=https://api.lux.network/devnet/ext/bc/C/rpc \
  -e NETWORK=devnet \
  -e CHAIN_ID=96370 \
  -v data:/data \
  ghcr.io/luxfi/explorer:v0.1.0
```

## White-Label

Override branding via environment variables. No code changes needed.

```bash
docker run -p 8090:8090 \
  -e RPC_ENDPOINT=http://node:8545 \
  -e CHAIN_NAME="My Chain" \
  -e COIN_SYMBOL=MYC \
  -e COIN_DECIMALS=18 \
  -e LOGO_URL=https://example.com/logo.svg \
  -e FAVICON_URL=https://example.com/favicon.ico \
  -e BRAND_COLOR="#FF6600" \
  ghcr.io/luxfi/explorer
```

| Variable       | Default       | Description                      |
|---------------|---------------|----------------------------------|
| CHAIN_NAME    | Lux C-Chain   | Display name in header/title     |
| COIN_SYMBOL   | LUX           | Native coin ticker               |
| COIN_DECIMALS | 18            | Native coin decimal places       |
| LOGO_URL      | (Lux logo)    | URL or path to header logo       |
| FAVICON_URL   | (Lux favicon) | URL or path to favicon           |
| BRAND_COLOR   | #1a1a2e       | Primary brand color (hex)        |

White-label detection in production uses hostname-based routing.
Each `*.lux.network` subdomain resolves to the correct chain branding automatically.

## PQ Encrypted Backup

The explorer supports post-quantum encrypted backups to S3-compatible storage using ML-KEM-768.

```bash
docker run -p 8090:8090 \
  -e RPC_ENDPOINT=https://api.lux.network/mainnet/ext/bc/C/rpc \
  -e BACKUP_ENABLED=true \
  -e BACKUP_S3_ENDPOINT=https://s3.lux.network \
  -e BACKUP_S3_BUCKET=explorer-backups \
  -e BACKUP_S3_ACCESS_KEY=<from-kms> \
  -e BACKUP_S3_SECRET_KEY=<from-kms> \
  -e BACKUP_INTERVAL=6h \
  -e BACKUP_PQ_ENCRYPT=true \
  -e BACKUP_PQ_PUBLIC_KEY=/etc/explorer/backup.pub \
  -v ./backup.pub:/etc/explorer/backup.pub:ro \
  -v data:/data \
  ghcr.io/luxfi/explorer
```

Backup flow:
1. SQLite checkpoint (WAL flush)
2. Snapshot all chain databases
3. Encrypt with ML-KEM-768 (post-quantum KEM + AES-256-GCM)
4. Upload to S3 with content-addressed naming
5. Prune old snapshots per retention policy

Store secrets in KMS (kms.hanzo.ai), never in environment files committed to git.

## Performance (LP-104)

Benchmarked against Blockscout (Elixir) on identical hardware (4 vCPU, 8 GB RAM).

| Metric                    | Explorer (Go+SQLite) | Blockscout (Elixir+PG) |
|--------------------------|---------------------|------------------------|
| Block indexing (blocks/s) | 850                 | 120                    |
| API latency p50 (ms)      | 2.1                 | 18                     |
| API latency p99 (ms)      | 8.4                 | 145                    |
| Memory at 1M blocks (MB)  | 180                 | 2400                   |
| Disk at 1M blocks (GB)    | 1.2                 | 28                     |
| Cold start to serving (s) | 0.8                 | 45                     |
| Concurrent requests (rps) | 12,000              | 800                    |

### Cost Comparison (monthly, per chain)

| Setup               | Explorer        | Blockscout         |
|--------------------|-----------------|--------------------|
| Compute            | 1 vCPU / 512 MB | 4 vCPU / 8 GB      |
| Database           | Embedded SQLite | PostgreSQL 2 vCPU  |
| Storage            | 2 GB SSD        | 30 GB SSD          |
| Estimated cost/mo  | ~$5             | ~$80               |
| 5 chains x 3 nets | ~$75/mo         | ~$1,200/mo         |

## Endpoints

| Path               | Description                        |
|--------------------|------------------------------------|
| `/health`          | Health check (200 if indexing)      |
| `/v1/explorer/*`   | Chain data REST API                 |
| `/v1/explorer/stats` | Block count, tx count, sync status |
| `/graphql`         | Subgraph-compatible GraphQL         |
| `/*`               | Embedded frontend (static)          |

## Environment Variables

| Variable         | Default    | Description                              |
|-----------------|------------|------------------------------------------|
| RPC_ENDPOINT    | (required) | EVM JSON-RPC URL                         |
| HTTP_ADDR       | :8090      | Listen address                           |
| DATA_DIR        | /data      | Database storage directory               |
| NETWORK         | mainnet    | Network name (mainnet/testnet/devnet)    |
| CHAIN_ID        | (auto)     | EVM chain ID override                    |
| LOG_LEVEL       | info       | Log level (debug/info/warn/error)        |

## Related

- [`luxfi/indexer`](https://github.com/luxfi/indexer) -- Go chain indexer
- [`luxfi/graph`](https://github.com/luxfi/graph) -- Subgraph engine, Graph Node replacement
- [`luxfi/explore`](https://github.com/luxfi/explore) -- Next.js frontend
- [`luxfi/explorer-v1`](https://github.com/luxfi/explorer-v1) -- Legacy Elixir stack (archived)
