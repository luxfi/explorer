# LUX Chain Explorer Indexers

Lightweight indexers for LUX Network non-EVM chains: P-Chain, X-Chain, Q-Chain, and Z/A-Chain.

## Architecture

Each indexer is a standalone Go service that:
1. Connects to the respective chain's RPC endpoint
2. Indexes blocks, transactions, and chain-specific data into PostgreSQL
3. Exposes a Blockscout-compatible REST API

## Chains

| Chain | Description | Default Port | RPC Endpoint |
|-------|-------------|--------------|--------------|
| P-Chain | Platform chain - validators, staking, networks | 4100 | `/ext/bc/P` |
| X-Chain | Exchange chain - assets, UTXOs, transfers | 4200 | `/ext/bc/X` |
| Q-Chain | Quantum chain - quantum stamps, finality | 4300 | `/ext/bc/Q` |
| Z/A-Chain | ZK attestation chain - AI attestations, ZK proofs | 4400 | `/ext/bc/Z` |

## Building

```bash
# Build all indexers
make build

# Build individual indexer
make pchain
make xchain
make qchain
make zchain

# Build Docker images
make docker
```

## Running

### Local Development

```bash
# Run P-Chain indexer
make run-pchain

# Run X-Chain indexer
make run-xchain

# Run Q-Chain indexer
make run-qchain

# Run Z-Chain indexer
make run-zchain
```

### Docker

```bash
# Using docker-compose from parent directory
cd ../docker-pchain-mainnet && docker-compose up -d
cd ../docker-xchain-mainnet && docker-compose up -d
cd ../docker-qchain-mainnet && docker-compose up -d
cd ../docker-zchain-mainnet && docker-compose up -d
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RPC_ENDPOINT` | Chain RPC URL | `http://localhost:9630/ext/bc/{chain}` |
| `DATABASE_URL` | PostgreSQL connection string | `postgres://blockscout:blockscout@localhost:5432/explorer_{chain}` |
| `HTTP_PORT` | API server port | Chain-specific |

## API Endpoints

All indexers expose Blockscout-compatible REST APIs:

### Common Endpoints

- `GET /health` - Health check
- `GET /api/v2/stats` - Chain statistics
- `GET /api/v2/blocks` - List blocks
- `GET /api/v2/blocks/{id}` - Get block by ID
- `GET /api/v2/transactions` - List transactions
- `GET /api/v2/transactions/{id}` - Get transaction by ID

### P-Chain Specific

- `GET /api/v2/validators` - List validators
- `GET /api/v2/validators/{nodeId}` - Get validator details
- `GET /api/v2/networks` - List networks (subnets)
- `GET /api/v2/networks/{id}` - Get network details

### X-Chain Specific

- `GET /api/v2/assets` - List assets
- `GET /api/v2/assets/{id}` - Get asset details
- `GET /api/v2/addresses/{address}/utxos` - Get address UTXOs
- `GET /api/v2/addresses/{address}/balances` - Get address balances

### Q-Chain Specific

- `GET /api/v2/stamps` - List quantum stamps
- `GET /api/v2/stamps/{id}` - Get stamp details
- `GET /api/v2/stamps/by-cchain/{blockNum}` - Get stamp by C-Chain block
- `GET /api/v2/finality` - Cross-chain finality status
- `GET /api/v2/keys` - List Ringtail keys

### Z/A-Chain Specific

- `GET /api/v2/providers` - List attestation providers
- `GET /api/v2/providers/{id}` - Get provider details
- `GET /api/v2/receipts` - List inference receipts
- `GET /api/v2/challenges` - List challenges
- `GET /api/v2/proofs` - List ZK proofs
- `GET /api/v2/transfers` - List confidential transfers
- `GET /api/v2/nullifiers/{nullifier}` - Check nullifier status

## Database Setup

Each indexer auto-creates its tables on startup. To manually create databases:

```sql
CREATE DATABASE explorer_pchain OWNER blockscout;
CREATE DATABASE explorer_xchain OWNER blockscout;
CREATE DATABASE explorer_qchain OWNER blockscout;
CREATE DATABASE explorer_zchain OWNER blockscout;
```

## Port Allocation

### Mainnet
- C-Chain: 4000 (Blockscout)
- P-Chain: 4100
- X-Chain: 4200
- Q-Chain: 4300
- Z-Chain: 4400

### Testnet
- C-Chain: 4010 (Blockscout)
- P-Chain: 4110
- X-Chain: 4210
- Q-Chain: 4310
- Z-Chain: 4410

### Devnet
- C-Chain: 4020 (Blockscout)
- P-Chain: 4120
- X-Chain: 4220
- Q-Chain: 4320
- Z-Chain: 4420
