# Multi-Chain Blockscout Setup

This setup supports the complete LUX Network multi-chain architecture including EVM and non-EVM chains.

## LUX Network Chains

| Chain | Type | Description | Explorer |
|-------|------|-------------|----------|
| **C-Chain** | EVM | Contract chain - smart contracts, DeFi | Blockscout |
| **P-Chain** | UTXO | Platform chain - validators, staking, networks | Custom Indexer |
| **X-Chain** | UTXO | Exchange chain - assets, transfers | Custom Indexer |
| **Q-Chain** | Quantum | Quantum chain - post-quantum finality | Custom Indexer |
| **Z/A-Chain** | ZK | Attestation chain - AI attestations, ZK proofs | Custom Indexer |

## Directory Structure

```
explorer-lux/
├── apps/                           # Blockscout apps (C-Chain)
├── indexers/                       # Custom chain indexers (P/X/Q/Z)
│   ├── pchain/                     # P-Chain indexer
│   ├── xchain/                     # X-Chain indexer
│   ├── qchain/                     # Q-Chain indexer
│   ├── zchain/                     # Z/A-Chain indexer
│   ├── go.mod
│   ├── Makefile
│   └── Dockerfile
├── docker-mainnet/                 # LUX C-Chain mainnet (Blockscout)
├── docker-lux-testnet/             # LUX C-Chain testnet
├── docker-lux-devnet/              # LUX C-Chain devnet
├── docker-zoo-mainnet/             # ZOO C-Chain mainnet
├── docker-zoo-testnet/             # ZOO C-Chain testnet
├── docker-pchain-mainnet/          # P-Chain mainnet
├── docker-xchain-mainnet/          # X-Chain mainnet
├── docker-qchain-mainnet/          # Q-Chain mainnet
├── docker-zchain-mainnet/          # Z/A-Chain mainnet
├── docker-compose.all-chains.yml   # All chains in one compose
└── docs/
```

## Port Assignments

### Mainnet

| Chain | API Port | Frontend Port | Domain |
|-------|----------|---------------|--------|
| C-Chain (LUX) | 4000 | 3000 | explore.lux.network |
| C-Chain (ZOO) | 4002 | 3001 | explore.zoo.network |
| P-Chain | 4100 | - | pchain.lux.network |
| X-Chain | 4200 | - | xchain.lux.network |
| Q-Chain | 4300 | - | qchain.lux.network |
| Z/A-Chain | 4400 | - | zchain.lux.network |

### Testnet

| Chain | API Port | Frontend Port | Domain |
|-------|----------|---------------|--------|
| C-Chain (LUX) | 4010 | 3010 | explore-test.lux.network |
| C-Chain (ZOO) | 4011 | 3011 | explore-test.zoo.network |
| P-Chain | 4110 | - | pchain-test.lux.network |
| X-Chain | 4210 | - | xchain-test.lux.network |
| Q-Chain | 4310 | - | qchain-test.lux.network |
| Z/A-Chain | 4410 | - | zchain-test.lux.network |

### Devnet

| Chain | API Port | Frontend Port | Domain |
|-------|----------|---------------|--------|
| C-Chain (LUX) | 4020 | 3020 | explore-dev.lux.network |
| P-Chain | 4120 | - | pchain-dev.lux.network |
| X-Chain | 4220 | - | xchain-dev.lux.network |
| Q-Chain | 4320 | - | qchain-dev.lux.network |
| Z/A-Chain | 4420 | - | zchain-dev.lux.network |

## Quick Start

### Start All LUX Chains (Mainnet + Testnet)
```bash
docker-compose -f docker-compose.lux-full.yml up -d
```

### Start Individual Chains - Mainnet
```bash
# C-Chain (Blockscout)
cd docker-mainnet && docker-compose up -d

# P-Chain
cd docker-pchain-mainnet && docker-compose up -d

# X-Chain
cd docker-xchain-mainnet && docker-compose up -d

# Q-Chain
cd docker-qchain-mainnet && docker-compose up -d

# Z/A-Chain
cd docker-zchain-mainnet && docker-compose up -d
```

### Start Individual Chains - Testnet
```bash
# C-Chain Testnet (Blockscout)
cd docker-lux-testnet && docker-compose up -d

# P-Chain Testnet
cd docker-pchain-testnet && docker-compose up -d

# X-Chain Testnet
cd docker-xchain-testnet && docker-compose up -d

# Q-Chain Testnet
cd docker-qchain-testnet && docker-compose up -d

# Z/A-Chain Testnet
cd docker-zchain-testnet && docker-compose up -d
```

### Build Custom Indexers
```bash
cd indexers
make build           # Build all indexers
make docker          # Build Docker images
```

## API Endpoints

### C-Chain (Blockscout)
- `GET /api/v2/blocks` - List blocks
- `GET /api/v2/transactions` - List transactions
- `GET /api/v2/addresses/{hash}` - Address details
- `GET /api/v2/tokens` - Token list
- Full Blockscout API: https://docs.blockscout.com/for-users/api

### P-Chain (Platform)
- `GET /api/v2/validators` - Current validators
- `GET /api/v2/validators/{nodeId}` - Validator details
- `GET /api/v2/networks` - Subnet list
- `GET /api/v2/blocks` - P-Chain blocks
- `GET /api/v2/stats` - Chain statistics

### X-Chain (Exchange)
- `GET /api/v2/assets` - Asset list
- `GET /api/v2/assets/{id}` - Asset details
- `GET /api/v2/addresses/{addr}/utxos` - Address UTXOs
- `GET /api/v2/addresses/{addr}/balances` - Address balances
- `GET /api/v2/blocks` - X-Chain blocks

### Q-Chain (Quantum)
- `GET /api/v2/stamps` - Quantum stamps list
- `GET /api/v2/stamps/by-cchain/{blockNum}` - Stamp for C-Chain block
- `GET /api/v2/finality` - Cross-chain finality status
- `GET /api/v2/keys` - Ringtail quantum keys
- `GET /api/v2/blocks` - Q-Chain blocks

### Z/A-Chain (Attestation)
- `GET /api/v2/providers` - AI attestation providers
- `GET /api/v2/receipts` - Inference receipts
- `GET /api/v2/challenges` - Attestation challenges
- `GET /api/v2/proofs` - ZK proofs
- `GET /api/v2/transfers` - Confidential transfers
- `GET /api/v2/nullifiers/{nullifier}` - Check nullifier spent

## Database Setup

Use the provided setup script to create all databases:

```bash
# Run the database setup script
psql -U postgres -f scripts/setup-databases.sql
```

Or create manually:

```sql
-- C-Chain databases (per network)
CREATE DATABASE explorer_luxnet OWNER blockscout;
CREATE DATABASE explorer_luxtest OWNER blockscout;
CREATE DATABASE explorer_luxdev OWNER blockscout;
CREATE DATABASE explorer_zoonet OWNER blockscout;
CREATE DATABASE explorer_zootest OWNER blockscout;

-- P-Chain databases
CREATE DATABASE explorer_pchain OWNER blockscout;
CREATE DATABASE explorer_pchain_test OWNER blockscout;

-- X-Chain databases
CREATE DATABASE explorer_xchain OWNER blockscout;
CREATE DATABASE explorer_xchain_test OWNER blockscout;

-- Q-Chain databases
CREATE DATABASE explorer_qchain OWNER blockscout;
CREATE DATABASE explorer_qchain_test OWNER blockscout;

-- Z/A-Chain databases
CREATE DATABASE explorer_zchain OWNER blockscout;
CREATE DATABASE explorer_zchain_test OWNER blockscout;

-- Stats databases
CREATE DATABASE stats_luxnet OWNER blockscout;
CREATE DATABASE stats_luxtest OWNER blockscout;
CREATE DATABASE stats_luxdev OWNER blockscout;
CREATE DATABASE stats_zoonet OWNER blockscout;
CREATE DATABASE stats_zootest OWNER blockscout;
```

Total: 18 databases for all chains and environments.

## RPC Endpoints

All chains connect to luxd on port 9630:

| Chain | RPC Endpoint |
|-------|--------------|
| C-Chain | `/ext/bc/C/rpc` or `/ext/bc/{blockchainID}/rpc` |
| P-Chain | `/ext/bc/P` |
| X-Chain | `/ext/bc/X` |
| Q-Chain | `/ext/bc/Q` |
| Z/A-Chain | `/ext/bc/Z` |

For specific subnet C-Chains (ZOO, SPC, etc.), use the blockchain ID:
- LUX Mainnet: `/ext/bc/dnmzhuf6poM6PUNQCe7MWWfBdTJEnddhHRNXz2x7H6qSmyBEJ/rpc`
- ZOO Mainnet: `/ext/bc/bXe2MhhAnXg6WGj6G8oDk55AKT1dMMsN72S8te7JdvzfZX1zM/rpc`

## Shared Services

These services are shared across all chains (run once from docker-mainnet):

| Service | Port | Description |
|---------|------|-------------|
| Visualizer | 8050 | Smart contract visualization |
| Sig-Provider | 8051 | Function signature decoding |
| PostgreSQL | 5432 | Shared database server |

## Health Checks

All indexers expose health endpoints:

```bash
# Check all chain health
curl http://localhost:4000/health  # C-Chain
curl http://localhost:4100/health  # P-Chain
curl http://localhost:4200/health  # X-Chain
curl http://localhost:4300/health  # Q-Chain
curl http://localhost:4400/health  # Z-Chain
```

## Multi-Chain Frontend

The Blockscout frontend supports a multi-chain dropdown. Configure with:

```env
NEXT_PUBLIC_NETWORK_GROUPS='[
  {"title":"Mainnet","items":[
    {"title":"LUX","url":"https://explore.lux.network"},
    {"title":"ZOO","url":"https://explore.zoo.network"},
    {"title":"P-Chain","url":"https://pchain.lux.network"},
    {"title":"X-Chain","url":"https://xchain.lux.network"},
    {"title":"Q-Chain","url":"https://qchain.lux.network"},
    {"title":"Z-Chain","url":"https://zchain.lux.network"}
  ]},
  {"title":"Testnet","items":[
    {"title":"LUX","url":"https://explore-test.lux.network"},
    {"title":"ZOO","url":"https://explore-test.zoo.network"}
  ]}
]'
```

## Nginx Configuration

Example nginx config for proxying all explorers:

```nginx
# C-Chain
server {
    server_name explore.lux.network;
    location / { proxy_pass http://127.0.0.1:3000; }
}
server {
    server_name api-explore.lux.network;
    location / { proxy_pass http://127.0.0.1:4000; }
}

# P-Chain
server {
    server_name pchain.lux.network api-pchain.lux.network;
    location / { proxy_pass http://127.0.0.1:4100; }
}

# X-Chain
server {
    server_name xchain.lux.network api-xchain.lux.network;
    location / { proxy_pass http://127.0.0.1:4200; }
}

# Q-Chain
server {
    server_name qchain.lux.network api-qchain.lux.network;
    location / { proxy_pass http://127.0.0.1:4300; }
}

# Z-Chain
server {
    server_name zchain.lux.network api-zchain.lux.network;
    location / { proxy_pass http://127.0.0.1:4400; }
}
```

## Next Steps

1. ✅ C-Chain explorers (LUX mainnet/testnet, ZOO mainnet/testnet)
2. ✅ Custom indexers for P/X/Q/Z chains
3. ✅ Docker compose configurations
4. 🔲 Build and deploy custom indexers
5. 🔲 Create unified frontend with chain selector
6. 🔲 Add testnet/devnet configurations for P/X/Q/Z
7. 🔲 Set up production nginx routing
