# LUX X-Chain Explorer - Testnet

Exchange Chain explorer for LUX Network Testnet.

## Details

- **Chain**: X-Chain (Exchange)
- **Environment**: Testnet
- **API Port**: 4210
- **RPC Endpoint**: `/ext/bc/X`

## Features

- Asset management and tracking
- UTXO indexing
- Balance tracking per address
- Transaction history

## Quick Start

```bash
# Start X-Chain testnet indexer
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Database Setup

```sql
CREATE DATABASE explorer_xchain_test OWNER blockscout;
```

## API Endpoints

- `GET /api/v2/stats` - Chain statistics
- `GET /api/v2/assets` - List assets
- `GET /api/v2/assets/{id}` - Asset details
- `GET /api/v2/addresses/{addr}/utxos` - Address UTXOs
- `GET /api/v2/addresses/{addr}/balances` - Address balances
- `GET /api/v2/blocks` - List blocks
- `GET /api/v2/transactions` - List transactions
