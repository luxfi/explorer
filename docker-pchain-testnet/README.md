# LUX P-Chain Explorer - Testnet

Platform Chain explorer for LUX Network Testnet.

## Details

- **Chain**: P-Chain (Platform)
- **Environment**: Testnet
- **API Port**: 4110
- **RPC Endpoint**: `/ext/bc/P`

## Features

- Validator tracking
- Staking information
- Network (subnet) management
- Delegation tracking

## Quick Start

```bash
# Start P-Chain testnet indexer
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Database Setup

```sql
CREATE DATABASE explorer_pchain_test OWNER blockscout;
```

## API Endpoints

- `GET /api/v2/stats` - Chain statistics
- `GET /api/v2/validators` - List validators
- `GET /api/v2/validators/{nodeId}` - Validator details
- `GET /api/v2/networks` - List networks
- `GET /api/v2/blocks` - List blocks
