# ZOO Network Testnet Explorer

Production-ready Blockscout explorer configuration for ZOO Network Testnet.

## Network Details

- **Chain ID**: 200201
- **Network Name**: ZOO Testnet
- **Currency**: ZOO
- **Explorer URL**: https://explore-test.zoo.network
- **API URL**: https://api-explore-test.zoo.network

## Services

| Service | Port | Description |
|---------|------|-------------|
| Backend | 4011 | Blockscout API |
| Frontend | 3011 | Next.js Web UI |
| Stats | 8262 | Statistics service |

**Note**: Uses shared visualizer and sig-provider from lux-mainnet to conserve resources.

## Prerequisites

1. PostgreSQL database with databases:
   - `explorer_zootest` - Main explorer database
   - `stats_zootest` - Statistics database

2. LUX Node running on port 9630 with ZOO testnet subnet RPC enabled

3. LUX Mainnet explorer running (provides shared visualizer and sig-provider)

4. Nginx configured to proxy:
   - explore-test.zoo.network -> localhost:3011
   - api-explore-test.zoo.network -> localhost:4011

## Quick Start

```bash
# Ensure lux-mainnet explorer is running first
cd ../docker-mainnet && docker-compose up -d

# Start ZOO testnet services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down
```

## Database Setup

The databases will be created automatically on first start. To manually create:

```sql
-- Connect as postgres user
CREATE DATABASE explorer_zootest OWNER blockscout;
CREATE DATABASE stats_zootest OWNER blockscout;

-- Grant schema permissions
\c explorer_zootest
ALTER SCHEMA public OWNER TO blockscout;
\c stats_zootest
ALTER SCHEMA public OWNER TO blockscout;
```
