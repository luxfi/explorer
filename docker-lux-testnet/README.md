# LUX Network Testnet Explorer

Production-ready Blockscout explorer configuration for LUX Network Testnet.

## Network Details

- **Chain ID**: 96368
- **Network Name**: LUX Testnet
- **Currency**: LUX
- **Explorer URL**: https://explore-test.lux.network
- **API URL**: https://api-explore-test.lux.network

## Services

| Service | Port | Description |
|---------|------|-------------|
| Backend | 4010 | Blockscout API |
| Frontend | 3010 | Next.js Web UI |
| Stats | 8152 | Statistics service |

**Note**: Uses shared visualizer and sig-provider from lux-mainnet to conserve resources.

## Prerequisites

1. PostgreSQL database with databases:
   - `explorer_luxtest` - Main explorer database
   - `stats_luxtest` - Statistics database

2. LUX Node running on port 9630 with testnet subnet RPC enabled

3. LUX Mainnet explorer running (provides shared visualizer and sig-provider)

4. Nginx configured to proxy:
   - explore-test.lux.network -> localhost:3010
   - api-explore-test.lux.network -> localhost:4010

## Quick Start

```bash
# Ensure lux-mainnet explorer is running first
cd ../docker-mainnet && docker-compose up -d

# Start testnet services
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
CREATE DATABASE explorer_luxtest OWNER blockscout;
CREATE DATABASE stats_luxtest OWNER blockscout;

-- Grant schema permissions
\c explorer_luxtest
ALTER SCHEMA public OWNER TO blockscout;
\c stats_luxtest
ALTER SCHEMA public OWNER TO blockscout;
```
