# LUX Network Devnet Explorer

Production-ready Blockscout explorer configuration for LUX Network Devnet (local development).

## Network Details

- **Chain ID**: 1337
- **Network Name**: LUX Devnet
- **Currency**: LUX
- **Explorer URL**: https://explore-dev.lux.network
- **API URL**: https://api-explore-dev.lux.network

## Services

| Service | Port | Description |
|---------|------|-------------|
| Backend | 4020 | Blockscout API |
| Frontend | 3020 | Next.js Web UI |
| Stats | 8162 | Statistics service |

**Note**: Uses shared visualizer and sig-provider from lux-mainnet to conserve resources.

## Prerequisites

1. PostgreSQL database with databases:
   - `explorer_luxdev` - Main explorer database
   - `stats_luxdev` - Statistics database

2. LUX Node running on port 9630 with devnet C-Chain RPC enabled

3. LUX Mainnet explorer running (provides shared visualizer and sig-provider)

4. Nginx configured to proxy:
   - explore-dev.lux.network -> localhost:3020
   - api-explore-dev.lux.network -> localhost:4020

## Quick Start

```bash
# Ensure lux-mainnet explorer is running first
cd ../docker-mainnet && docker-compose up -d

# Start devnet services
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
CREATE DATABASE explorer_luxdev OWNER blockscout;
CREATE DATABASE stats_luxdev OWNER blockscout;

-- Grant schema permissions
\c explorer_luxdev
ALTER SCHEMA public OWNER TO blockscout;
\c stats_luxdev
ALTER SCHEMA public OWNER TO blockscout;
```

## Development Usage

This configuration is designed for local development with:
- POA automining mode
- Chain ID 1337 (standard development chain)
- Direct connection to local luxd node at port 9630
