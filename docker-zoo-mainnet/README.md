# ZOO Network Mainnet Explorer

Production-ready Blockscout explorer configuration for ZOO Network Mainnet.

## Network Details

- **Chain ID**: 200200
- **Network Name**: ZOO Network
- **Currency**: ZOO
- **Explorer URL**: https://explore.zoo.network
- **API URL**: https://api-explore.zoo.network

## Services

| Service | Port | Description |
|---------|------|-------------|
| Backend | 4002 | Blockscout API |
| Frontend | 3001 | Next.js Web UI |
| Stats | 8252 | Statistics service |

**Note**: Uses shared visualizer and sig-provider from lux-mainnet to conserve resources.

## Prerequisites

1. PostgreSQL database with databases:
   - `explorer_zoonet` - Main explorer database
   - `stats_zoonet` - Statistics database

2. LUX Node running on port 9630 with ZOO subnet RPC enabled

3. LUX Mainnet explorer running (provides shared visualizer and sig-provider)

4. Nginx configured to proxy:
   - explore.zoo.network -> localhost:3001
   - api-explore.zoo.network -> localhost:4002

## Quick Start

```bash
# Ensure lux-mainnet explorer is running first
cd ../docker-mainnet && docker-compose up -d

# Start ZOO mainnet services
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
CREATE DATABASE explorer_zoonet OWNER blockscout;
CREATE DATABASE stats_zoonet OWNER blockscout;

-- Grant schema permissions
\c explorer_zoonet
ALTER SCHEMA public OWNER TO blockscout;
\c stats_zoonet
ALTER SCHEMA public OWNER TO blockscout;
```
