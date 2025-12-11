# LUX Network Mainnet Explorer

Production-ready Blockscout explorer configuration for LUX Network Mainnet.

## Network Details

- **Chain ID**: 96369
- **Network Name**: LUX Network
- **Currency**: LUX
- **Explorer URL**: https://explore.lux.network
- **API URL**: https://api-explore.lux.network

## Services

| Service | Port | Description |
|---------|------|-------------|
| Backend | 4000 | Blockscout API |
| Frontend | 3000 | Next.js Web UI |
| Visualizer | 8050 | Contract visualization |
| Sig Provider | 8051 | Signature provider |
| Stats | 8052 | Statistics service |
| User Ops Indexer | 8053 | ERC-4337 indexer |

## Prerequisites

1. PostgreSQL database with databases:
   - `explorer_luxnet` - Main explorer database
   - `stats_luxnet` - Statistics database
   - `user_ops_luxnet` - User operations database

2. LUX Node running on port 9630 with RPC enabled

3. Nginx configured to proxy:
   - explore.lux.network -> localhost:3000
   - api-explore.lux.network -> localhost:4000

## Quick Start

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down
```

## Environment Variables

### Backend
- `ETHEREUM_JSONRPC_HTTP_URL`: LUX node RPC endpoint
- `DATABASE_URL`: PostgreSQL connection string
- `CHAIN_ID`: 96369

### Frontend
- `NEXT_PUBLIC_API_HOST`: Backend API host (api-explore.lux.network)
- `NEXT_PUBLIC_NETWORK_NAME`: LUX Network
- `NEXT_PUBLIC_NETWORK_ID`: 96369

## Maintenance

### Restart services
```bash
docker-compose restart backend frontend
```

### Update images
```bash
docker-compose pull
docker-compose up -d
```

### View service health
```bash
docker-compose ps
curl http://localhost:4000/api/v2/stats
```
