# [NETWORK] Blockchain Explorer

This is the official blockchain explorer for [NETWORK] Network, based on Blockscout.

## Quick Start

### Run Mainnet Explorer
```bash
cd scripts
./run-mainnet.sh
```

Access at:
- Frontend: http://localhost:3000
- API: http://localhost:4000/api

### Run Testnet Explorer
```bash
cd scripts
./run-testnet.sh
```

Access at:
- Frontend: http://localhost:3010  
- API: http://localhost:4010/api

### Stop Explorers
```bash
# Stop mainnet
cd docker-compose
docker-compose down

# Stop testnet
cd docker-compose
docker-compose -p explorer-[network]-testnet down
```

## Configuration

### Environment Variables

Key configurations are in `docker-compose/envs/`:
- `common-blockscout.env` - Backend configuration
- `common-frontend.env` - Frontend configuration
- `common-stats.env` - Stats service configuration

### Network-Specific Settings

Update these for your network:
- `CHAIN_ID` - Your network's chain ID
- `ETHEREUM_JSONRPC_HTTP_URL` - RPC endpoint
- `DATABASE_URL` - PostgreSQL connection
- `NEXT_PUBLIC_NETWORK_NAME` - Display name
- `NEXT_PUBLIC_NETWORK_CURRENCY_SYMBOL` - Token symbol

### Branding

Replace logo files in `docker-compose/frontend/public/images/`:
- `[network]_logo.svg` - Light mode logo
- `[network]_logo_dark.svg` - Dark mode logo

## Database Setup

Each environment uses separate databases:
- Mainnet: `explorer_[network]net`
- Testnet: `explorer_[network]test`

Grant permissions:
```sql
GRANT ALL PRIVILEGES ON DATABASE explorer_[network]net TO blockscout;
GRANT ALL PRIVILEGES ON DATABASE explorer_[network]test TO blockscout;
```

## Docker Images

### Using Pre-built Images
```bash
docker pull ghcr.io/blockscout/blockscout:latest
```

### Building Custom Images
```bash
cd docker
docker build -t [network]/blockscout:latest -f Dockerfile ..
```

## Maintenance

### View Logs
```bash
# Mainnet logs
docker-compose logs -f

# Testnet logs  
docker-compose -p explorer-[network]-testnet logs -f
```

### Update Blockscout
1. Update version in `docker-compose.yml`
2. Pull new images: `docker-compose pull`
3. Restart: `./run-mainnet.sh`

### Backup Database
```bash
pg_dump -h localhost -U blockscout explorer_[network]net > backup.sql
```

## Troubleshooting

### Backend keeps restarting
- Check database connectivity
- Verify RPC endpoint is accessible
- Check logs: `docker-compose logs backend`

### Frontend shows no data
- Ensure backend is running: `docker ps`
- Check API endpoint: `curl http://localhost:4000/api/v2/stats`
- Verify environment variables in frontend container

### Database permission errors
- Add missing columns if upgrading:
  ```sql
  ALTER TABLE token_instances ADD COLUMN IF NOT EXISTS skip_metadata_url boolean;
  ALTER TABLE missing_block_ranges ADD COLUMN IF NOT EXISTS priority integer;
  ```

## Contributing

1. Fork this repository
2. Create your feature branch
3. Make your changes
4. Submit a pull request

## Support

- Discord: [Your Discord]
- Forum: [Your Forum]
- GitHub Issues: [Your Repo]/issues