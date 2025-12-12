# LUX Q-Chain Explorer - Testnet

Quantum Chain explorer for LUX Network Testnet.

## Details

- **Chain**: Q-Chain (Quantum)
- **Environment**: Testnet
- **API Port**: 4310
- **RPC Endpoint**: `/ext/bc/Q`

## Features

- Quantum stamp tracking
- Post-quantum finality proofs
- Cross-chain finality status
- Ringtail quantum key management
- ML-DSA/SLH-DSA signature verification

## Quick Start

```bash
# Start Q-Chain testnet indexer
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Database Setup

```sql
CREATE DATABASE explorer_qchain_test OWNER blockscout;
```

## API Endpoints

- `GET /api/v2/stats` - Chain statistics
- `GET /api/v2/stamps` - List quantum stamps
- `GET /api/v2/stamps/{id}` - Stamp details
- `GET /api/v2/stamps/by-cchain/{blockNum}` - Stamp by C-Chain block
- `GET /api/v2/finality` - Cross-chain finality status
- `GET /api/v2/finality/{chainId}` - Finality for specific chain
- `GET /api/v2/keys` - Ringtail quantum keys
- `GET /api/v2/blocks` - List blocks
