# LUX Z/A-Chain Explorer - Testnet

ZK Attestation Chain explorer for LUX Network Testnet.

## Details

- **Chain**: Z/A-Chain (ZK Attestation)
- **Environment**: Testnet
- **API Port**: 4410
- **RPC Endpoint**: `/ext/bc/Z`

## Features

- AI attestation provider registry
- Inference receipt tracking
- ZK proof verification (Groth16, Plonk)
- Challenge/settlement protocol
- Confidential transfers
- Nullifier tracking

## Quick Start

```bash
# Start Z-Chain testnet indexer
docker-compose up -d

# View logs
docker-compose logs -f

# Stop
docker-compose down
```

## Database Setup

```sql
CREATE DATABASE explorer_zchain_test OWNER blockscout;
```

## API Endpoints

- `GET /api/v2/stats` - Chain statistics
- `GET /api/v2/providers` - AI attestation providers
- `GET /api/v2/providers/{id}` - Provider details
- `GET /api/v2/receipts` - Inference receipts
- `GET /api/v2/challenges` - Attestation challenges
- `GET /api/v2/proofs` - ZK proofs
- `GET /api/v2/transfers` - Confidential transfers
- `GET /api/v2/nullifiers/{nullifier}` - Check nullifier status
- `GET /api/v2/blocks` - List blocks
