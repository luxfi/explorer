#!/bin/bash

# Run ZOO Network Mainnet Explorer
# This script starts the Blockscout explorer for ZOO mainnet

cd "$(dirname "$0")/.."

echo "Starting ZOO Network Mainnet Explorer..."
echo "  Chain ID: 200200"
echo "  Frontend: http://localhost:3001"
echo "  Backend API: http://localhost:4001"
echo ""

# Start services
docker-compose -f compose.mainnet.yml up -d

echo ""
echo "ZOO Mainnet Explorer is starting..."
echo "View logs: docker-compose -f compose.mainnet.yml logs -f"