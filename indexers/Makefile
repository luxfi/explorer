# LUX Explorer Indexers Makefile
# Builds lightweight indexers for all LUX chains:
#   A-Chain (AI), B-Chain (Bridge), P-Chain (Platform), Q-Chain (Quantum),
#   T-Chain (Teleport), X-Chain (Exchange), Z-Chain (ZK - coming soon)

.PHONY: all build clean achain bchain pchain qchain tchain xchain zchain docker test

# Build configuration
GO := go
GOFLAGS := -ldflags="-s -w"
BUILD_DIR := ./build

all: build

# Build all chain indexers
build: achain bchain pchain qchain tchain xchain zchain

achain:
	@echo "Building A-Chain (AI) indexer..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/achain-indexer ./achain

bchain:
	@echo "Building B-Chain (Bridge) indexer..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/bchain-indexer ./bchain

pchain:
	@echo "Building P-Chain (Platform) indexer..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/pchain-indexer ./pchain

qchain:
	@echo "Building Q-Chain (Quantum) indexer..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/qchain-indexer ./qchain

tchain:
	@echo "Building T-Chain (Teleport) indexer..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/tchain-indexer ./tchain

xchain:
	@echo "Building X-Chain (Exchange) indexer..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/xchain-indexer ./xchain

zchain:
	@echo "Building Z-Chain (ZK) indexer..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/zchain-indexer ./zchain

clean:
	@echo "Cleaning build directory..."
	@rm -rf $(BUILD_DIR)

# Docker builds
docker: docker-achain docker-bchain docker-pchain docker-qchain docker-tchain docker-xchain docker-zchain

docker-achain:
	docker build --build-arg CHAIN=achain -t luxfi/achain-indexer:latest .

docker-bchain:
	docker build --build-arg CHAIN=bchain -t luxfi/bchain-indexer:latest .

docker-pchain:
	docker build --build-arg CHAIN=pchain -t luxfi/pchain-indexer:latest .

docker-qchain:
	docker build --build-arg CHAIN=qchain -t luxfi/qchain-indexer:latest .

docker-tchain:
	docker build --build-arg CHAIN=tchain -t luxfi/tchain-indexer:latest .

docker-xchain:
	docker build --build-arg CHAIN=xchain -t luxfi/xchain-indexer:latest .

docker-zchain:
	docker build --build-arg CHAIN=zchain -t luxfi/zchain-indexer:latest .

# Run locally (for development)
# Port assignments:
#   A-Chain: 4500    B-Chain: 4600    P-Chain: 4100
#   Q-Chain: 4300    T-Chain: 4700    X-Chain: 4200
#   Z-Chain: 4400
run-achain:
	$(GO) run ./achain/main.go -rpc http://localhost:9630/ext/bc/A -port 4500

run-bchain:
	$(GO) run ./bchain/main.go -rpc http://localhost:9630/ext/bc/B -port 4600

run-pchain:
	$(GO) run ./pchain/main.go -rpc http://localhost:9630/ext/bc/P -port 4100

run-qchain:
	$(GO) run ./qchain/main.go -rpc http://localhost:9630/ext/bc/Q -port 4300

run-tchain:
	$(GO) run ./tchain/main.go -rpc http://localhost:9630/ext/bc/T -port 4700

run-xchain:
	$(GO) run ./xchain/main.go -rpc http://localhost:9630/ext/bc/X -port 4200

run-zchain:
	$(GO) run ./zchain/main.go -rpc http://localhost:9630/ext/bc/Z -port 4400

# Test
test:
	$(GO) test -v ./...

# Format and lint
fmt:
	$(GO) fmt ./...

lint:
	golangci-lint run ./...

# Dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Build info
info:
	@echo "LUX Explorer Indexers"
	@echo "====================="
	@echo ""
	@echo "Chains:"
	@echo "  A-Chain (AI)       - Port 4500 - AI compute providers, tasks, attestations"
	@echo "  B-Chain (Bridge)   - Port 4600 - Cross-chain bridges, MPC signers"
	@echo "  C-Chain (EVM)      - Port 4000 - Smart contracts (Blockscout)"
	@echo "  P-Chain (Platform) - Port 4100 - Validators, staking, networks"
	@echo "  Q-Chain (Quantum)  - Port 4300 - Quantum stamps, finality proofs"
	@echo "  T-Chain (Teleport) - Port 4700 - Cross-chain messages, warp signatures"
	@echo "  X-Chain (Exchange) - Port 4200 - Assets, UTXOs, transfers"
	@echo "  Z-Chain (ZK)       - Port 4400 - ZK proofs, confidential transfers"
	@echo ""
	@echo "Usage:"
	@echo "  make build        - Build all indexers"
	@echo "  make docker       - Build Docker images"
	@echo "  make run-<chain>  - Run specific chain indexer"
	@echo "  make test         - Run tests"
	@echo "  make clean        - Clean build artifacts"
