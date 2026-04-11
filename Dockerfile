# luxfi/explorer — Combined: indexer + graph + explore frontend
#
#   ghcr.io/luxfi/indexer   ← chain data (blocks, txs, tokens, contracts)
#   ghcr.io/luxfi/graph     ← subgraph events (swaps, pools, DeFi, GraphQL)
#   ghcr.io/luxfi/explore   ← Next.js frontend
#   ghcr.io/luxfi/explorer  ← This: all three combined
#
# Each component can also run standalone for independent scaling.

ARG GO_VERSION=1.26
ARG NODE_VERSION=22
ARG INDEXER_REPO=https://github.com/luxfi/indexer.git
ARG INDEXER_REF=main
ARG GRAPH_REPO=https://github.com/luxfi/graph.git
ARG GRAPH_REF=main
ARG EXPLORE_REPO=https://github.com/luxfi/explore.git
ARG EXPLORE_REF=main

# ---- Stage 1: Build frontend ----
FROM node:${NODE_VERSION}-alpine AS frontend
ARG EXPLORE_REPO
ARG EXPLORE_REF
RUN apk add --no-cache git
WORKDIR /app
RUN git clone --depth=1 --branch=${EXPLORE_REF} ${EXPLORE_REPO} .
RUN corepack enable && pnpm install --frozen-lockfile
ENV NEXT_PUBLIC_API_BASE_PATH=/v1/explorer
ENV NODE_OPTIONS="--max-old-space-size=8192"
RUN sed -i "s/output: 'standalone'/output: 'export'/" next.config.js || true
RUN pnpm build || true
RUN mkdir -p /app/out && [ -f /app/out/index.html ] || \
    echo '<!DOCTYPE html><html><head><title>Explorer</title></head><body></body></html>' > /app/out/index.html

# ---- Stage 2: Build Go binaries ----
FROM golang:${GO_VERSION}-alpine AS builder
ARG INDEXER_REPO
ARG INDEXER_REF
ARG GRAPH_REPO
ARG GRAPH_REF
RUN apk add --no-cache gcc musl-dev sqlite-dev git
ARG VERSION=dev

# Build indexer
WORKDIR /indexer
RUN git clone --depth=1 --branch=${INDEXER_REF} ${INDEXER_REPO} .
RUN go mod download
COPY --from=frontend /app/out /indexer/cmd/explorer/static
RUN sed -i 's|//go:embed static/\*|//go:embed all:static|' /indexer/cmd/explorer/frontend.go 2>/dev/null || true
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" go build \
    -ldflags="-s -w -X main.version=${VERSION}" -o /bin/indexer ./cmd/indexer/
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" go build \
    -ldflags="-s -w -X main.version=${VERSION}" -o /bin/explorer ./cmd/explorer/

# Build graph
WORKDIR /graph
RUN git clone --depth=1 --branch=${GRAPH_REF} ${GRAPH_REPO} .
RUN go mod download
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" go build \
    -ldflags="-s -w -X main.version=${VERSION}" -o /bin/graph ./cmd/graph/

# ---- Stage 3: Runtime ----
FROM alpine:3.21
RUN apk add --no-cache ca-certificates sqlite-libs
COPY --from=builder /bin/indexer /usr/local/bin/indexer
COPY --from=builder /bin/explorer /usr/local/bin/explorer
COPY --from=builder /bin/graph /usr/local/bin/graph
COPY --from=frontend /app/out /srv/frontend

RUN adduser -D -u 65532 explorer
USER explorer
VOLUME /data
ENV DATA_DIR=/data HTTP_ADDR=:8090
EXPOSE 8090 4000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:8090/health || exit 1

# Default: run the multi-chain explorer (indexer + graph + frontend)
# Override with: docker run ... indexer --chain cchain --rpc ...
#            or: docker run ... graph --rpc ...
ENTRYPOINT ["explorer"]
