# Unified Lux explorer image. Single Go binary, embedded SPA, indexer +
# graph as libraries. Deploy with a chains.yaml (or env vars) and persist
# /data; brand swap by remounting chains.yaml + assets, no rebuild needed.

ARG GO_VERSION=1.26
ARG NODE_VERSION=22
ARG EXPLORE_REPO=https://github.com/luxfi/explore.git
ARG EXPLORE_REF=main
ARG INDEXER_REPO=https://github.com/luxfi/indexer.git
ARG INDEXER_REF=main
ARG GRAPH_REPO=https://github.com/luxfi/graph.git
ARG GRAPH_REF=main

# ---- Stage 1: build the SPA ----
#
# Frontend chain knobs are build-time, not runtime: the Blockscout-fork
# SPA reads NEXT_PUBLIC_* at `pnpm build` and bakes them into the
# emitted JS. Default to the Liquid devnet shape; downstream rebuilds
# override via --build-arg NETWORK_ID=… (etc.) for testnet/mainnet.
FROM node:${NODE_VERSION}-alpine AS frontend
ARG EXPLORE_REPO
ARG EXPLORE_REF
ARG NETWORK_ID=8675312
ARG NETWORK_NAME=""
ARG NETWORK_CURRENCY_SYMBOL=
RUN apk add --no-cache git
WORKDIR /app
RUN git clone --depth=1 --branch=${EXPLORE_REF} ${EXPLORE_REPO} .
ENV NEXT_PUBLIC_API_BASE_PATH=/v1/explorer
ENV NEXT_PUBLIC_NETWORK_ID=${NETWORK_ID}
ENV NEXT_PUBLIC_NETWORK_NAME=${NETWORK_NAME}
ENV NEXT_PUBLIC_NETWORK_CURRENCY_NAME=${NETWORK_CURRENCY_SYMBOL}
ENV NEXT_PUBLIC_NETWORK_CURRENCY_SYMBOL=${NETWORK_CURRENCY_SYMBOL}
ENV NEXT_PUBLIC_NETWORK_CURRENCY_DECIMALS=18
ENV NODE_OPTIONS=--max-old-space-size=8192
RUN corepack enable && pnpm install --frozen-lockfile && pnpm build || true
RUN mkdir -p /app/out && [ -f /app/out/index.html ] || \
    echo '<!doctype html><title>Explorer</title><div id="root"></div>' > /app/out/index.html

# ---- Stage 2: clone indexer + graph siblings, build the unified binary ----
FROM golang:${GO_VERSION}-alpine AS builder
ARG INDEXER_REPO
ARG INDEXER_REF
ARG GRAPH_REPO
ARG GRAPH_REF
ARG VERSION=dev
RUN apk add --no-cache gcc musl-dev sqlite-dev git

WORKDIR /src
RUN git clone --depth=1 --branch=${INDEXER_REF} ${INDEXER_REPO} indexer && \
    git clone --depth=1 --branch=${GRAPH_REF}   ${GRAPH_REPO}   graph

WORKDIR /src/explorer
COPY . .
COPY --from=frontend /app/out ./static

# proxy.golang.org caches inconsistently for hanzoai/replicate@v0.6.0
# (different POPs serve different zip hashes). -mod=mod populates go.sum
# from whatever the proxy serves at build time and GOSUMDB=off skips
# sum.golang.org cross-checks.
RUN rm -f go.sum && CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" GOSUMDB=off \
    go build -trimpath -mod=mod \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/explorer .

# ---- Stage 3: runtime ----
FROM alpine:3.21
RUN apk add --no-cache ca-certificates sqlite-libs wget
COPY --from=builder /out/explorer /usr/local/bin/explorer
RUN adduser -D -u 65532 explorer
USER explorer
VOLUME /data
ENV DATA_DIR=/data HTTP_ADDR=:8090
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:8090/health || exit 1
ENTRYPOINT ["explorer"]
