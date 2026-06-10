# Lux Explorer data-layer image (v1.3.0+).
#
# As of v1.3.0 the Go binary is API-only — it serves /v1/* (indexer +
# blockscout-compat REST), /health, /envs.js, and per-host brand SVGs.
# Every other path returns 404 and the IngressRoute routes it to the
# per-brand Blockscout FE Deployment (ghcr.io/{brand-org}/explore-{env}).
# Built from luxfi/explore via Dockerfile.branded — see ~/work/lux/explore.

ARG GO_VERSION=1.26
ARG INDEXER_REPO=https://github.com/luxfi/indexer.git
ARG INDEXER_REF=main
ARG GRAPH_REPO=https://github.com/luxfi/graph.git
ARG GRAPH_REF=main

# ---- Stage 1: clone indexer + graph siblings, build the unified binary ----
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

# proxy.golang.org caches inconsistently for hanzoai/replicate@v0.6.0
# (different POPs serve different zip hashes). -mod=mod populates go.sum
# from whatever the proxy serves at build time and GOSUMDB=off skips
# sum.golang.org cross-checks.
RUN rm -f go.sum && CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" GOSUMDB=off \
    go build -trimpath -mod=mod \
      -ldflags="-s -w -X main.version=${VERSION}" \
      -o /out/explorer .

# ---- Stage 2: runtime ----
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
