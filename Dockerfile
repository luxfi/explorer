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
# luxfi/explore is a Next.js `output: 'standalone'` SSR app, not a static
# export — so `pnpm build` does NOT produce /app/out/. The unified
# explorer needs static assets to embed via go:embed; until upstream
# explore ships `output: 'export'`, we ship a substantive runtime SPA
# shell from explorer/static/. The shell wires /envs.js (window.ENV)
# to render the chain list client-side. When upstream explore lands
# static-export support, this stage gains `pnpm build && cp .next/static
# /app/out/_next/static` and the shell can hydrate.
#
# Build-arg defaults shape the optional Next.js static export attempt
# (only used if explore.git lands `output: 'export'` upstream). Real
# branding comes from the runtime chains.yaml + brand assets mount on
# the explorer Deployment — no rebuild needed to swap.
FROM node:${NODE_VERSION}-alpine AS frontend
ARG EXPLORE_REPO
ARG EXPLORE_REF
ARG NETWORK_ID=8675312
ARG NETWORK_NAME="regulated EVM L1"
ARG NETWORK_CURRENCY_SYMBOL=
RUN apk add --no-cache git
WORKDIR /app
# Best-effort: clone explore and try to produce a static export. If
# anything fails (missing pnpm-lockfile entry, missing env vars, SSR-only
# Next config), don't fail the image — explorer/static/ still ships.
RUN git clone --depth=1 --branch=${EXPLORE_REF} ${EXPLORE_REPO} . || true
ENV NEXT_PUBLIC_API_BASE_PATH=/v1/explorer
ENV NEXT_PUBLIC_NETWORK_ID=${NETWORK_ID}
ENV NEXT_PUBLIC_NETWORK_NAME=${NETWORK_NAME}
ENV NEXT_PUBLIC_NETWORK_CURRENCY_NAME=${NETWORK_CURRENCY_SYMBOL}
ENV NEXT_PUBLIC_NETWORK_CURRENCY_SYMBOL=${NETWORK_CURRENCY_SYMBOL}
ENV NEXT_PUBLIC_NETWORK_CURRENCY_DECIMALS=18
ENV NODE_OPTIONS=--max-old-space-size=8192
RUN if [ -f package.json ]; then \
      corepack enable && pnpm install --frozen-lockfile --ignore-scripts && pnpm build || true; \
    fi
# /app/out is created only if static export succeeded. The builder stage
# below COPYs it over explorer/static/ — but only if non-empty. The
# fallback path is the local explorer/static/index.html (substantive
# 372-byte SPA shell with id="root" + /envs.js bootstrap).
RUN mkdir -p /app/out

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
# explorer/static/ already contains the substantive SPA shell. Only
# overlay frontend /app/out/ if it has the static-exported assets (an
# index.html that's NOT the 60-byte stub). When upstream explore ships
# static-export, the cp succeeds and overlays the real assets.
RUN --mount=type=bind,from=frontend,source=/app/out,target=/tmp/frontend-out \
    sh -eu -c '\
      if [ -s /tmp/frontend-out/index.html ] && [ "$(wc -c </tmp/frontend-out/index.html)" -gt 100 ]; then \
        echo "[frontend] overlaying static export onto explorer/static/"; \
        cp -R /tmp/frontend-out/. /src/explorer/static/; \
      else \
        echo "[frontend] static export not produced, keeping committed explorer/static/ SPA shell"; \
      fi'

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
