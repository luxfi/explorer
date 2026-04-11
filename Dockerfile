# luxfi/explorer — Combined indexer backend + explore frontend in 1 image
#
# Three images, three repos:
#   ghcr.io/luxfi/indexer   ← luxfi/indexer   (Go backend only)
#   ghcr.io/luxfi/explore   ← luxfi/explore   (Next.js frontend only)
#   ghcr.io/luxfi/explorer  ← luxfi/explorer  (this: combined)
#
# Build:  docker build -t ghcr.io/luxfi/explorer .
# Run:    docker run -p 8090:8090 -e RPC_ENDPOINT=http://node:9650/ext/bc/C/rpc ghcr.io/luxfi/explorer

ARG GO_VERSION=1.26
ARG NODE_VERSION=22
ARG INDEXER_REPO=https://github.com/luxfi/indexer.git
ARG INDEXER_REF=main
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
RUN sed -i "s/output: 'standalone'/output: 'export'/" next.config.js || true
RUN pnpm build || true
# Fallback: if export fails, create minimal static dir
RUN mkdir -p /app/out && [ -f /app/out/index.html ] || echo '<!DOCTYPE html><html><head><title>Explorer</title></head><body><div id="root"></div></body></html>' > /app/out/index.html

# ---- Stage 2: Build Go backend ----
FROM golang:${GO_VERSION}-alpine AS backend
ARG INDEXER_REPO
ARG INDEXER_REF
RUN apk add --no-cache gcc musl-dev sqlite-dev git
WORKDIR /src
RUN git clone --depth=1 --branch=${INDEXER_REF} ${INDEXER_REPO} .
RUN go mod download
COPY --from=frontend /app/out /src/cmd/explorer/static
ARG VERSION=dev
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" GOOS=linux go build \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /explorer ./cmd/explorer/

# ---- Stage 3: Runtime ----
FROM alpine:3.21
RUN apk add --no-cache ca-certificates sqlite-libs
COPY --from=backend /explorer /usr/local/bin/explorer
RUN adduser -D -u 65532 explorer
USER explorer
VOLUME /data
ENV DATA_DIR=/data HTTP_ADDR=:8090
EXPOSE 8090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD wget -qO- http://localhost:8090/health || exit 1
ENTRYPOINT ["explorer"]
