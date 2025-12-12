# Multi-stage Dockerfile for LUX chain indexers
# Usage: docker build --build-arg CHAIN=pchain -t luxfi/pchain-indexer .

ARG CHAIN=pchain

# Build stage
FROM golang:1.21-alpine AS builder

RUN apk add --no-cache git make

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum* ./
RUN go mod download

# Copy source code
COPY . .

# Build the specified chain indexer
ARG CHAIN
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /indexer ./${CHAIN}

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates curl

WORKDIR /app

COPY --from=builder /indexer /app/indexer

# Default port (override with -e HTTP_PORT)
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${HTTP_PORT:-4000}/health || exit 1

ENTRYPOINT ["/app/indexer"]
