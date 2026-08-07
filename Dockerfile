# Lux Explorer data-layer image (v1.3.0+).
#
# As of v1.3.0 the Go binary is API-only — it serves /v1/* (indexer +
# blockscout-compat REST), /health, /envs.js, and per-host brand SVGs.
# Every other path returns 404 and the IngressRoute routes it to the
# per-brand Blockscout FE Deployment (ghcr.io/{brand-org}/explore-{env}).
# Built from luxfi/explore via Dockerfile.branded — see ~/work/lux/explore.

ARG GO_VERSION=1.26

# ---- Stage 1: build the unified FE + indexer + graph binary ----
# graph + indexer are consumed as Go modules pinned in go.mod (luxfi/graph
# v1.2.3, luxfi/indexer v1.4.5), NOT cloned as siblings — explorer has no
# replace directive, so under -mod=mod the module cache is authoritative.
FROM golang:${GO_VERSION}-alpine AS builder
ARG VERSION=dev
RUN apk add --no-cache gcc musl-dev sqlite-dev git

# luxfi/* modules are private and may be re-tagged; resolve them direct
# (not via proxy/sumdb) and skip checksum-db cross-checks, exactly as the
# node image does. The default GITHUB_TOKEN is repo-scoped; a cross-org PAT
# is injected as the BuildKit secret `ghtok` by docker.yml.
ENV GOPRIVATE=github.com/lux-private/*,github.com/hanzoai/*
ENV GONOSUMCHECK=github.com/luxfi/*
ENV GONOSUMDB=github.com/lux-private/*
ENV GONOPROXY=github.com/lux-private/*
ENV GOFLAGS=-mod=mod

WORKDIR /src
COPY go.mod go.sum ./
# Configure git auth once so both `go mod download` here and the implicit
# fetch during `go build` can reach private luxfi/* modules.
RUN --mount=type=secret,id=ghtok,required=false \
    if [ -s /run/secrets/ghtok ]; then \
        git config --global url."https://x-access-token:$(cat /run/secrets/ghtok)@github.com/".insteadOf "https://github.com/"; \
    fi && \
    go mod download

COPY . .
# Tests run here, in the one place that already has cgo + sqlite-dev, so a
# release that fails them never becomes an image. Nothing else in this repo
# runs them: .hanzo/workflows/release.yml builds on a v* tag and there is no
# other workflow, so a test file added to this repo was, until now, never
# executed by anything but a developer's laptop.
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" go vet ./... && \
    CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" go test ./...
RUN CGO_ENABLED=1 CGO_CFLAGS="-D_LARGEFILE64_SOURCE" \
    go build -trimpath \
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
