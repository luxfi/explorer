# luxfi/explorer — Combined: indexer backend + explore frontend
#
# Uses the pre-built indexer image as base, adds the frontend static export.
# No Go compilation needed — just layers the frontend on top.
#
#   ghcr.io/luxfi/indexer   ← Go backend (built by luxfi/indexer CI)
#   ghcr.io/luxfi/explore   ← Next.js frontend (built by luxfi/explore CI)
#   ghcr.io/luxfi/explorer  ← This: combined

ARG INDEXER_IMAGE=ghcr.io/luxfi/indexer:main
ARG NODE_VERSION=22
ARG EXPLORE_REPO=https://github.com/luxfi/explore.git
ARG EXPLORE_REF=main

# ---- Stage 1: Build frontend static export ----
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
RUN mkdir -p /app/out && [ -f /app/out/index.html ] || \
    echo '<!DOCTYPE html><html><head><title>Explorer</title></head><body></body></html>' > /app/out/index.html

# ---- Stage 2: Combine indexer + frontend ----
FROM ${INDEXER_IMAGE}

USER root
COPY --from=frontend /app/out /srv/frontend
USER explorer

# The explorer binary serves /srv/frontend at /* and API at /v1/explorer/*
ENV FRONTEND_DIR=/srv/frontend
