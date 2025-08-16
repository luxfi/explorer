# Explorer Dockerfile - Elixir/Phoenix Blockscout
FROM elixir:1.17-alpine AS builder

# Install build dependencies
RUN apk add --no-cache --update \
  git build-base nodejs npm python3 \
  automake libtool inotify-tools autoconf \
  rust cargo

WORKDIR /app

# Install hex and rebar
RUN mix local.hex --force && \
    mix local.rebar --force

# Set mix env
ENV MIX_ENV=prod

# Copy mix files
COPY mix.exs mix.lock ./
COPY apps/*/mix.exs ./apps/

# Install dependencies
RUN mix deps.get --only prod && \
    mix deps.compile

# Copy application files
COPY . .

# Compile assets
RUN cd apps/block_scout_web && \
    npm install && \
    npm run build

# Compile application
RUN mix compile

# Build release
RUN mix release

# Runtime stage
FROM alpine:3.18

RUN apk add --no-cache --update \
  bash openssl libstdc++ ncurses-libs

WORKDIR /app

# Create non-root user
RUN addgroup -g 1000 -S blockscout && \
    adduser -u 1000 -S blockscout -G blockscout

# Copy release from builder
COPY --from=builder --chown=blockscout:blockscout /app/_build/prod/rel/block_scout ./

USER blockscout

ENV HOME=/app

# Expose Phoenix port
EXPOSE 4000

# Start the application
CMD ["bin/block_scout", "start"]