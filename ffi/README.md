# lux_explorer_ffi — Blockscout-rs services, in-process, one binary

This crate makes the Lux explorer **one single binary** that runs the
[Blockscout-rs](../../explorer-rs) explorer services (sig-provider, and — as
scaled out — smart-contract-verifier, stats, multichain-aggregator, visualizer)
**in-process via cgo FFI**. No subprocesses. No Go rewrites. Each service's real
Rust entrypoint runs on its own Tokio runtime thread inside the explorer binary.

```
┌──────────────────────────── explorer (single Go binary) ────────────────────────────┐
│  main.go ─ startFFIServices() (ffi_on.go, //go:build ffi)                             │
│      │  cgo  →  liblux_explorer_ffi.a  (this crate, crate-type = ["staticlib"])       │
│      │             │  lux_explorer_start_sig_provider(config_json) ─┐                  │
│      │             │  lux_explorer_start_all()                      │                  │
│      ▼             ▼                                                ▼                  │
│  Go-native indexer/graph/SPA/realtime        Rust sig-provider on its own Tokio thread │
└───────────────────────────────────────────────────────────────────────────────────────┘
```

## Why one staticlib for all services

A single `staticlib` wraps every service, so the final binary links **one** copy
of the Rust std / panic runtime. Linking several separate `.a`s would risk
duplicate-symbol conflicts. Adding a service is a path dep + a feature + one
`service!{…}` line — nothing else changes.

## C ABI

Exported from `src/lib.rs` (see the `service!` macro):

```c
// Spawn <svc> on its own Tokio runtime thread; returns 0 (LUX_FFI_OK) once
// launched. config_json is the service's Settings as JSON; "" / NULL => the
// service's upstream defaults.
int lux_explorer_start_sig_provider(const char* config_json);
// …one per wired service…

// Start every service compiled into this staticlib with default config.
int lux_explorer_start_all(void);
```

Return codes: `0` ok · `1` bad-config · `2` parse-error · `3` disabled
(service's cargo feature was off) · `4` spawn-error. Disabled services still
export their symbol and return `3`, so the Go binary links identically no matter
which features were compiled in.

## Build

From the explorer repo root:

```sh
make single                       # all wired services
make single FFI_FEATURES=sig-provider   # scope to specific services
```

`make single` runs `cargo build --release --features <…>` here, then
`go build -tags ffi`. The default `make build` / `go build ./...` compiles the
`ffi_off.go` stub and needs **none** of this.

### Build-tool prerequisites (Rust path only)

The Blockscout-rs `*-proto` crates generate gRPC + Swagger at build time, so the
host needs:

- **protoc** — `brew install protobuf`
- **protoc-gen-openapiv2** — `go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest`
  (must be on `PATH`; it lands in `$(go env GOPATH)/bin`)

These are standard upstream Blockscout-rs build deps (the prost-build panic
message itself points at `brew install protobuf`), not added by this crate.

### Cargo.lock is seeded

`ffi/Cargo.lock` is seeded from `explorer-rs/sig-provider/Cargo.lock` so the
build resolves the **same** dependency versions the service is known to build
with. Without this, re-resolving the graph as a path dep pulled in
`prost-build 0.14` against the service's `0.11` build script and failed. When
adding a service whose lock conflicts, reconcile the lock the same way (start
from that service's `Cargo.lock`, let cargo extend it).

## Scaling out (one service at a time)

Each service pins a **different** major of `blockscout-service-launcher`
(sig-provider 0.10 · visualizer 0.13 · verifier 0.17 · stats 0.19 ·
multichain-aggregator 0.21) and the DB-backed ones pull `sea-orm` + migrations.
Cargo can carry multiple majors, but the build surface grows, so enable and
**verify the link after each**:

1. **Cargo.toml** — uncomment the service's `*-server` path dep and its
   `[features]` entry (both are already written out, commented).
2. **src/lib.rs** — uncomment its `service!{…}` block (the entrypoint signatures
   are already filled in and confirmed against explorer-rs) and the matching
   line in `lux_explorer_start_all`.
3. **ffi_on.go** — add a `start("<svc>", …)` line.
4. `make single FFI_FEATURES=<svc>` and confirm the `.a` links into the Go
   binary (`nm explorer | grep lux_explorer_start_<svc>`).

Confirmed upstream entrypoints (all take a `serde::Deserialize` `Settings`):

| service                 | crate                              | entrypoint                  |
|-------------------------|------------------------------------|-----------------------------|
| sig-provider            | `sig_provider_server`              | `sig_provider(Settings)`    |
| smart-contract-verifier | `smart_contract_verifier_server`   | `run(Settings)`             |
| stats                   | `stats_server`                     | `stats(Settings, None)`     |
| multichain-aggregator   | `multichain_aggregator_server`     | `run(Settings)`             |
| visualizer              | `visualizer_server`                | `run(Settings)`             |

## Front router (zip) — how the binary is fronted

The single binary's **public** listener is [`github.com/hanzoai/zip`](../../../hanzo/hanzoai/zip)
(Fiber v3 / fasthttp), wired in `front.go`. Each in-process service keeps its
own HTTP server bound to **loopback** (`127.0.0.1:<port>`, assigned from
`servicePortBase = 8050`, HTTP=base+2n / gRPC=base+2n+1); zip is the only thing
exposed. Routing, in registration order:

```
/api/<prefix>/*   →  httputil.ReverseProxy → http://127.0.0.1:<svc_http_port>   (mountServiceProxies, services.go)
/*                →  the existing Go-native explorer *http.ServeMux             (zip.AdaptNetHTTP, front.go)
```

The proxy strips the `/api/<prefix>` mount prefix, so the upstream sees its own
native path (e.g. `/api/sig/health` → sig-provider `/health`;
`/api/sig/api/v1/abi/function` → `/api/v1/abi/function`). Enabled services +
ports are configured under `services:` in chains.yaml
(`ServicesConfig` → `resolveServices` is the single source of truth both the
proxy and this FFI launcher read). Default prefixes:
`sig-provider→sig`, `smart-contract-verifier→verifier`, `stats→stats`,
`multichain-aggregator→multichain`, `visualizer→visualizer`.

Proven end-to-end (sig-provider, one process owning both :8090 and the service
port): `curl /api/sig/health → {"status":"SERVING"}`, matching a direct hit on
the in-process service port.

## Database: SQLite status per service (verified against explorer-rs)

The brief asked to run DB-backed services on **SQLite** if sea-orm allows it
with minimal effort. It does **not**, here — documented exactly:

| service                 | DB? | SQLite-able? | status   | what it needs |
|-------------------------|-----|--------------|----------|---------------|
| sig-provider            | no  | n/a          | **WIRED + PROVEN** | nothing (stateless) |
| visualizer              | no  | n/a          | ready to wire | nothing (stateless) — clean next target |
| smart-contract-verifier | no  | n/a          | ready to wire | nothing (stateless) |
| stats                   | yes | **no**       | disabled | its **own** Postgres + a populated **Blockscout indexer Postgres** to read from |
| multichain-aggregator   | yes | **no**       | disabled | its own Postgres (+ optional replica) |

Why no SQLite: `blockscout_service_launcher::database` is **Postgres-only** —
`initialize_postgres::<Migrator>()` pins `sea_orm::DatabaseBackend::Postgres`
and formats `postgresql://…` DSNs (`libs/blockscout-service-launcher/src/database.rs`
lines 39/67/294). `stats-server` calls that directly (`server.rs:206 init_stats_db`)
**and** opens a second connection to a Blockscout indexer DB
(`server.rs:223 connect_to_indexer_db_common`). Forcing SQLite would mean
patching the launcher's backend selection + every migration — outside "minimal
effort" and explicitly a Rust rewrite the brief forbids. So stats /
multichain-aggregator stay disabled. The Go side already passes a
`database.url` (with `create_database` + `run_migrations`) through
`buildSettingsJSON` whenever `ServiceConfig.DatabaseURL` is set, so the day a
Postgres is provided these turn on with config alone — no code change.

`ServiceConfig.DatabaseURL` in chains.yaml feeds `database.url` in the settings
JSON `startFFIServices` sends; migrations run when present.
