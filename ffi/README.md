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
/v1/<prefix>/*   →  httputil.ReverseProxy → http://127.0.0.1:<svc_http_port>   (mountServiceProxies, services.go)
/*                →  the existing Go-native explorer *http.ServeMux             (zip.AdaptNetHTTP, front.go)
```

The proxy strips the `/v1/<prefix>` mount prefix, so the upstream sees its own
native path (e.g. `/v1/sig/health` → sig-provider `/health`;
`/v1/sig/api/v1/abi/function` → `/api/v1/abi/function`). Enabled services +
ports are configured under `services:` in chains.yaml
(`ServicesConfig` → `resolveServices` is the single source of truth both the
proxy and this FFI launcher read). Default prefixes:
`sig-provider→sig`, `smart-contract-verifier→verifier`, `stats→stats`,
`multichain-aggregator→multichain`, `visualizer→visualizer`.

Proven end-to-end (sig-provider, one process owning both :8090 and the service
port): `curl /v1/sig/health → {"status":"SERVING"}`, matching a direct hit on
the in-process service port.

## Database: SQLite on hanzoai/vfs — no Postgres, no blockscout-service

DB-backed services now run on **SQLite**, with the file living on a
**hanzoai/vfs** mount (block-level PQ-encrypted, backed by `s3://` in prod or
`file://` for local dev). No Postgres, no `blockscout` indexer DB hardcode. The
three pieces:

**1. Launcher — no Postgres hardcode.**
`blockscout_service_launcher::database` was Postgres-only:
`initialize_postgres::<Migrator>()` pins `DatabaseBackend::Postgres` and runs a
`CREATE DATABASE` dance over `postgresql://…` DSNs. We added
`initialize_database::<Migrator>()` (`database.rs`) which branches on the DSN
scheme: `sqlite://…?mode=rwc` connects straight through (sea-orm infers
`DatabaseBackend::Sqlite`; the file is created by the rwc open mode, the
Postgres-only CREATE DATABASE is skipped); `postgresql://…` is unchanged.
Proven by `blockscout-service-launcher/src/database.rs` `sqlite_tests`
(connects, creates the file, runs DDL — `cargo test -p blockscout-service-launcher --features database-1 sqlite_tests`).

**2. vfs mount in the Go binary** (`vfsmount.go`, off by default).
`setupVFS` opens the configured backend (`vfs.backend: s3://…` or `file://…` in
chains.yaml), mounts it at a local mountpoint, and `resolveServices`
(`services.go`) stamps each DB-backed service's `database.url` as
`sqlite://<mountpoint>/<svc>.db?mode=rwc`. The FUSE mount needs the `fuse` build
tag + macFUSE/fuse-t (or Linux kernel FUSE); without it the mountpoint degrades
to a plain local dir (the s3:// backing is a build-tag swap, the SQLite path is
identical). vfs's own `TestSQLiteRoundTrip` proves a SQLite DB survives the
encrypted block layer byte-for-byte; the explorer's `TestSetupVFS*` /
`TestResolveServicesStampsSQLiteUrlOnVFSMount` prove the wiring.

**3. stats — CONNECTS on SQLite; migrations are the documented follow-up.**

| service                 | DB? | connects on SQLite? | migrations on SQLite? | status |
|-------------------------|-----|---------------------|-----------------------|--------|
| sig-provider            | no  | n/a                 | n/a                   | **WIRED + PROVEN** (stateless) |
| visualizer              | no  | n/a                 | n/a                   | ready to wire (stateless) |
| smart-contract-verifier | no  | n/a                 | n/a                   | ready to wire (stateless) |
| **stats**               | yes | **YES (proven)**    | **NO — needs porting**| launcher swapped; connect proven; see below |
| multichain-aggregator   | yes | yes (same launcher path) | no — same class of migrations | follows stats |

stats pins `blockscout-service-launcher 0.19` + **tonic 0.12**, while the in-tree
`libs/blockscout-service-launcher` is **0.21** + tonic 0.14 (incompatible with
stats' grpc router). So stats builds against a **vendored 0.19 launcher carrying
the identical SQLite patch**: `libs/blockscout-service-launcher-0.19-sqlite`
(stats `Cargo.toml` path-deps it; `stats-server/src/server.rs:init_stats_db`
calls `initialize_database`). `stats-server` compiles clean and **connects to a
SQLite DB on disk with no Postgres** — proven by
`stats-server/tests/sqlite_migration.rs::stats_connects_to_sqlite_without_postgres`.

**The long pole — stats' migrations are Postgres-specific.** Running them on
SQLite fails at the FIRST statement (captured by
`stats_migrations_fail_on_sqlite_and_we_capture_why`):

```
Migration Error: Execution Error: error returned from database: (code: 1)
near "TYPE": syntax error
Query: CREATE TYPE "chart_type" AS ENUM ('COUNTER','LINE')
```

Every Postgres-ism that must be ported (4 migrations, `stats/migration/src/`):

| construct | migration | SQLite port |
|-----------|-----------|-------------|
| `CREATE TYPE … AS ENUM` (chart_type, chart_resolution) | init, add_resolution | drop the type; use `TEXT` + a `CHECK (col IN (…))` constraint |
| `INT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY` | init | `INTEGER PRIMARY KEY AUTOINCREMENT` |
| `DEFAULT (now())`, `now() at time zone 'utc'` | init, add_updated_at | `DEFAULT CURRENT_TIMESTAMP` |
| `timestamptz` / `ALTER COLUMN … TYPE timestamptz` | add_updated_at | SQLite has no typed timestamp/ALTER TYPE — store TEXT/INTEGER; column already exists, drop the ALTER |
| `COMMENT ON TABLE …` | init | unsupported — drop (comments are cosmetic) |
| `ALTER TABLE … ADD FOREIGN KEY` | init | SQLite cannot add FK via ALTER — declare it inline in CREATE TABLE |
| `ALTER TABLE … DROP/ADD CONSTRAINT … UNIQUE` | add_resolution | SQLite cannot ALTER constraints — create a UNIQUE INDEX instead |
| `DELETE … WHERE date = to_timestamp(0)` | drop_zero_timestamp | replace `to_timestamp(0)` with the literal epoch the column stores |

Because `from_sql` (`migration/src/lib.rs`) runs each `;`-split statement through
`Statement::from_string(manager.get_database_backend(), …)` — i.e. raw SQL, not
the sea-query builder — the port means **rewriting these migrations to branch on
`manager.get_database_backend()`** (Postgres SQL vs SQLite SQL) or rewriting them
in backend-agnostic sea-query. That is a self-contained Rust task in the stats
crate, tracked here; it does **not** touch the launcher or the Go binary.
multichain-aggregator's migrations are the same class (enums, identity,
timestamptz) and port the same way.

**Also required at stats runtime (independent of migrations):** stats needs an
`indexer_db_url` — `server.rs:connect_to_main_indexer_db` errors `"Indexer DB
URL is not set"` without one — and the `charts_config` / `layout_config` /
`update_groups_config` files. Those make stats *serve*; the brief's win is that
it *connects to its own SQLite DB on the vfs mount with no Postgres*, which is
proven.

### FFI link note — one staticlib can't yet hold sig-provider + stats

`make single FFI_FEATURES=stats` builds stats into the staticlib. Combining
**sig-provider AND stats** in one `.a` currently fails to build because the
merged graph resolves **two `prost-build` majors** (0.11 from sig-provider, 0.13
from stats' proto crates), and `zetachain-cctx-proto`'s build script (pulled via
stats) is written against one major while `tonic_build` hands it the other:

```
error[E0308]: mismatched types … expected trait `prost_build::ServiceGenerator`
(prost-build 0.11.9), found trait `ServiceGenerator` (prost-build 0.13.5)
  --> zetachain-cctx-proto/build.rs:46
```

This is the multi-major lock-reconciliation chore the "Scaling out" note above
warns about, not a stats-on-SQLite problem. There is also a second, harder
collision once stats *does* link: stats pulls `sqlx`'s bundled SQLite C library
(`libsqlite3-sys`, ~401 `sqlite3_*` symbols) while the Go side already links
`mattn/go-sqlite3`'s bundled SQLite C (pulled transitively by `luxfi/indexer`
and `luxfi/graph`, which both `sql.Open("sqlite3", …)`) — `ld` reports 245
`duplicate symbol _sqlite3_*`. Shipping sig-provider+stats in one binary needs
ONE C SQLite: either switch `luxfi/indexer`/`luxfi/graph` to the pure-Go
`modernc.org/sqlite` (no C — the clean end state, leaves only sqlx's copy), or
build `libsqlite3-sys` against a shared system libsqlite3. Until then, stats
builds and links **alone** (`make single FFI_FEATURES=stats`) against a lock
seeded from stats' own `Cargo.lock` (prost-build 0.13 only); sig-provider is the
default `make single`. Both proven to link individually; co-linking is the
documented follow-up.

`ServiceConfig.DatabaseURL` (or the vfs-derived sqlite url) feeds `database.url`
in the settings JSON `startFFIServices` sends. **Keep `run_migrations: false`
for stats until the migrations are ported** — otherwise boot fails at the
`CREATE TYPE` above.
