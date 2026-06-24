//! C-ABI staticlib that runs the Blockscout-rs explorer services in-process
//! inside the Lux explorer Go binary via cgo.
//!
//! Design (one way, decomplected):
//!   * Each wrapped service exposes the SAME shape upstream: a `Settings` type
//!     that is `serde::Deserialize` with every field `#[serde(default)]`, plus
//!     an async entrypoint `fn(Settings) -> Result<(), anyhow::Error>` that
//!     builds its own server and blocks. We do NOT reimplement any service —
//!     we call its real entrypoint.
//!   * The FFI boundary is uniform: `lux_explorer_start_<svc>(config_json)`
//!     parses the JSON into that service's `Settings` (empty `{}` => upstream
//!     defaults), spawns a dedicated OS thread with a multi-thread Tokio
//!     runtime, and runs the service to completion on it. The call returns
//!     immediately with 0 once the worker thread is launched; the service keeps
//!     running for the life of the process (matching how a subprocess would).
//!   * ONE staticlib wraps every service => one Rust std / panic runtime, no
//!     duplicate-symbol conflicts from linking multiple separate `.a`s.
//!
//! The `service!` macro is the single place that knows how to bridge a service;
//! adding a service is one macro invocation (+ its path dep + feature in
//! Cargo.toml). Disabled services still export their symbol and return
//! `LUX_FFI_ERR_DISABLED`, so the Go side links and runs regardless of which
//! features were compiled in.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::thread;

/// Worker thread launched successfully; service is running in-process.
pub const LUX_FFI_OK: i32 = 0;
/// `config_json` pointer was null or not valid UTF-8.
pub const LUX_FFI_ERR_BAD_CONFIG: i32 = 1;
/// `config_json` was non-empty but failed to deserialize into the service's
/// `Settings`.
pub const LUX_FFI_ERR_PARSE: i32 = 2;
/// This service was not compiled into the staticlib (its cargo feature was off).
pub const LUX_FFI_ERR_DISABLED: i32 = 3;
/// Failed to spawn the worker OS thread.
pub const LUX_FFI_ERR_SPAWN: i32 = 4;

/// Parse a C string config pointer into an owned JSON string.
/// Empty / null => "{}" so the service falls back to its own defaults.
fn config_str(ptr: *const c_char) -> Result<String, i32> {
    if ptr.is_null() {
        return Ok("{}".to_string());
    }
    // SAFETY: caller (cgo) guarantees a NUL-terminated C string or null.
    let cstr = unsafe { CStr::from_ptr(ptr) };
    match cstr.to_str() {
        Ok(s) if s.trim().is_empty() => Ok("{}".to_string()),
        Ok(s) => Ok(s.to_string()),
        Err(_) => Err(LUX_FFI_ERR_BAD_CONFIG),
    }
}

/// Spawn a dedicated OS thread running a fresh multi-thread Tokio runtime that
/// drives `fut_fn` (the service's blocking server future) to completion. The
/// thread is named so it shows up in stacks / metrics.
fn spawn_service<F, Fut>(name: &'static str, fut_fn: F) -> i32
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<(), anyhow::Error>>,
{
    let builder = thread::Builder::new().name(format!("lux-svc-{name}"));
    let spawned = builder.spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name(format!("lux-{name}"))
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("[ffi:{name}] failed to build tokio runtime: {e}");
                return;
            }
        };
        if let Err(e) = rt.block_on(fut_fn()) {
            eprintln!("[ffi:{name}] service exited with error: {e:#}");
        } else {
            eprintln!("[ffi:{name}] service exited");
        }
    });
    match spawned {
        Ok(_handle) => LUX_FFI_OK,
        Err(e) => {
            eprintln!("[ffi:{name}] failed to spawn worker thread: {e}");
            LUX_FFI_ERR_SPAWN
        }
    }
}

/// `service!` generates the uniform C-ABI entrypoint for one wrapped service.
///
///   service!(fn_name = lux_explorer_start_sig_provider,
///            name = "sig-provider",
///            feature = "sig-provider",
///            settings = sig_provider_server::Settings,
///            run = |s| sig_provider_server::sig_provider(s));
///
/// When `feature` is enabled the body parses JSON into `settings`, spawns the
/// worker, and runs `run`. When disabled the same symbol is exported but
/// returns `LUX_FFI_ERR_DISABLED`, so the Go binary links identically either
/// way.
macro_rules! service {
    (
        fn_name = $fn_name:ident,
        name    = $name:literal,
        feature = $feature:literal,
        settings = $settings:path,
        run     = $run:expr $(,)?
    ) => {
        #[no_mangle]
        pub extern "C" fn $fn_name(config_json: *const c_char) -> i32 {
            #[cfg(feature = $feature)]
            {
                let json = match config_str(config_json) {
                    Ok(j) => j,
                    Err(code) => return code,
                };
                let settings: $settings = match serde_json::from_str(&json) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!(concat!("[ffi:", $name, "] bad settings JSON: {}"), e);
                        return LUX_FFI_ERR_PARSE;
                    }
                };
                let run = $run;
                spawn_service($name, move || run(settings))
            }
            #[cfg(not(feature = $feature))]
            {
                let _ = config_json;
                eprintln!(concat!(
                    "[ffi:", $name,
                    "] service not compiled in (rebuild ffi with --features ", $feature, ")"
                ));
                LUX_FFI_ERR_DISABLED
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Wired services. Add one line per service (and the matching path dep +
// feature in Cargo.toml). Each upstream entrypoint signature was confirmed
// against explorer-rs:
//   sig-provider              : sig_provider_server::sig_provider(Settings)
//   smart-contract-verifier   : smart_contract_verifier_server::run(Settings)
//   stats                     : stats_server::stats(Settings, None)
//   multichain-aggregator     : multichain_aggregator_server::run(Settings)
//   visualizer                : visualizer_server::run(Settings)
// ---------------------------------------------------------------------------

service!(
    fn_name = lux_explorer_start_sig_provider,
    name = "sig-provider",
    feature = "sig-provider",
    settings = sig_provider_server::Settings,
    run = |s| sig_provider_server::sig_provider(s),
);

// stats — DB-backed, runs on SQLite (backed by hanzoai/vfs) via the launcher's
// initialize_database. The entrypoint is `stats(Settings, None)` (the `None` is
// the optional runtime-setup override). Settings.db_url is the sqlite:// url
// services.go derives from the vfs mountpoint. See README "Database" section:
// stats CONNECTS on SQLite; its Postgres-specific migrations are the documented
// porting follow-up (run_migrations should stay false until they are ported).
service!(
    fn_name = lux_explorer_start_stats,
    name = "stats",
    feature = "stats",
    settings = stats_server::Settings,
    run = |s| stats_server::stats(s, None),
);

// multichain-aggregator — DB-backed, runs on SQLite (bundled SQLCipher) via the
// same launcher initialize_database path as stats; its migrations are ported +
// proven on SQLite (multichain-aggregator-migration/tests/sqlite_migration.rs).
// The entrypoint is `run(Settings)`. NOTE: the SERVER has two upstream-dep
// blockers (see ffi/Cargo.toml's dep note): it pins launcher 0.21 / tonic 0.14,
// incompatible with stats' 0.19 / 0.12 (can't co-link), AND it currently fails to
// compile standalone in a transitive dep (api-client-framework vs reqwest-
// middleware 0.4.2). With the feature OFF (the default `stats` build) this still
// exports the symbol and returns LUX_FFI_ERR_DISABLED, so the Go side links
// unchanged — the wiring is a complete, byte-identical stub until those deps are
// reconciled, then it goes live with no Go-side change.
service!(
    fn_name = lux_explorer_start_multichain_aggregator,
    name = "multichain-aggregator",
    feature = "multichain-aggregator",
    settings = multichain_aggregator_server::Settings,
    run = |s| multichain_aggregator_server::run(s),
);

// --- Scale-out (uncomment the dep+feature in Cargo.toml, then this block) ---
//
// service!(
//     fn_name = lux_explorer_start_smart_contract_verifier,
//     name = "smart-contract-verifier",
//     feature = "smart-contract-verifier",
//     settings = smart_contract_verifier_server::Settings,
//     run = |s| smart_contract_verifier_server::run(s),
// );
//
// service!(
//     fn_name = lux_explorer_start_visualizer,
//     name = "visualizer",
//     feature = "visualizer",
//     settings = visualizer_server::Settings,
//     run = |s| visualizer_server::run(s),
// );

/// Convenience: start every service compiled into this staticlib with default
/// config (`{}` => upstream defaults). Returns the bitwise-OR of the per-service
/// return codes, so 0 means every wired service launched. Disabled services
/// contribute `LUX_FFI_ERR_DISABLED`; the Go caller can treat that as "not
/// requested" and ignore it, or call the specific starters it needs instead.
#[no_mangle]
pub extern "C" fn lux_explorer_start_all() -> i32 {
    let empty = b"{}\0".as_ptr() as *const c_char;
    let mut rc = LUX_FFI_OK;
    rc |= lux_explorer_start_sig_provider(empty);
    rc |= lux_explorer_start_stats(empty);
    rc |= lux_explorer_start_multichain_aggregator(empty);
    // Mirror each service! entry here as it is enabled:
    // rc |= lux_explorer_start_smart_contract_verifier(empty);
    // rc |= lux_explorer_start_visualizer(empty);
    rc
}
