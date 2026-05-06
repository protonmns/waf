//! `EmbeddedValkey` — lifecycle supervisor for a `valkey-server` child process.
//!
//! Enabled via the `valkey` Cargo feature.
//!
//! When `backend = "embedded"` the WAF spawns a `valkey-server` child process
//! bound to a UNIX socket. The process is **killed on drop** (`kill_on_drop(true)`)
//! so no orphan processes are left when the parent exits.
//!
//! ## Binary search order
//!
//! 1. `cache.embedded.binary_path` (from config) — if non-empty
//! 2. `valkey-server` on `PATH`
//! 3. `redis-server` on `PATH` (Valkey is Redis-compatible)
//!
//! ## Startup arguments
//!
//! ```text
//! valkey-server
//!   --unixsocket  /tmp/prx-valkey-{pid}-{nanos}.sock
//!   --unixsocketperm 700
//!   --bind 127.0.0.1
//!   --port 0               # disable TCP; UNIX socket only
//!   --save ""              # no persistence (in-memory)
//!   --maxmemory {mb}mb
//!   --maxmemory-policy allkeys-lru
//!   --loglevel warning
//!   --protected-mode no
//! ```

#![cfg(feature = "valkey")]

use std::path::PathBuf;
use std::time::Duration;

use tokio::process::Command;
use tracing::{debug, info, warn};
use waf_common::config::EmbeddedValkeyConfig;

/// Handle to a running `valkey-server` child process.
pub struct EmbeddedValkey {
    child: tokio::process::Child,
    /// UNIX socket path used by the embedded server.
    pub socket_path: PathBuf,
    /// TCP fallback address (`127.0.0.1:0` when port=0, so unused here; kept
    /// for the "connect via UNIX socket" path in [`ValkeyStore`]).
    pub connect_addr: String,
}

impl EmbeddedValkey {
    /// Spawn the `valkey-server` process and wait until it is ready.
    ///
    /// Returns `Err` if no binary is found or the server does not become ready
    /// within 5 seconds.
    pub async fn spawn(cfg: &EmbeddedValkeyConfig, max_size_mb: u64) -> anyhow::Result<Self> {
        let binary = find_binary(&cfg.binary_path)?;
        info!(binary = %binary.display(), "spawning embedded Valkey");

        // UNIX socket path: PID + monotonic-ish nanos so a quick restart after crash
        // does not collide with a stale file from a reused PID.
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0u128, |d| d.as_nanos());
        let socket_path = PathBuf::from(format!("/tmp/prx-valkey-{pid}-{nanos}.sock"));

        // Ensure data dir exists.
        if !cfg.data_dir.is_empty() {
            let _ = std::fs::create_dir_all(&cfg.data_dir);
        }

        let mut args = vec![
            "--unixsocket".to_string(),
            socket_path.to_string_lossy().to_string(),
            "--unixsocketperm".to_string(),
            "700".to_string(),
            "--bind".to_string(),
            "127.0.0.1".to_string(),
            "--port".to_string(),
            "0".to_string(),
            "--save".to_string(),
            String::new(),
            "--maxmemory".to_string(),
            format!("{max_size_mb}mb"),
            "--maxmemory-policy".to_string(),
            "allkeys-lru".to_string(),
            "--loglevel".to_string(),
            "warning".to_string(),
            "--protected-mode".to_string(),
            "no".to_string(),
        ];

        // Append operator-defined extra args.
        args.extend(cfg.extra_args.iter().cloned());

        let child = Command::new(&binary)
            .args(&args)
            .kill_on_drop(true) // auto-kill when parent process exits
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to spawn valkey-server ({}): {e}", binary.display()))?;

        debug!(pid = child.id(), socket = %socket_path.display(), "valkey-server spawned");

        // Wait until the UNIX socket is ready.
        wait_ready(&socket_path, Duration::from_secs(5))
            .await
            .map_err(|e| anyhow::anyhow!("embedded Valkey did not become ready within 5s: {e}"))?;

        info!(socket = %socket_path.display(), "embedded Valkey ready");

        let connect_addr = format!("unix:{}", socket_path.display());

        Ok(Self {
            child,
            socket_path,
            connect_addr,
        })
    }

    /// Returns the connect address suitable for the Valkey client:
    /// `"unix:/tmp/prx-valkey-{pid}-{nanos}.sock"`.
    pub fn unix_socket_addr(&self) -> String {
        format!("unix:{}", self.socket_path.display())
    }
}

impl Drop for EmbeddedValkey {
    fn drop(&mut self) {
        // `kill_on_drop(true)` handles this automatically when the Child is dropped.
        // We call start_kill() explicitly here for clarity and to ensure the
        // SIGKILL is sent even if the runtime is shutting down.
        if let Err(e) = self.child.start_kill() {
            warn!(error = %e, "failed to kill embedded valkey-server on drop");
        }
    }
}

// ── Binary discovery ──────────────────────────────────────────────────────────

fn find_binary(config_path: &str) -> anyhow::Result<PathBuf> {
    if !config_path.is_empty() {
        let p = PathBuf::from(config_path);
        if p.exists() {
            return Ok(p);
        }
        return Err(anyhow::anyhow!("configured binary_path does not exist: {config_path}"));
    }

    for name in &["valkey-server", "redis-server"] {
        if let Ok(path) = which_binary(name) {
            return Ok(path);
        }
    }

    Err(anyhow::anyhow!(
        "valkey-server (or redis-server) not found in PATH; \
         install Valkey or set cache.embedded.binary_path"
    ))
}

/// Minimal `which`-like lookup: scan each component of `PATH`.
fn which_binary(name: &str) -> anyhow::Result<PathBuf> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = PathBuf::from(dir).join(name);
        if candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(anyhow::anyhow!("{name} not found"))
}

// ── Readiness polling ─────────────────────────────────────────────────────────

/// Poll the UNIX socket until it accepts a connection (no separate `exists()`
/// check — avoids TOCTOU between stat and connect).
async fn wait_ready(socket_path: &PathBuf, timeout: Duration) -> anyhow::Result<()> {
    use tokio::net::UnixStream;
    use tokio::time::sleep;

    let deadline = tokio::time::Instant::now() + timeout;
    let poll_interval = Duration::from_millis(100);

    loop {
        if UnixStream::connect(socket_path).await.is_ok() {
            return Ok(());
        }

        if tokio::time::Instant::now() >= deadline {
            return Err(anyhow::anyhow!(
                "timeout waiting for UNIX socket: {}",
                socket_path.display()
            ));
        }

        sleep(poll_interval).await;
    }
}
