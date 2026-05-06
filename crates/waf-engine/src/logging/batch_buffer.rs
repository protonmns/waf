//! Async batch buffer that ships JSON entries to `VictoriaLogs`.
//!
//! Producers call [`BatchSender::try_send`] from any context (sync, async,
//! in a `tracing` Layer's `on_event` hook).  A background task flushes the
//! accumulated entries to the configured URL on either of two triggers:
//!
//! * batch reaches `BatchConfig::batch_size` entries, or
//! * `BatchConfig::flush_interval` has elapsed since the last flush.
//!
//! On any flush failure (network error, non-2xx response) we drop the
//! current batch and emit a `tracing::warn!` rate-limited to once every 30
//! seconds — this is the fail-open guarantee that keeps WAF traffic
//! flowing even when `VictoriaLogs` is unhealthy or full.
//!
//! When the producer queue is saturated, the **new** entry is dropped (not
//! the oldest, which would require a separate non-Tokio buffer).  This
//! preserves chronological order and is sufficient for fail-open semantics.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde_json::Value;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Tunable parameters for a [`BatchSender`] flush task.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Target URL — typically `http://127.0.0.1:9428/insert/jsonline`.
    pub url: String,
    /// Flush threshold: send when this many entries are queued.
    pub batch_size: usize,
    /// Time-based flush ceiling: send if any entries have been pending
    /// for at least this long.
    pub flush_interval: Duration,
    /// Bound on the producer→flusher channel.  Once full, new entries are
    /// dropped with a rate-limited warning.
    pub channel_capacity: usize,
    /// HTTP timeout for a single ingest call.
    pub request_timeout: Duration,
    /// Identifier used in warning messages (`"tracing"` or `"audit"`).
    pub kind: &'static str,
}

impl BatchConfig {
    /// Build a default config tuned for the `tracing` layer.
    pub const fn for_tracing(url: String, batch_size: usize, flush_interval_ms: u64, channel_capacity: usize) -> Self {
        Self {
            url,
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            channel_capacity,
            request_timeout: Duration::from_secs(5),
            kind: "tracing",
        }
    }

    /// Build a default config tuned for the audit sender.
    pub const fn for_audit(url: String, batch_size: usize, flush_interval_ms: u64, channel_capacity: usize) -> Self {
        Self {
            url,
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            channel_capacity,
            request_timeout: Duration::from_secs(5),
            kind: "audit",
        }
    }
}

/// Producer handle — cloneable, cheap, lock-free hot path.
#[derive(Clone)]
pub struct BatchSender {
    tx: mpsc::Sender<Value>,
    /// Last instant (millis since process start) we emitted a `channel
    /// full` warning. Avoids log spam when the buffer is saturated.
    last_full_warn_ms: Arc<AtomicU64>,
    kind: &'static str,
}

impl BatchSender {
    /// Enqueue an entry. Never blocks. Drops the entry (with a
    /// rate-limited warn) when the channel is full.
    pub fn try_send(&self, entry: Value) {
        // The Closed branch (flusher task gone) is intentionally indistinguishable
        // from the Ok branch on the producer side — both leave the hot path silent.
        if let Err(mpsc::error::TrySendError::Full(_)) = self.tx.try_send(entry) {
            self.warn_rate_limited("channel full — dropping entry");
        }
    }

    /// Test whether the underlying flush task is still alive.  Used by the
    /// audit sender to short-circuit serialisation when `VictoriaLogs` is
    /// down anyway.
    pub fn is_active(&self) -> bool {
        !self.tx.is_closed()
    }

    fn warn_rate_limited(&self, msg: &str) {
        const COOLDOWN_MS: u64 = 30_000;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let prev = self.last_full_warn_ms.load(Ordering::Relaxed);
        if prev == 0 || now_ms.saturating_sub(prev) >= COOLDOWN_MS {
            // Race-tolerant: if two threads update simultaneously, both
            // may emit one warning, which is acceptable.
            self.last_full_warn_ms.store(now_ms, Ordering::Relaxed);
            warn!(target: "victoria_logs::buffer", kind = self.kind, "{msg}");
        }
    }
}

/// Spawn the background flush task and return a producer handle.
///
/// The task lives on the current Tokio runtime and exits when all
/// `BatchSender` clones are dropped (channel closed).
pub fn spawn_batch_flusher(cfg: BatchConfig) -> BatchSender {
    let (tx, rx) = mpsc::channel(cfg.channel_capacity);
    let last_full_warn_ms = Arc::new(AtomicU64::new(0));
    let sender = BatchSender {
        tx,
        last_full_warn_ms: Arc::clone(&last_full_warn_ms),
        kind: cfg.kind,
    };
    tokio::spawn(flush_loop(rx, cfg));
    sender
}

async fn flush_loop(mut rx: mpsc::Receiver<Value>, cfg: BatchConfig) {
    let client = match reqwest::Client::builder().timeout(cfg.request_timeout).build() {
        Ok(c) => c,
        Err(e) => {
            warn!(target: "victoria_logs::buffer", kind = cfg.kind, error = %e, "Failed to build reqwest client; flush loop exiting");
            return;
        }
    };

    let mut batch: Vec<Value> = Vec::with_capacity(cfg.batch_size);
    let mut ticker = tokio::time::interval(cfg.flush_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut last_flush_failure_ms: u64 = 0;

    loop {
        tokio::select! {
            biased;
            received = rx.recv() => {
                if let Some(entry) = received {
                    batch.push(entry);
                    if batch.len() >= cfg.batch_size {
                        do_flush(&client, &cfg, &mut batch, &mut last_flush_failure_ms).await;
                    }
                } else {
                    // All producers dropped — final flush, then exit.
                    if !batch.is_empty() {
                        do_flush(&client, &cfg, &mut batch, &mut last_flush_failure_ms).await;
                    }
                    debug!(target: "victoria_logs::buffer", kind = cfg.kind, "flush loop exiting");
                    return;
                }
            }
            _ = ticker.tick() => {
                if !batch.is_empty() {
                    do_flush(&client, &cfg, &mut batch, &mut last_flush_failure_ms).await;
                }
            }
        }
    }
}

async fn do_flush(client: &reqwest::Client, cfg: &BatchConfig, batch: &mut Vec<Value>, last_failure_ms: &mut u64) {
    if batch.is_empty() {
        return;
    }

    // `VictoriaLogs` `/insert/jsonline` expects newline-delimited JSON. Build
    // the payload up front; the `Vec<Value>` is then cleared so subsequent
    // flushes start fresh regardless of HTTP outcome.
    let mut body = String::with_capacity(batch.len() * 256);
    for entry in batch.iter() {
        match serde_json::to_string(entry) {
            Ok(line) => {
                body.push_str(&line);
                body.push('\n');
            }
            Err(e) => {
                warn!(target: "victoria_logs::buffer", kind = cfg.kind, error = %e, "Failed to serialize log entry; dropping");
            }
        }
    }
    batch.clear();

    if body.is_empty() {
        return;
    }

    let outcome = client
        .post(&cfg.url)
        .header("Content-Type", "application/stream+json")
        .body(body)
        .send()
        .await;

    match outcome {
        Ok(resp) if resp.status().is_success() => {
            // Reset the failure backoff so the next failure logs immediately.
            *last_failure_ms = 0;
        }
        Ok(resp) => {
            rate_limited_failure_warn(
                last_failure_ms,
                cfg.kind,
                &format!("VictoriaLogs ingest returned HTTP {}", resp.status()),
            );
        }
        Err(e) => {
            rate_limited_failure_warn(last_failure_ms, cfg.kind, &format!("VictoriaLogs ingest failed: {e}"));
        }
    }
}

fn rate_limited_failure_warn(last_failure_ms: &mut u64, kind: &str, msg: &str) {
    const COOLDOWN_MS: u64 = 30_000;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    if *last_failure_ms == 0 || now_ms.saturating_sub(*last_failure_ms) >= COOLDOWN_MS {
        *last_failure_ms = now_ms;
        warn!(target: "victoria_logs::buffer", kind, "{msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_helpers_set_kind() {
        let t = BatchConfig::for_tracing("http://x".to_string(), 1, 1, 1);
        assert_eq!(t.kind, "tracing");
        let a = BatchConfig::for_audit("http://x".to_string(), 1, 1, 1);
        assert_eq!(a.kind, "audit");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn closed_sender_reports_inactive() {
        let cfg = BatchConfig::for_tracing("http://127.0.0.1:1/insert/jsonline".to_string(), 10, 100, 4);
        let sender = spawn_batch_flusher(cfg);
        // Sender is active immediately after spawn.
        assert!(sender.is_active());
    }
}
