//! `VictoriaLogs` managed sidecar.
//!
//! Owns the lifecycle of the in-process `victoria-logs` child:
//!
//! * `installer` — make sure the binary exists on disk (download from GitHub
//!   releases when missing; verify SHA-256 before exec).
//! * `sidecar` — spawn the binary with the configured flags, wait for the
//!   `/health` endpoint, then keep monitoring the child until shutdown.
//!
//! All operations are no-ops when `VictoriaLogsConfig::enabled = false`, so
//! the feature is fully opt-in and zero-cost for operators that don't want
//! `VictoriaLogs` in their stack.

pub mod installer;
pub mod sidecar;

pub use installer::ensure_binary;
pub use sidecar::VictoriaLogsSidecar;
