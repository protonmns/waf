//! `VictoriaLogs` ingest pipeline (Phase 02).
//!
//! Two independent layers, sharing a common batch-buffer abstraction:
//!
//! * [`vlogs_layer`] — a `tracing_subscriber::Layer` that ships every
//!   `tracing` event into `VictoriaLogs` as JSON. Used for general
//!   observability.
//! * [`audit_sender`] — a structured WAF security-event sink invoked from
//!   `WafEngine::inspect` for every non-Allow decision. Used for audit /
//!   compliance, intentionally separate from the noisy `tracing` stream.
//!
//! Both layers fail open: if the buffer is saturated or `VictoriaLogs` is
//! unreachable, entries are dropped, a single warning is emitted, and the
//! WAF request path stays unblocked.
//!
//! ### Crate placement
//!
//! The original plan (`plans/260502-victorialog/plan.md`) placed these in
//! `crates/gateway/src/logging/`. They live in `waf-engine` instead because
//! `engine.rs` needs to invoke the audit sender directly, and `waf-engine`
//! sits below `gateway` in the dep graph — moving the modules avoids a
//! circular dependency. The tracing layer is also here so the binary can
//! install it from a single crate path.

pub mod audit_sender;
pub mod batch_buffer;
pub mod vlogs_layer;

pub use audit_sender::{AuditEvent, AuditEventType, AuditSender};
pub use batch_buffer::{BatchConfig, BatchSender, spawn_batch_flusher};
pub use vlogs_layer::{LayerSlot, VictoriaLogsLayer};
