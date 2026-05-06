//! FR-005 phase-01 bench — `DDoS` counter `incr_get` hot path.
//!
//! Target (phase-01 spec): p99 < 50µs for `incr_get`.
//! Single hot-key benchmark measures the worst-case contention scenario.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use waf_engine::checks::ddos::{CounterStore, MemoryCounterStore};

fn bench_incr_get_hot(c: &mut Criterion) {
    let store = MemoryCounterStore::new(100_000, 60);
    let ttl_ms = 60_000_i64;

    c.bench_function("ddos_incr_get_hot", |b| {
        let mut now_ms = 0_i64;
        b.iter(|| {
            now_ms += 1;
            black_box(store.incr_get_blocking(black_box("hot_key"), ttl_ms, now_ms).unwrap())
        });
    });
}

fn bench_incr_get_cold(c: &mut Criterion) {
    let store = MemoryCounterStore::new(100_000, 60);
    let ttl_ms = 60_000_i64;

    c.bench_function("ddos_incr_get_cold", |b| {
        let mut key_id = 0_u64;
        b.iter(|| {
            key_id += 1;
            let key = format!("key_{key_id}");
            black_box(store.incr_get_blocking(black_box(&key), ttl_ms, 0).unwrap())
        });
    });
}

criterion_group!(benches, bench_incr_get_hot, bench_incr_get_cold);
criterion_main!(benches);
